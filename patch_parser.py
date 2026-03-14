import re
import os


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

def clean_line(line):
    """Normalize patch line content."""

    # Remove comments
    line = re.sub(r'//.*', '', line)
    line = re.sub(r'/\*.*?\*/', '', line)

    # Normalize whitespace
    line = re.sub(r'\s+', ' ', line)

    line = line.strip()

    if not line:
        return ""

    # Skip trivial syntax lines
    if line in {"{", "}", ";", "(", ")", ","}:
        return ""

    return line


def is_test_file(filename):
    patterns = ["test", "spec", "mock", "fixture", "example"]
    return any(p in filename.lower() for p in patterns)


def is_generated_file(filename):
    """
    Skip lockfiles, vendored node_modules, and other generated files.
    These contain dependency metadata, not vulnerable code — extracting
    signatures from them produces pure noise.
    """
    if not filename:
        return False

    fname = filename.lower()

    # Lockfiles and dependency manifests
    generated_names = {
        "package-lock.json",
        "yarn.lock",
        "npm-shrinkwrap.json",
        "pnpm-lock.yaml",
        "composer.lock",
        "gemfile.lock",
        "cargo.lock",
        "poetry.lock",
        "pipfile.lock",
        "go.sum",
    }

    basename = os.path.basename(fname)
    if basename in generated_names:
        return True

    # node_modules vendored copies
    if "node_modules/" in fname or "node_modules\\" in fname:
        return True

    # Minified JS
    if fname.endswith(".min.js") or fname.endswith(".min.css"):
        return True

    # Bundled/dist output
    if "/dist/" in fname or "/bundle/" in fname or "/vendor/" in fname:
        return True

    return False


# ---------------------------------------------------------
# Language detection
# ---------------------------------------------------------

def detect_language_from_filename(filename):

    if not filename:
        return 'unknown'

    ext = os.path.splitext(filename)[1].lower()

    if ext == '.go':
        return 'go'

    if ext == '.rs':
        return 'rust'

    if ext in {'.js', '.mjs', '.cjs'}:
        return 'javascript'

    if ext in {'.ts', '.tsx'}:
        return 'typescript'

    if ext in {'.c', '.h', '.cpp', '.hpp', '.cc', '.cxx'}:
        return 'c_cpp'

    if ext == '.py':
        return 'python'

    return 'unknown'


# ---------------------------------------------------------
# Vulnerability classification
# ---------------------------------------------------------

def _content_looks_like_js(content):
    """
    Detect JavaScript content from line patterns even without a .js extension.
    Uses syntactic markers that are unambiguous in JS but rare in C/Python.
    Requires 2+ distinct indicators to avoid false positives.
    """
    indicators = [
        "===",          # strict equality — JS only
        "!==",          # strict inequality — JS only
        "=>",           # arrow function
        "const ",       # JS const declaration
        "let ",         # JS let declaration
        ".shift()",     # array method
        ".push(",       # array method
        ".split(",      # string method
        "require(",     # CommonJS import
        "import ",      # ES module import
        "module.",      # CommonJS module
        "exports.",     # CommonJS exports
        "typeof ",      # JS typeof
        "undefined",    # JS undefined
        "prototype.",   # JS prototype
    ]
    hits = sum(1 for ind in indicators if ind in content)
    return hits >= 2


def classify_patch(vulnerable_lines, fix_lines, patch_filepath=None):

    all_lines = vulnerable_lines + fix_lines
    content = " ".join(all_lines)

    lang = detect_language_from_filename(patch_filepath) if patch_filepath else 'unknown'

    # ── Language-first classification ─────────────────────────────────────

    if lang == 'go':
        return 'go_static'

    if lang == 'rust':
        return 'rust_static'

    if lang in {'javascript', 'typescript'}:
        if any(x in content for x in ['require(', 'import ', 'module.exports']):
            return 'js_bundling'
        return 'js_generic'

    if lang == 'c_cpp':
        if 'template<' in content or (patch_filepath and patch_filepath.endswith('.h')):
            return 'c_cpp_inline'

    # ── Content-based JS detection ────────────────────────────────────────
    # Catches JS patches where the file extension wasn't captured (e.g.
    # when the last file processed was package.json or a lockfile).

    if _content_looks_like_js(content):
        if any(x in content for x in ['require(', 'import ', 'module.exports',
                                        'node_modules', 'package.json']):
            return 'js_bundling'
        return 'js_generic'

    # ── Vulnerability pattern detection ───────────────────────────────────

    if re.search(r'\bNULL\b|\bnullptr\b', content):
        return 'null_deref'

    # Tightened: require C-style MAX_/MIN_ macros, not bare version numbers.
    # Old regex `[<>]=?\s*\d+` matched ">=0.10.0" from package.json engines field.
    if re.search(r'[<>]=?\s*(MAX_|MIN_|[A-Z_]{4,})', content):
        return 'bounds_check'

    # Integer comparison in C context (not version strings)
    if re.search(r'\b(int|size_t|uint|long|ssize_t)\b.*[<>]=?\s*\d+', content):
        return 'bounds_check'

    if re.search(r'\bmalloc\b|\bfree\b|\brealloc\b|\bcalloc\b', content):
        return 'memory_management'

    if re.search(r'\.\./', content) or re.search(r'path.*traversal', content, re.IGNORECASE):
        return 'path_traversal'

    if re.search(r'\bstrcpy\b|\bstrcat\b|\bsprintf\b|\bgets\b', content):
        return 'buffer_overflow'

    return 'generic'


# ---------------------------------------------------------
# Patch parser
# ---------------------------------------------------------

def parse_patch(patch_file):

    vulnerable_lines = []
    fix_lines = []

    current_file = None
    all_files_seen = []   # collect every file for accurate classification

    with open(patch_file, "r", errors="ignore") as f:

        for raw in f:

            # Skip diff metadata
            if raw.startswith(("diff ", "index ", "@@")):
                continue

            # Track file names
            if raw.startswith("--- "):

                parts = raw.split()

                if len(parts) >= 2:
                    p = parts[1]
                    current_file = p[2:] if p.startswith("a/") else p

                continue

            if raw.startswith("+++ "):

                parts = raw.split()

                if len(parts) >= 2:
                    p = parts[1]
                    new_file = p[2:] if p.startswith("b/") else p

                    # Insert a boundary sentinel when file changes.
                    # clone_detector skips empty lines in context pairs,
                    # so this prevents pairing the last line of file A
                    # with the first line of file B.
                    if new_file != current_file and (vulnerable_lines or fix_lines):
                        vulnerable_lines.append("")
                        fix_lines.append("")

                    current_file = new_file
                    if current_file and current_file not in all_files_seen:
                        all_files_seen.append(current_file)

                continue

            # Skip test files and generated files (lockfiles, node_modules, etc.)
            if current_file and (
                is_test_file(current_file) or is_generated_file(current_file)
            ):
                continue

            # Removed lines = vulnerable pattern
            if raw.startswith("-") and not raw.startswith("---"):

                line = clean_line(raw[1:])

                if line:
                    vulnerable_lines.append(line)

            # Added lines = fix pattern
            elif raw.startswith("+") and not raw.startswith("+++"):

                line = clean_line(raw[1:])

                if line:
                    fix_lines.append(line)

    # Remove duplicates
    vulnerable_lines = list(dict.fromkeys(vulnerable_lines))
    fix_lines = list(dict.fromkeys(fix_lines))

    # Classify using ALL files seen, not just the last one.
    # Primary file = first non-generated, non-test source file seen.
    primary_file = next(
        (f for f in all_files_seen
         if not is_test_file(f) and not is_generated_file(f)),
        current_file
    )

    patch_type = classify_patch(vulnerable_lines, fix_lines, primary_file)

    return {
        "vulnerable_lines": vulnerable_lines,
        "fix_lines": fix_lines,
        "patch_type": patch_type
    }
