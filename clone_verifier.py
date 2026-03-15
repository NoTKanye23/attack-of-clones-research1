import re


# File extensions per language family — used to cross-check that
# a result file actually matches the patch language before confirming.
_LANG_EXTENSIONS = {
    "js_bundling": {".js", ".mjs", ".cjs", ".ts", ".tsx"},
    "js_generic":  {".js", ".mjs", ".cjs", ".ts", ".tsx"},
    "go_static":   {".go"},
    "rust_static": {".rs"},
    "c_cpp":       {".c", ".h", ".cpp", ".hpp", ".cc", ".cxx"},
    "c_cpp_inline":{".c", ".h", ".cpp", ".hpp", ".cc", ".cxx"},
    "null_deref":  {".c", ".h", ".cpp", ".hpp", ".cc", ".cxx",
                    ".go", ".rs", ".py"},
    "bounds_check":{".c", ".h", ".cpp", ".hpp", ".cc", ".cxx"},
    "memory_management": {".c", ".h", ".cpp", ".hpp", ".cc", ".cxx"},
    "buffer_overflow":   {".c", ".h", ".cpp", ".hpp", ".cc", ".cxx"},
    "path_traversal":    {".c", ".h", ".cpp", ".hpp", ".py",
                          ".go", ".rs", ".js", ".ts"},
    "generic":     None,  # None = accept any extension
}


def _file_extension(path: str) -> str:
    """Return lowercased file extension including the dot, e.g. '.go'"""
    if "." in path:
        return "." + path.rsplit(".", 1)[1].lower()
    return ""


def _language_matches(result_path: str, patch_type: str) -> bool:
    """
    Return True if the result file's extension is compatible with the
    patch language type.

    This is the primary false-positive filter for cross-language token
    collisions (e.g. JS patch matching a Go file because a camelCase
    identifier appears in both).
    """
    allowed = _LANG_EXTENSIONS.get(patch_type)
    if allowed is None:
        return True  # generic patch — accept any file
    ext = _file_extension(result_path)
    return ext in allowed


def _normalize(text: str) -> str:
    """Normalize whitespace for comparison."""
    return " ".join(text.split())


def _tokenize(text: str) -> set:
    """Extract meaningful tokens from text."""
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text)
    return {t for t in tokens if len(t) > 1}


def contains_vulnerable_pattern(code: str, vuln_sig: str) -> bool:
    """
    Check if code contains the vulnerable pattern.
    Uses normalized exact match first, then token overlap fallback.
    """
    if _normalize(vuln_sig) in _normalize(code):
        return True

    sig_tokens = _tokenize(vuln_sig)
    code_tokens = _tokenize(code)

    if not sig_tokens:
        return False

    overlap = sig_tokens.intersection(code_tokens)
    return len(overlap) / len(sig_tokens) >= 0.8


def contains_fix_pattern(code: str, fix_signatures: list) -> bool:
    """
    Return True if code already contains the fix — meaning the clone
    has already been patched and should not be reported.
    """
    norm_code = _normalize(code)
    for fix in fix_signatures:
        if _normalize(fix) in norm_code:
            return True
    return False


def verify_from_context(result: dict, vuln_sig: str, fix_sigs: list,
                        patch_type: str = "generic") -> bool:
    """
    Verify a candidate clone using the API's inline context window.

    A confirmed vulnerable clone must:
      1. Come from a file whose extension matches the patch language
      2. Contain the vulnerable pattern in its context lines
      3. NOT already contain the fix pattern

    The language check (step 1) is the key false-positive filter:
    it prevents JS patches from matching Go/Rust files that happen
    to share camelCase identifiers.
    """
    path = result.get("path", "")

    # Language cross-check — reject mismatched file types immediately
    if not _language_matches(path, patch_type):
        return False

    context_lines = (
        result.get("context_before", [])
        + [result.get("context", "")]
        + result.get("context_after", [])
    )
    code_block = "\n".join(context_lines)

    if not contains_vulnerable_pattern(code_block, vuln_sig):
        return False

    if contains_fix_pattern(code_block, fix_sigs):
        return False

    return True


def is_vulnerable_clone(code: str, vuln_sig: str, fix_sigs: list,
                        patch_type: str = "generic",
                        result_path: str = "") -> bool:
    """
    Full verification using complete file content.
    Used when file content has been fetched from sources.debian.org.
    """
    # Language check applies to full-file verification too
    if result_path and not _language_matches(result_path, patch_type):
        return False

    if not contains_vulnerable_pattern(code, vuln_sig):
        return False

    if contains_fix_pattern(code, fix_sigs):
        return False

    return True
