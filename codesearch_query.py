import requests
import re
import os


DCS_API_KEY = os.environ.get("DCS_API_KEY", "")
API_BASE = "https://codesearch.debian.net/api/v1"


# ---------------------------------------------------------
# Query generation
# ---------------------------------------------------------

def build_query_variants(sig, patch_type='generic'):
    """
    Generate search queries ordered from most specific to least specific.

    Query types (in priority order):
      1. Macro constants — e.g. ANY_SLASH_REGEX, MAX_SAMPLES
      2. RE2 wildcard — e.g. [a-z_]+ < MAX_SAMPLES (variable name wildcard)
      3. camelCase identifiers from context pairs
      4. Function calls
      5. String literals (JS)
      6. Fallback tokens
    """

    queries = []

    # --------------------------------------------------
    # Context pair: extract best token from each half
    # --------------------------------------------------
    if " | " in sig:
        l1, l2 = sig.split(" | ", 1)
        best_l1 = _clean_for_search(l1)
        best_l2 = _clean_for_search(l2)
        if best_l1:
            queries.append(best_l1)
        if best_l2 and best_l2 != best_l1:
            queries.append(best_l2)

    # --------------------------------------------------
    # Macros (strongest anchors)
    # --------------------------------------------------
    macros = re.findall(r'\b[A-Z_]{4,}\b', sig)
    for m in macros:
        queries.append(m)

    # --------------------------------------------------
    # RE2 wildcard variants for comparisons
    # e.g. "s < MAX_SAMPLES" -> "[a-z_]+ < MAX_SAMPLES"
    #      "ptr == NULL"     -> "[a-z_]+ == NULL"
    # These match renamed variables while keeping the structural constraint.
    # --------------------------------------------------
    comp_matches = re.findall(
        r'([a-zA-Z_][a-zA-Z0-9_]*)\s*(==|!=|<=|>=|<|>)\s*([a-zA-Z_][a-zA-Z0-9_]*)',
        sig
    )
    for left, op, right in comp_matches:
        # Wildcard left side (variable) if right is a macro or preserve token
        if re.match(r'^[A-Z_]{3,}$', right) or right in {"NULL", "nullptr", "0"}:
            queries.append(f"[a-z_]+ {op} {right}")
        # Wildcard right side if left is a macro
        if re.match(r'^[A-Z_]{3,}$', left):
            queries.append(f"{left} {op} [a-z_0-9]+")

    # --------------------------------------------------
    # Function calls
    # --------------------------------------------------
    for fc in re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', sig):
        skip = {"if", "for", "while", "switch", "return"}
        if fc not in skip:
            queries.append(fc + "(")

    # --------------------------------------------------
    # Language-specific strategies
    # --------------------------------------------------
    if patch_type.startswith('js_'):

        for _, s in re.findall(r'(["\'])(.*?)\1', sig):
            if len(s) > 3 and s not in {'.', '..', '/'}:
                queries.append(s)

        for m in re.findall(r'module:([^\s]+)', sig):
            queries.append(m)

        # camelCase identifiers are project-specific in JS
        # camelCase identifiers are project-specific in JS
        camel = re.findall(r'\b[a-z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]*\b', sig)
        for c in camel:
            if len(c) > 5:
                queries.append(c)

        # JS string equality patterns: VAR[idx] === 'literal'
        # e.g. "parts[0] === '..'" → query: === '\.\.'
        # Highly specific to path-traversal and boundary-check logic.
        str_eq = re.findall(r"=== '([^']{2,10})'", sig)
        for literal in str_eq:
            if literal not in {'.', '/', ''}:
                escaped = re.escape(literal)
                queries.append(f"=== '{escaped}'")

    elif patch_type.startswith('go_') or patch_type.startswith('rust_'):

        for t in re.findall(r'\b[A-Z][a-zA-Z0-9]+\b', sig):
            if len(t) > 2:
                queries.append(t)

    elif patch_type == 'c_cpp_inline':

        if 'template<' in sig:
            queries.append('template<')

        for c in re.findall(r'\b(static|dynamic|const|reinterpret)_cast', sig):
            queries.append(f"{c}_cast")

    # --------------------------------------------------
    # Fallback: meaningful identifier tokens
    # --------------------------------------------------
    SKIP_TOKENS = {
        "for", "if", "while", "return", "else", "const",
        "let", "var", "new", "this", "true", "false",
        "null", "undefined", "int", "void", "char",
    }

    tokens = re.findall(r'[A-Za-z_][A-Za-z0-9_]*', sig)
    for t in tokens:
        if t not in SKIP_TOKENS and len(t) > 4:
            queries.append(t)

    # --------------------------------------------------
    # Deduplicate while preserving order
    # --------------------------------------------------
    seen = set()
    unique = []

    for q in queries:
        q = q.strip()
        if q and q not in seen:
            seen.add(q)
            unique.append(q)

    return unique


# ---------------------------------------------------------
# Signature cleanup
# ---------------------------------------------------------

def _clean_for_search(q):
    """
    Extract the single most specific searchable token from a signature fragment.

    Priority order:
      1. Uppercase macros (ANY_SLASH_REGEX, MAX_SAMPLES) — most specific
      2. camelCase identifiers (firstPathSegment, resolvedParts) — project-specific
      3. String literals > 2 chars that aren't trivially common ('/', '.', '..')
      4. Long snake_case identifiers >= 8 chars
      5. Function calls > 4 chars
      6. Fallback: longest token that is not a generic keyword
    """
    SKIP = {
        "if", "for", "while", "return", "else", "const", "let", "var",
        "function", "class", "import", "export", "default", "from",
        "new", "this", "true", "false", "null", "undefined",
        "int", "void", "char", "bool", "auto", "static",
        "parts", "path", "part", "node", "args", "opts",
    }

    # Strip context-pair separator
    q = q.replace(" | ", " ")

    tokens = re.findall(r'[A-Za-z_][A-Za-z0-9_]*', q)

    # 1. Uppercase macros (best anchor)
    macros = [t for t in tokens if re.match(r'^[A-Z][A-Z0-9_]{3,}$', t)]
    if macros:
        return max(macros, key=len)

    # 2. camelCase identifiers
    camel = [t for t in tokens
             if re.search(r'[a-z][A-Z]', t) and t not in SKIP and len(t) > 4]
    if camel:
        return max(camel, key=len)

    # 3. String literals that are meaningful (not '/', '.', '..')
    # Use non-greedy match and exclude strings containing quotes themselves
    TRIVIAL_STRINGS = {'/', '.', '..', '', ' ', '\\n', '\\t', "'", '"'}
    string_lits = re.findall(r'"([^"\']{3,})"', q) + re.findall(r"'([^'\"]{3,})'", q)
    useful_strings = [s for s in string_lits if s not in TRIVIAL_STRINGS
                      and not s.startswith(' ')]
    if useful_strings:
        return max(useful_strings, key=len)

    # 4. Long tokens >= 8 chars
    long_tokens = [t for t in tokens if len(t) >= 8 and t not in SKIP]
    if long_tokens:
        return max(long_tokens, key=len)

    # 5. Function calls
    calls = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', q)
    useful_calls = [c for c in calls if c not in SKIP and len(c) > 4]
    if useful_calls:
        return max(useful_calls, key=len)

    # 6. Anything not in skip, length > 3
    useful = [t for t in tokens if t not in SKIP and len(t) > 3]
    if useful:
        return max(useful, key=len)

    return ""


# ---------------------------------------------------------
# API call
# ---------------------------------------------------------

def _call_api(query):

    headers = {"User-Agent": "attack-of-clones-research"}

    if DCS_API_KEY:
        headers["x-dcs-apikey"] = DCS_API_KEY

    # Use regexp mode when the query contains RE2 patterns
    is_regexp = bool(re.search(r'\[.*?\]|\\.|\(\?', query))
    match_mode = "regexp" if is_regexp else "literal"

    for attempt in range(2):
        try:
            r = requests.get(
                f"{API_BASE}/search",
                params={"query": query, "match_mode": match_mode},
                headers=headers,
                timeout=30
            )
            break
        except requests.exceptions.Timeout:
            if attempt == 0:
                print(f"    Timeout, retrying...")
                continue
            print(f"    Timed out after retry, skipping.")
            return []
        except requests.exceptions.RequestException as e:
            print(f"    Request error: {e}")
            return []

    if r.status_code == 403:
        print("    API key required.")
        print("    Get it from https://codesearch.debian.net/apikeys/")
        print("    export DCS_API_KEY=your_key_here")
        return []

    if r.status_code != 200:
        print(f"    Request failed: {r.status_code}")
        return []

    try:
        return r.json()
    except Exception:
        return []


# ---------------------------------------------------------
# Main search function
# ---------------------------------------------------------

# Tokens so common that searching them wastes API quota and causes timeouts.
# These are NOT added to SKIP in _clean_for_search — they can appear in
# multi-token queries — but are refused as standalone search queries.
_TOO_GENERIC = {
    "parts", "path", "part", "node", "args", "opts", "data", "item",
    "name", "type", "list", "size", "len", "val", "buf", "ptr", "err",
    "ret", "res", "str", "tmp", "key", "idx", "pos", "end", "out",
    "src", "dst", "msg", "tag", "num", "obj", "arr", "map", "set",
    # JS-specific generics
    "shift", "push", "pop", "join", "split", "slice", "length",
    "index", "match", "replace", "trim", "test", "exec",
    # C generics
    "free", "exit", "next", "prev", "root", "head", "tail",
}

# Maximum result count before we consider a query too noisy to use.
# CodeSearch caps at 2000; anything >200 is almost certainly a generic token.
MAX_USEFUL_RESULTS = 200


def _is_specific_enough(query: str) -> bool:
    """
    Return False if a query is a single bare token that is too generic
    to produce useful results.
    """
    # Multi-token or regex queries are always worth trying
    stripped = query.strip()
    if " " in stripped or "[" in stripped or "(" in stripped:
        return True
    # Single token: reject if it's a known generic or very short
    token = re.sub(r"[()\[\]]", "", stripped)
    if token.lower() in _TOO_GENERIC:
        return False
    if len(token) <= 3:
        return False
    return True


def search_codesearch(signature, patch_type="generic", source_package=None):
    """
    Search Debian CodeSearch for the given signature.

    source_package: if provided, exclude results from this package
                    (avoids returning the patched package itself as a clone).
    """
    queries = build_query_variants(signature, patch_type)

    print(f"  Trying {len(queries)} query variant(s)...")

    for q in queries:

        if not q:
            continue

        if not _is_specific_enough(q):
            print(f"    Skipping generic query: {q}")
            continue

        print(f"    Query: {q}")
        results = _call_api(q)

        if not results:
            continue

        # Filter out the source package itself — it's the vulnerable one,
        # not a clone. Match on the package name portion before the underscore.
        if source_package:
            pkg_prefix = source_package.split("_")[0].lower()
            filtered = [
                r for r in results
                if not r.get("package", "").lower().startswith(pkg_prefix)
            ]
            if len(filtered) < len(results):
                excluded = len(results) - len(filtered)
                print(f"    (excluded {excluded} result(s) from source package)")
            results = filtered

        if not results:
            continue

        # Reject queries that match too much — they generate noise, not signal
        if len(results) >= MAX_USEFUL_RESULTS:
            print(f"    {len(results)} results — too noisy, trying next variant")
            continue

        print(f"    Found {len(results)} match(es).")
        return results[:20]

    print("  No matches found for any query variant.")
    return []

def search_by_filename(filename: str, source_package: str = None) -> list:
    """
    Search Debian CodeSearch for packages containing a specific filename.

    Used for vendoring detection: if a patch touches vendor/zlib/inflate.c,
    searching for "inflate.c" finds other Debian packages that have copied
    that same file — regardless of what the code inside looks like.

    Uses literal match mode — no tokenization, no variant generation.
    The query is the full filename including extension (e.g. "inflate.c").

    Returns up to 50 results (more than the standard 20 — vendoring searches
    are broader by design and we want to see all affected packages).
    """
    if not filename:
        return []

    print(f"    Filename query (literal): {filename}")
    results = _call_api(filename)

    if not results:
        return []

    # Filter out the source package itself
    if source_package:
        pkg_prefix = source_package.split("_")[0].lower()
        results = [
            r for r in results
            if not r.get("package", "").lower().startswith(pkg_prefix)
        ]

    if len(results) >= MAX_USEFUL_RESULTS:
        print(f"    {len(results)} results — filename too common, skipping.")
        return []

    print(f"    Found {len(results)} package(s) containing {filename}.")
    return results[:50]
