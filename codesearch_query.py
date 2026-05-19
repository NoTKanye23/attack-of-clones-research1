import requests
import re
import os
 
 
DCS_API_KEY = os.environ.get("DCS_API_KEY", "")
API_BASE = "https://codesearch.debian.net/api/v1"
 
 
def build_query_variants(sig, patch_type='generic'):
    """
    Generate search queries ordered from most specific to least specific.
    """
    queries = []
 
    if " | " in sig:
        l1, l2 = sig.split(" | ", 1)
        best_l1 = _clean_for_search(l1)
        best_l2 = _clean_for_search(l2)
        if best_l1:
            queries.append(best_l1)
        if best_l2 and best_l2 != best_l1:
            queries.append(best_l2)
 
    macros = re.findall(r'\b[A-Z_]{4,}\b', sig)
    queries.extend(macros)
 
    comp_matches = re.findall(
        r'([a-zA-Z_][a-zA-Z0-9_]*)\s*(==|!=|<=|>=|<|>)\s*([a-zA-Z_][a-zA-Z0-9_]*)',
        sig
    )
    for left, op, right in comp_matches:
        if re.match(r'^[A-Z_]{3,}$', right) or right in {"NULL", "nullptr", "0"}:
            queries.append(f"[a-z_]+ {op} {right}")
        if re.match(r'^[A-Z_]{3,}$', left):
            queries.append(f"{left} {op} [a-z_0-9]+")
 
    for fc in re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', sig):
        skip = {"if", "for", "while", "switch", "return"}
        if fc not in skip:
            queries.append(fc + "(")
 
    if patch_type.startswith('js_'):
        for _, s in re.findall(r'(["\'])(.*?)\1', sig):
            if len(s) > 3 and s not in {'.', '..', '/'}:
                queries.append(s)
        for m in re.findall(r'module:([^\s]+)', sig):
            queries.append(m)
        camel = re.findall(r'\b[a-z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]*\b', sig)
        for c in camel:
            if len(c) > 5:
                queries.append(c)
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
 
    SKIP_TOKENS = {
        "for", "if", "while", "return", "else", "const",
        "let", "var", "new", "this", "true", "false",
        "null", "undefined", "int", "void", "char",
    }
    tokens = re.findall(r'[A-Za-z_][A-Za-z0-9_]*', sig)
    for t in tokens:
        if t not in SKIP_TOKENS and len(t) > 4:
            queries.append(t)
 
    seen = set()
    unique = []
    for q in queries:
        q = q.strip()
        if q and q not in seen:
            seen.add(q)
            unique.append(q)
    return unique
 
 
def _clean_for_search(q):
    """Extract the single most specific searchable token from a signature fragment."""
    SKIP = {
        "if", "for", "while", "return", "else", "const", "let", "var",
        "function", "class", "import", "export", "default", "from",
        "new", "this", "true", "false", "null", "undefined",
        "int", "void", "char", "bool", "auto", "static",
        "parts", "path", "part", "node", "args", "opts",
    }
    q = q.replace(" | ", " ")
    tokens = re.findall(r'[A-Za-z_][A-Za-z0-9_]*', q)
 
    macros = [t for t in tokens if re.match(r'^[A-Z][A-Z0-9_]{3,}$', t)]
    if macros:
        return max(macros, key=len)
 
    camel = [t for t in tokens if re.search(r'[a-z][A-Z]', t) and t not in SKIP and len(t) > 4]
    if camel:
        return max(camel, key=len)
 
    TRIVIAL_STRINGS = {'/', '.', '..', '', ' ', '\\n', '\\t', "'", '"'}
    string_lits = re.findall(r'"([^"\']{3,})"', q) + re.findall(r"'([^'\"]{3,})'", q)
    useful_strings = [s for s in string_lits if s not in TRIVIAL_STRINGS and not s.startswith(' ')]
    if useful_strings:
        return max(useful_strings, key=len)
 
    long_tokens = [t for t in tokens if len(t) >= 8 and t not in SKIP]
    if long_tokens:
        return max(long_tokens, key=len)
 
    calls = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', q)
    useful_calls = [c for c in calls if c not in SKIP and len(c) > 4]
    if useful_calls:
        return max(useful_calls, key=len)
 
    useful = [t for t in tokens if t not in SKIP and len(t) > 3]
    if useful:
        return max(useful, key=len)
    return ""
 
 
def _call_api(query):
    headers = {"User-Agent": "attack-of-clones-research"}
    if DCS_API_KEY:
        headers["x-dcs-apikey"] = DCS_API_KEY
 
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
        return []
    if r.status_code != 200:
        print(f"    Request failed: {r.status_code}")
        return []
    try:
        return r.json()
    except Exception:
        return []
 
 
_TOO_GENERIC = {
    "parts", "path", "part", "node", "args", "opts", "data", "item",
    "name", "type", "list", "size", "len", "val", "buf", "ptr", "err",
    "ret", "res", "str", "tmp", "key", "idx", "pos", "end", "out",
    "src", "dst", "msg", "tag", "num", "obj", "arr", "map", "set",
    "shift", "push", "pop", "join", "split", "slice", "length",
    "index", "match", "replace", "trim", "test", "exec",
    "free", "exit", "next", "prev", "root", "head", "tail",
}
 
MAX_USEFUL_RESULTS = 200      # signature searches — code patterns
FILENAME_MAX_RESULTS = 5000   # filename searches — path filtering reduces these downstream
 
 
def _is_specific_enough(query: str) -> bool:
    stripped = query.strip()
    if " " in stripped or "[" in stripped or "(" in stripped:
        return True
    token = re.sub(r"[()\[\]]", "", stripped)
    if token.lower() in _TOO_GENERIC:
        return False
    if len(token) <= 3:
        return False
    return True
 
 
def search_codesearch(signature, patch_type="generic", source_package=None):
    queries = build_query_variants(signature, patch_type)
    print(f"  Trying {len(queries)} query variant(s)...")
 
    for q in queries:
        if not q:
            continue
 
        lowered = q.lower()
        if any(word in lowered for word in ["negative", "must", "invalid", "error"]):
            print(f"    Skipping comment-derived query: {q}")
            continue
 
        if not _is_specific_enough(q):
            print(f"    Skipping generic query: {q}")
            continue
 
        print(f"    Query: {q}")
        results = _call_api(q)
        if not results:
            continue
 
        if source_package:
            pkg_prefix = source_package.split("_")[0].lower()
            filtered = [r for r in results if not r.get("package", "").lower().startswith(pkg_prefix)]
            if len(filtered) < len(results):
                excluded = len(results) - len(filtered)
                print(f"    (excluded {excluded} result(s) from source package)")
            results = filtered
        if not results:
            continue
 
        if len(results) >= MAX_USEFUL_RESULTS:
            print(f"    {len(results)} results — too noisy, trying next variant")
            continue
 
        print(f"    Found {len(results)} match(es).")
        return results[:20]
 
    print("  No matches found for any query variant.")
    return []
 
 
def search_by_filename(filename: str, source_package: str = None) -> list:
    """Search for packages containing a specific filename (literal)."""
    if not filename:
        return []
    print(f"    Filename query (literal): {filename}")
    results = _call_api(filename)
    if not results:
        return []
 
    if source_package:
        pkg_prefix = source_package.split("_")[0].lower()
        results = [r for r in results if not r.get("package", "").lower().startswith(pkg_prefix)]
 
    seen = set()
    deduped = []
    for r in results:
        key = (r.get("package", ""), r.get("path", ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(r)
 
    if len(deduped) >= FILENAME_MAX_RESULTS:
        print(f"    {len(deduped)} results — filename too common, skipping.")
        return []
    print(f"    Found {len(deduped)} package(s) containing {filename}.")
    return deduped[:200]  # higher cap than signature search
 
 
# ---------------------------------------------------------
# Fix 2: Per-package search (searchperpackage endpoint)
# ---------------------------------------------------------
# Collapses N file-level results into ≤2 results per source package.
# Converts 2141 crc32.c file hits → ~50 package-level hits.
# Research basis: Debian CodeSearch API /api/v1/searchperpackage
# Used by Salvatore Bonaccorso (Debian security team) manually;
# this function automates that workflow.
 
def search_per_package(query: str, source_package: str = None) -> list:
    """
    Query Debian CodeSearch's searchperpackage endpoint.
    Returns ≤2 results per source package — dramatically reduces noise
    for common tokens like function names or filenames.
 
    Use this for:
      - Library-anchored token searches (x2nmodp, multmodp)
      - Filename searches where the filename is common (crc32.c)
      - Any query expected to return >200 file-level results
    """
    if not query:
        return []
 
    headers = {"User-Agent": "attack-of-clones-research"}
    if DCS_API_KEY:
        headers["x-dcs-apikey"] = DCS_API_KEY
 
    print(f"    Per-package query: {query}")
 
    for attempt in range(2):
        try:
            r = requests.get(
                f"{API_BASE}/searchperpackage",
                params={"query": query},
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
        return []
    if r.status_code != 200:
        print(f"    Request failed: {r.status_code}")
        return []
 
    try:
        data = r.json()
    except Exception:
        return []
 
    # searchperpackage returns nested: [{package, results:[{package, path, context...}]}]
    # Flatten to the same format as /search so callers need no special handling
    flat = []
    for item in data:
        for result in item.get("results", []):
            flat.append(result)
    data = flat
 
    # Filter out the source package itself
    if source_package:
        pkg_prefix = source_package.split("_")[0].lower()
        data = [r for r in data
                if not r.get("package", "").lower().startswith(pkg_prefix)]
 
    print(f"    Found {len(data)} result(s) across packages via per-package search.")
    return data
 
 
def build_restricted_query(token: str, filetype: str = None,
                           path_hint: str = None,
                           exclude_package: str = None) -> str:
    """
    Fix 3: Build a field-restricted CodeSearch query.
    Debian CodeSearch supports: filetype:c, path:<regex>, -package:<name>
 
    Examples:
      build_restricted_query("x2nmodp", filetype="c", exclude_package="zlib")
      → "x2nmodp filetype:c -package:zlib"
 
      build_restricted_query("crc32_combine64", path_hint="crc32")
      → "crc32_combine64 path:crc32"
    """
    parts = [token]
    if filetype:
        parts.append(f"filetype:{filetype}")
    if path_hint:
        parts.append(f"path:{path_hint}")
    if exclude_package:
        parts.append(f"-package:{exclude_package}")
    return " ".join(parts)
