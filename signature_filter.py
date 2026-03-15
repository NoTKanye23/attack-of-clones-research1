import re


NOISE_TOKENS = {
    "NULL", "TRUE", "FALSE", "EOF", "NONE",
    "SIZE", "TYPE", "FLAG", "MODE", "DATA",
    "ERR", "RET", "BUF", "PTR", "LEN"
}

C_KEYWORDS = {
    "if", "for", "while", "return", "else", "break",
    "continue", "switch", "case", "default", "do"
}

# Function/method names so common in JS/Go/C that searching them
# as standalone signatures produces only noise.
GENERIC_CALLS = {
    "shift", "push", "pop", "join", "split", "slice", "splice",
    "forEach", "filter", "reduce", "map", "find", "sort", "reverse",
    "toString", "indexOf", "includes", "startsWith", "endsWith",
    "replace", "match", "trim", "concat", "length", "keys", "values",
    "entries", "assign", "create", "free", "exit", "next", "open",
    "close", "read", "write", "printf", "fprintf", "malloc", "realloc",
}


def _is_bare_string_literal(text: str) -> bool:
    """
    Return True if the signature is just a quoted string with no code structure.
    These come from JSON values, config strings, and import paths.

    Acceptable quoted strings: those containing operators, parens, brackets
    i.e. actual code fragments that happen to be quoted.
    Rejected: bare module names, path fragments, config keys, timestamps.
    """
    stripped = text.strip()
    # Must start and end with a quote to be a bare string
    if not (stripped.startswith('"') or stripped.startswith("'")):
        return False
    # If it contains code-like characters, keep it
    if re.search(r'[()=!<>&|{}\[\]]', stripped):
        return False
    # If it contains a space it might be a meaningful phrase — keep it
    inner = stripped.strip("\"'")
    if " " in inner:
        return False
    # Bare relative paths, package names, config keys → reject
    return True


def _is_json_lockfile_line(text: str) -> bool:
    """
    Return True if the line looks like it came from a JSON lockfile,
    package-lock.json, npm audit output, or similar non-code content.

    These enter patches as changes to lock files and produce
    completely useless search queries (e.g. "madeAt": 1771566180086).
    """
    stripped = text.strip()

    # JSON string key-value pairs: "key": value
    if re.match(r'^"[^"]+"\s*:', stripped):
        return True

    # Dependency chains from npm audit: pkg>pkg>pkg (must contain >)
    if re.search(r'[a-z0-9]>[a-z@]', stripped):
        return True

    # Lines that are purely numeric IDs like "1113214" (npm audit IDs)
    if re.match(r'^"\d+"\s*[,{]?$', stripped):
        return True

    # Pure numeric timestamps or version strings with no code structure
    if re.match(r'^[\d.]+$', stripped):
        return True

    # npm run / build script lines from README fragments in patches
    if stripped.startswith('- `npm ') or stripped.startswith('`npm '):
        return True

    return False


def _is_standalone_generic_call(text: str) -> bool:
    """
    Return True if the signature is a single generic function call
    that would return hundreds of thousands of CodeSearch results.
    """
    # Match bare "name(" or "name(" with no other content
    m = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\s*\)?$', text.strip())
    if m and m.group(1) in GENERIC_CALLS:
        return True
    return False


def filter_signatures(signatures):
    """
    Remove noisy or trivial signatures. Keep:
      - comparison expressions
      - non-generic function calls
      - uppercase macro constants (4+ chars)
      - control-flow patterns
      - context pairs (two-line joins)
    Reject:
      - JSON/lockfile content
      - single generic function calls
      - C keywords, noise tokens, pure punctuation
    """
    filtered = []
    seen = set()

    for sig in signatures:
        text = sig["signature"] if isinstance(sig, dict) else sig
        text = text.strip()

        if not text or text in seen:
            continue
        if len(text) < 2 or len(text) > 120:
            continue
        if text in ("{", "}", ";", "(", ")", ","):
            continue
        if text in C_KEYWORDS or text in NOISE_TOKENS:
            continue

        # Reject bare quoted string literals (module paths, config keys)
        if _is_bare_string_literal(text):
            continue

        # Reject JSON lockfile content
        if _is_json_lockfile_line(text):
            continue

        # Reject standalone generic function calls
        if _is_standalone_generic_call(text):
            continue

        # Keep comparison expressions
        if re.search(r'(==|!=|<=|>=|<|>)', text):
            filtered.append(text)
            seen.add(text)
            continue

        # Keep non-generic function calls
        if re.search(r'[a-zA-Z_][a-zA-Z0-9_]*\s*\(', text):
            filtered.append(text)
            seen.add(text)
            continue

        # Keep uppercase macros (min 4 chars)
        if re.match(r'^[A-Z_]{4,}$', text):
            filtered.append(text)
            seen.add(text)
            continue

        # Keep context pairs — but only if neither half is a lockfile line
        if " | " in text:
            l1, l2 = text.split(" | ", 1)
            if not _is_json_lockfile_line(l1) and not _is_json_lockfile_line(l2):
                filtered.append(text)
                seen.add(text)
            continue

        # Keep anything else with reasonable length
        if len(text) >= 6:
            filtered.append(text)
            seen.add(text)

    return filtered
