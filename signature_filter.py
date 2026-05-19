import re

NOISE_TOKENS = {
    "NULL","TRUE","FALSE","EOF","NONE",
    "SIZE","TYPE","FLAG","MODE","DATA",
    "ERR","RET","BUF","PTR","LEN",
}

C_KEYWORDS = {
    "if","for","while","return","else","break",
    "continue","switch","case","default","do",
}

GENERIC_CALLS = {
    "shift","push","pop","join","split","slice","splice",
    "forEach","filter","reduce","map","find","sort","reverse",
    "toString","indexOf","includes","startsWith","endsWith",
    "replace","match","trim","concat","length","keys","values",
    "entries","assign","create","free","exit","next","open",
    "close","read","write","printf","fprintf","malloc","realloc",
}

_PROSE_PHRASES = {
    "must be","should be","non-negative","non negative",
    "vulnerable","patched","comment","otherwise zero is returned",
    "calculated for each","concatenated","seq1","seq2","requiring only",
    "were calculated","used with",
}


def _is_bare_string_literal(text: str) -> bool:
    s = text.strip()
    if not (s.startswith('"') or s.startswith("'")):
        return False
    if re.search(r'[()=!<>&|{}\[\]]', s):
        return False
    inner = s.strip("\"'")
    return " " not in inner


def _is_json_lockfile_line(text: str) -> bool:
    s = text.strip()
    if re.match(r'^"[^"]+"\s*:', s):        return True
    if re.search(r'[a-z0-9]>[a-z@]', s):   return True
    if re.match(r'^"\d+"\s*[,{]?$', s):    return True
    if re.match(r'^[\d.]+$', s):            return True
    if s.startswith('- `npm ') or s.startswith('`npm '): return True
    return False


def _is_standalone_generic_call(text: str) -> bool:
    m = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\s*\)?$', text.strip())
    return bool(m) and m.group(1) in GENERIC_CALLS


def _is_pure_commentary(text: str) -> bool:
    """
    MVP: reject if prose phrase present AND no code structure characters
    Code chars: = ( ) { } ; < >
    A commentary line with an embedded function call is NOT pure commentary.
    """
    lowered  = text.lower()
    has_prose = any(p in lowered for p in _PROSE_PHRASES)
    has_code  = bool(re.search(r'[=(){};<>]', text))
    return has_prose and not has_code


def filter_signatures(signatures):
    filtered, seen = [], set()

    for sig in signatures:
        text = sig["signature"] if isinstance(sig, dict) else sig
        text = text.strip()

        if not text or text in seen:               continue
        if len(text) < 2 or len(text) > 250:       continue
        if text in ("{","}",";","(",")",","):       continue
        if text in C_KEYWORDS or text in NOISE_TOKENS: continue
        if _is_bare_string_literal(text):           continue
        if _is_json_lockfile_line(text):            continue
        if _is_standalone_generic_call(text):       continue
        if _is_pure_commentary(text):               continue

        # Comparisons — always keep
        if re.search(r'(==|!=|<=|>=|<|>)', text):
            filtered.append(text); seen.add(text); continue

        # Function calls — keep if not generic
        if re.search(r'[a-zA-Z_][a-zA-Z0-9_]*\s*\(', text):
            filtered.append(text); seen.add(text); continue

        # Uppercase macros
        if re.match(r'^[A-Z_]{4,}$', text):
            filtered.append(text); seen.add(text); continue

        # Context pairs: check each half
        if " | " in text:
            l1, l2 = text.split(" | ", 1)
            if (not _is_json_lockfile_line(l1) and not _is_json_lockfile_line(l2)
                    and not _is_pure_commentary(l1) and not _is_pure_commentary(l2)):
                filtered.append(text); seen.add(text)
            continue

        # N-gram / block signatures: space-separated, has a specific anchor token
        if " " in text and " | " not in text and len(text) >= 10:
            parts = text.split()
            if any(p not in {"VAR","NUM","VARIABLE","STRING"} and len(p) > 3
                   for p in parts):
                filtered.append(text); seen.add(text)
            continue

        if len(text) >= 6:
            filtered.append(text); seen.add(text)

    return filtered
