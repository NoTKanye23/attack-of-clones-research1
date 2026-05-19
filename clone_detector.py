import re
from patch_parser import parse_patch

PRESERVE_TOKENS = {
    "NULL", "nullptr", "malloc", "free", "realloc", "calloc",
    "memcpy", "memset", "strlen", "strcpy", "strcat", "sprintf",
    "fprintf", "printf", "assert", "abort", "exit",
}

# ---------------------------------------------------------------------------
# MVP §3.2.2 — Statement abstraction
# ---------------------------------------------------------------------------

_FORMAT_SPEC = re.compile(
    r'%(?:\d+\$)?[-+0 #]*\d*(?:\.\d+)?[hlLqjzt]?[diouxXeEfFgGcsSp%nAa]'
)

def _abstract_string(s):
    """Preserve printf format specifiers; replace everything else with STRING."""
    specs = _FORMAT_SPEC.findall(s)
    return "".join(specs) if specs else "STRING"


def abstract_line(line):
    """
    MVP §3.2.2 lightweight abstraction:
      string literals  -> STRING (or format specs)
      integer literals -> NUM
      lowercase locals -> VARIABLE   (heuristic; keywords/APIs/macros preserved)
    Used for block/body signatures so Type-2 clones are matched during verify.
    NOT used for search query generation (would kill recall).
    """
    line = re.sub(r'"([^"]*)"', lambda m: _abstract_string(m.group(1)), line)
    line = re.sub(r"'([^']*)'", lambda m: "STRING", line)
    line = re.sub(r'\b\d+\b', 'NUM', line)

    _KW = {
        "if","for","while","return","else","switch","case","break","continue",
        "do","sizeof","typedef","struct","enum","union","static","const",
        "unsigned","signed","long","short","void","int","char","bool",
        "auto","extern","inline",
    }
    def _replace(m):
        w = m.group(0)
        if w in _KW:            return w
        if w in PRESERVE_TOKENS: return w
        if re.match(r'^[A-Z_]{3,}$', w): return w   # macro
        if w[0].islower():      return "VARIABLE"
        return w

    return re.sub(r'\b[A-Za-z_][A-Za-z0-9_]*\b', _replace, line)


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def normalize_line(line):
    line = re.sub(r'//.*', '', line)
    line = re.sub(r'/\*.*?\*/', '', line, flags=re.DOTALL)
    return re.sub(r'\s+', ' ', line.strip())


def _is_comment_line(line):
    s = line.strip()
    if s.startswith("//") or s.startswith("*") or s.startswith("/*"):
        return True
    if "//" in s and not any(c in s for c in "();{}"):
        return True
    return False


_PROSE_MARKERS = [
    "must be", "should be", "non-negative", "non negative",
    "vulnerable", "patched", "otherwise zero is returned",
    "were calculated", "concatenated", "seq1", "seq2",
    "requiring only", "calculated for each",
]


def _looks_like_prose(line):
    lowered = line.lower()
    return any(m in lowered for m in _PROSE_MARKERS)


def _line_is_code(line):
    if _is_comment_line(line): return False
    if _looks_like_prose(line): return False
    return bool(re.search(r'[=(){}\[\];<>]|[a-zA-Z_][a-zA-Z0-9_]*\s*\(', line))


def _line_is_meaningful(line):
    if _looks_like_prose(line): return False
    if re.search(r'[a-zA-Z_][a-zA-Z0-9_]*\s*\(', line):       return True
    if re.search(r'(==|!=|<=|>=|<|>)\s*[a-zA-Z0-9_]', line):  return True
    if re.search(r'\b(if|for|while|return)\b', line):           return True
    if re.search(r'\b[A-Z_]{4,}\b', line):                      return True
    if re.search(r'[=;{}]', line):                              return True
    return False


# ---------------------------------------------------------------------------
# MOVERY §3 — Core Vulnerable Line (CVL) extraction
# ---------------------------------------------------------------------------
# MOVERY defines CVLs as lines that: (a) appear only in the vulnerable version,
# (b) are not purely whitespace/comment, (c) are semantically related to the
# fix (share tokens with the patch lines).  We implement a lightweight version:
# filter out comment/prose lines, then score remaining lines by token overlap
# with the fix lines.  Lines with zero overlap to the fix are still kept if
# they contain code structure — they may be the vulnerable body that the fix
# wraps around.

def extract_core_vulnerable_lines(vulnerable_lines, fix_lines):
    """
    MOVERY-inspired CVL extraction.
    Returns a subset of vulnerable_lines that are most likely to be
    semantically related to the vulnerability, ordered by relevance.
    """
    fix_tokens = set()
    for l in fix_lines:
        fix_tokens.update(re.findall(r'[A-Za-z_][A-Za-z0-9_]*', l))

    # Drop keywords that are too generic to discriminate
    _DROP = {"if","for","while","return","else","int","void","char","static"}
    fix_tokens -= _DROP

    scored = []
    for line in vulnerable_lines:
        if not line or _is_comment_line(line) or _looks_like_prose(line):
            continue
        nl = normalize_line(line)
        if not nl or not _line_is_code(nl):
            continue
        line_tokens = set(re.findall(r'[A-Za-z_][A-Za-z0-9_]*', nl)) - _DROP
        # Overlap score: shared tokens with the fix (MOVERY semantic proximity)
        overlap = len(line_tokens & fix_tokens)
        # Length score: prefer longer, more specific lines
        length_score = min(len(nl) / 20.0, 3.0)
        scored.append((nl, overlap + length_score))

    scored.sort(key=lambda x: x[1], reverse=True)
    return [line for line, _ in scored]


# ---------------------------------------------------------------------------
# Structured extractors (CPVDetector + baseline)
# ---------------------------------------------------------------------------

def extract_comparisons(line):
    pattern = r'([a-zA-Z0-9_]+)\s*(==|!=|<=|>=|<|>)\s*([a-zA-Z0-9_]+)'
    sigs = []
    for l, op, r in re.findall(pattern, line):
        sigs.append(f"{l} {op} {r}")
        if r.isdigit(): sigs.append(f"{l} {op} NUM")
    return sigs


def extract_function_calls(line):
    skip  = {"if","for","while","switch","return","sizeof"}
    calls = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', line)
    return [c + "(" for c in calls if c not in skip]


def extract_macros(line):
    return re.findall(r'\b[A-Z_]{4,}\b', line)


def extract_control_flow(line):
    if re.search(r'\b(if|for|while)\s*\(', line):
        return [normalize_line(line)]
    return []


def extract_loop_condition(line):
    m = re.search(r'\b(while|for)\s*\(([^)]+)\)', line)
    return [m.group(2).strip()] if m else []


def extract_context_pairs(lines):
    """
    CPVDetector §3: context pairs (two adjacent code lines).
    Both lines must be meaningful (not comment/prose) for the pair to be kept.
    This is the highest-precision signature type per our experiments.
    """
    pairs = []
    for i in range(len(lines) - 1):
        if _is_comment_line(lines[i]) and _is_comment_line(lines[i+1]):
            continue
        l1 = normalize_line(lines[i])
        l2 = normalize_line(lines[i+1])
        if not l1 or not l2:                continue
        if len(l1) < 3 or len(l2) < 3:     continue
        if len(l1) > 120 or len(l2) > 120: continue
        if _looks_like_prose(l1) or _looks_like_prose(l2): continue
        # CPVDetector: BOTH lines must be code-meaningful
        if not (_line_is_meaningful(l1) and _line_is_meaningful(l2)): continue
        pairs.append(f"{l1} | {l2}")
    return pairs


def extract_function_body(lines):
    """
    Extract complete function body. Emits both raw and MVP-abstracted variants
    so Type-2 clones (renamed variables) are caught at verification time.
    """
    body_lines = []
    in_body    = False
    brace_count = 0
    for line in lines:
        if _is_comment_line(line): continue
        if not in_body:
            if re.search(r'\b\w+\s+\w+\s*\([^)]*\)\s*\{?', line):
                in_body = True
                body_lines.append(normalize_line(line))
                brace_count += line.count('{') - line.count('}')
        else:
            body_lines.append(normalize_line(line))
            brace_count += line.count('{') - line.count('}')
            if brace_count == 0: break
    if not body_lines:
        return []
    raw_body   = " ".join(body_lines)
    abstracted = abstract_line(raw_body)
    sigs = [raw_body]
    if abstracted != raw_body:
        sigs.append(abstracted)
    return sigs


def extract_full_vulnerable_block(lines):
    """
    Join all code-like removed lines into one block signature.
    MVP §3.2.2: also emit abstracted variant for Type-2 clone matching.
    Uses MOVERY CVL ordering internally (most relevant lines first).
    """
    meaningful = []
    for l in lines:
        if _is_comment_line(l): continue
        nl = normalize_line(l)
        if not nl or _looks_like_prose(nl): continue
        if _line_is_code(nl): meaningful.append(nl)
    if not meaningful:
        return []
    raw_block  = " ".join(meaningful)
    if len(raw_block) > 500:
        raw_block = raw_block[:500] + "..."
    abstracted = abstract_line(raw_block)
    sigs = [raw_block]
    if abstracted != raw_block:
        sigs.append(abstracted)
    return sigs


# ---------------------------------------------------------------------------
# ReDeBug §3 — 4-gram n-gram extractor with entropy gate
# ---------------------------------------------------------------------------
# ReDeBug uses 4-grams over a lowercase token stream.  We add an entropy gate
# (inspired by MVP §3.3.3): a n-gram is only kept if it contains at least one
# token that is long enough (>=7 chars) to discriminate between files.
# This prevents "if len < 0" style grams from flooding the signature set.

_NGRAM_SKIP = {
    "if","for","while","return","else","switch","case","break","continue",
    "do","int","void","char","bool","auto","static","const","unsigned",
    "signed","long","short","struct","enum","typedef","extern","inline",
    "the","and","or","not","new","this","true","false","null","none",
    "var","let","def","self","cls",
}


def _ngram_normalize(line):
    """ReDeBug §3: lowercase, strip comments/punctuation, collapse whitespace."""
    line = re.sub(r'//.*', '', line)
    line = re.sub(r'/\*.*?\*/', '', line)
    line = re.sub(r'[{};,\(\)\[\]]', ' ', line)
    return re.sub(r'\s+', ' ', line.lower().strip())


def extract_ngram_signatures(lines, n=4):
    """
    ReDeBug-inspired 4-gram extraction.
    Entropy gate: n-gram must have >= 1 token of length >= 7 that is not
    a generic keyword/skip token.
    This is the fallback for patches (like zlib math) where structured
    extractors produce only prose or overly-generic function calls.
    """
    all_tokens = []
    for line in lines:
        if _is_comment_line(line) or _looks_like_prose(line):
            continue
        norm = _ngram_normalize(line)
        if norm:
            toks = re.findall(r'[a-z_][a-z0-9_]*|\d+', norm)
            all_tokens.extend(toks)

    if len(all_tokens) < n:
        return []

    seen, result = set(), []
    for i in range(len(all_tokens) - n + 1):
        window = all_tokens[i:i+n]
        gram   = " ".join(window)
        if gram in seen:
            continue
        # Entropy gate: at least one informative long token
        if not any(len(t) >= 7 and t not in _NGRAM_SKIP for t in window):
            continue
        seen.add(gram)
        result.append(gram)
    return result


# ---------------------------------------------------------------------------
# Language-specific extractors
# ---------------------------------------------------------------------------

def extract_js_signatures(lines):
    sigs = set()
    _SKIP_STRINGS = {
        "./utils/path","../utils/path","node:path","node:fs",
        "node:url","node:os","node:crypto","./utils","../utils",
    }
    for line in lines:
        line = normalize_line(line)
        sigs.update(extract_function_calls(line))
        for _, s in re.findall(r'(["\'])(.*?)\1', line):
            if (len(s) > 8 and not s.isdigit() and s not in _SKIP_STRINGS
                    and '|' not in s and not s.startswith('.')
                    and not re.match(r'^[a-z][a-z0-9-]+$', s)):
                sigs.add(f'"{s}"')
        if ('&&' in line or '||' in line) and len(line.strip()) > 10:
            sigs.add(line.strip())
        for m in re.findall(r'(?:require|import)\s*\(?\s*[\'"]([^\'"]+)[\'"]', line):
            sigs.add(f"module:{m}")
    return list(sigs)


def extract_go_rust_signatures(lines):
    sigs = set()
    for line in lines:
        line = normalize_line(line)
        sigs.update(extract_function_calls(line))
        for t in re.findall(r'\b[A-Z][a-zA-Z0-9]*\b', line):
            if len(t) > 2 and t not in PRESERVE_TOKENS:
                sigs.add(t)
        sigs.update(extract_comparisons(line))
        sigs.update(extract_control_flow(line))
    return list(sigs)


def extract_c_cpp_inline_signatures(lines):
    sigs = set()
    for line in lines:
        line = normalize_line(line)
        if 'template<' in line:
            sigs.add('template<')
        for c in re.findall(r'\b(static|dynamic|const|reinterpret)_cast<', line):
            sigs.add(f"{c}_cast<")
        sigs.update(extract_comparisons(line))
    return list(sigs)


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def extract_signatures_from_lines(lines, patch_type='generic'):
    sigs = set()

    if patch_type.startswith('js_'):
        sigs.update(extract_js_signatures(lines))
    elif patch_type.startswith('go_') or patch_type.startswith('rust_'):
        sigs.update(extract_go_rust_signatures(lines))
    elif patch_type == 'c_cpp_inline':
        sigs.update(extract_c_cpp_inline_signatures(lines))
    else:
        for line in lines:
            if _is_comment_line(line): continue
            line = normalize_line(line)
            if not line or _looks_like_prose(line): continue
            sigs.update(extract_comparisons(line))
            sigs.update(extract_function_calls(line))
            sigs.update(extract_macros(line))
            sigs.update(extract_control_flow(line))
            sigs.update(extract_loop_condition(line))

    # CPVDetector context pairs (all patch types)
    sigs.update(extract_context_pairs(lines))

    # Block/body signatures (generic patches: zlib-style math, etc.)
    if patch_type == 'generic':
        sigs.update(extract_full_vulnerable_block(lines))
        sigs.update(extract_function_body(lines))
        # ReDeBug 4-gram fallback — catches math patches where structured
        # extractors produce only comments or overly-generic tokens
        sigs.update(extract_ngram_signatures(lines, n=4))

    return list(sigs)


def _derive_vulnerable_from_context(context_lines, fix_lines):
    """
    When a patch has no removed lines (pure addition), derive vulnerable
    patterns from the surrounding unchanged context.
    MOVERY insight: the context lines form the vulnerable function body
    that existed before the guard was added.
    """
    fix_set = {normalize_line(l) for l in fix_lines if l}
    derived = []
    for line in context_lines:
        nl = normalize_line(line)
        if not nl or _is_comment_line(nl) or _looks_like_prose(nl):
            continue
        if nl in fix_set:
            continue
        if not _line_is_meaningful(nl):
            continue
        derived.append(nl)
    return list(dict.fromkeys(derived))


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------

def extract_signatures_from_patch(patch_file):
    parsed = parse_patch(patch_file)
    vulnerable_lines = parsed["vulnerable_lines"]
    fix_lines        = parsed["fix_lines"]
    context_lines    = parsed.get("context_lines", [])
    patch_type       = parsed["patch_type"]

    fix_set = set(fix_lines)
    truly_vulnerable = [l for l in vulnerable_lines if l not in fix_set]

    # MOVERY CVL: if we have vulnerable lines, use CVL ordering
    if truly_vulnerable:
        truly_vulnerable = extract_core_vulnerable_lines(truly_vulnerable, fix_lines)

    # Fallback: derive from context (e.g. patch only adds a guard)
    if not truly_vulnerable:
        truly_vulnerable = _derive_vulnerable_from_context(context_lines, fix_lines)

    return {
        "vulnerable":      extract_signatures_from_lines(truly_vulnerable, patch_type),
        "fix":             extract_signatures_from_lines(fix_lines, patch_type),
        "patch_type":      patch_type,
        "vulnerable_lines": truly_vulnerable,
        "fix_lines":       fix_lines,
        "context_lines":   context_lines,
    }
