import re

_LANG_EXTENSIONS = {
    "js_bundling":       {".js", ".mjs", ".cjs", ".ts", ".tsx"},
    "js_generic":        {".js", ".mjs", ".cjs", ".ts", ".tsx"},
    "go_static":         {".go"},
    "rust_static":       {".rs"},
    "c_cpp":             {".c", ".h", ".cpp", ".hpp", ".cc", ".cxx"},
    "c_cpp_inline":      {".c", ".h", ".cpp", ".hpp", ".cc", ".cxx"},
    "null_deref":        {".c", ".h", ".cpp", ".hpp", ".cc", ".cxx",
                          ".go", ".rs", ".py"},
    "bounds_check":      {".c", ".h", ".cpp", ".hpp", ".cc", ".cxx"},
    "memory_management": {".c", ".h", ".cpp", ".hpp", ".cc", ".cxx"},
    "buffer_overflow":   {".c", ".h", ".cpp", ".hpp", ".cc", ".cxx"},
    "path_traversal":    {".c", ".h", ".cpp", ".hpp", ".py",
                          ".go", ".rs", ".js", ".ts"},
    "generic":           None,   # accept any extension
}

_VERIFIER_SKIP = {
    "if","for","while","return","else","switch","case","break",
    "int","void","char","bool","auto","static","const","unsigned",
    "signed","long","short","struct","enum","typedef","extern",
}


def _file_extension(path: str) -> str:
    return ("." + path.rsplit(".", 1)[1].lower()) if "." in path else ""


def _language_matches(result_path: str, patch_type: str) -> bool:
    """Language cross-check (pre-filter, applied before MVP C1)."""
    allowed = _LANG_EXTENSIONS.get(patch_type)
    if allowed is None:
        return True
    return _file_extension(result_path) in allowed


def _normalize(text: str) -> str:
    return " ".join(text.split())


def _tokenize(text: str) -> set:
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text)
    return {t for t in tokens if len(t) > 1 and t not in _VERIFIER_SKIP}


def _abstract_for_verify(text: str) -> str:
    """
    MVP §3.2.2 abstraction applied to candidate code before token comparison.
    Mirrors abstract_line() in clone_detector but self-contained.
    """
    text = re.sub(r'"[^"]*"', 'STRING', text)
    text = re.sub(r"'[^']*'", 'STRING', text)
    text = re.sub(r'\b\d+\b', 'NUM', text)
    _KW = {"if","for","while","return","else","int","void","char","static","const"}
    def _r(m):
        w = m.group(0)
        if w in _KW:                      return w
        if re.match(r'^[A-Z_]{3,}$', w): return w
        if w[0].islower():                return "VARIABLE"
        return w
    return re.sub(r'\b[A-Za-z_][A-Za-z0-9_]*\b', _r, text)


def _mvp_c1_check(vuln_sig: str, candidate_text: str) -> bool:
    """
    MVP §3.3 C1 prerequisite:
    Every meaningful token from the vulnerability signature must appear
    somewhere in the candidate text.  This is a hard gate — if any token
    is missing, we skip the fuzzy match entirely.
    Tokens shorter than 4 chars or in the skip-list are not required
    (they are too common to be discriminating).
    """
    sig_tokens = {
        t for t in _tokenize(vuln_sig)
        if len(t) >= 4
    }
    if not sig_tokens:
        return True   # no meaningful tokens to check → pass
    cand_tokens = _tokenize(candidate_text)
    # C1: all sig tokens must be present
    return sig_tokens.issubset(cand_tokens)


def contains_vulnerable_pattern(code: str, vuln_sig: str) -> bool:
    """
    Two-stage matching:
    Stage 1 - MVP C1: token prerequisite check.
    Stage 2 - fuzzy: normalized exact match, then token overlap on abstracted text.
    """
    # C1 fast gate
    if not _mvp_c1_check(vuln_sig, code):
        return False

    # Exact match (raw)
    if _normalize(vuln_sig) in _normalize(code):
        return True

    # Abstracted token overlap (MVP C2 / MOVERY normalized comparison)
    abs_sig  = _abstract_for_verify(vuln_sig)
    abs_code = _abstract_for_verify(code)
    sig_tokens  = _tokenize(abs_sig)
    code_tokens = _tokenize(abs_code)
    if not sig_tokens:
        return False
    overlap = len(sig_tokens & code_tokens) / len(sig_tokens)
    # Lower threshold for longer signatures (function bodies)
    threshold = 0.6 if len(vuln_sig) > 100 else 0.8
    return overlap >= threshold


def contains_fix_pattern(code: str, fix_signatures: list) -> bool:
    norm_code = _normalize(code)
    for fix in fix_signatures:
        if _normalize(fix) in norm_code:
            return True
    return False


def verify_from_context(result: dict, vuln_sig: str, fix_sigs: list,
                        patch_type: str = "generic") -> bool:
    path = result.get("path", "")
    # Pre-filter: language cross-check (before any token work)
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
    if result_path and not _language_matches(result_path, patch_type):
        return False
    if not contains_vulnerable_pattern(code, vuln_sig):
        return False
    if contains_fix_pattern(code, fix_sigs):
        return False
    return True
