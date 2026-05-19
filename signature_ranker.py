import re

SECURITY_APIS = {
    "malloc", "free", "realloc", "memcpy", "memset",
    "strcpy", "strcat", "sprintf", "gets", "NULL", "nullptr",
}

_PROSE = {
    "must be", "should be", "non-negative", "non negative",
    "calculated for each", "concatenated", "requiring only",
    "were calculated", "used with",
}


def score_signature(sig):
    try:
        if not sig or not isinstance(sig, str):
            return 0.0
        score = 0.0

        # CPVDetector: context pairs are the highest-value signal
        if " | " in sig:
            score += 6.0

        # Length bonus (MVP: longer signatures are more specific)
        score += min(len(sig) / 10.0, 5.0)

        # Control flow
        if re.search(r'\b(if|for|while)\s*\(', sig):
            score += 5.0

        # Comparisons
        if re.search(r'(==|!=|<=|>=)', sig):
            score += 4.0
        elif re.search(r'\s[<>]\s', sig):
            score += 2.0

        # Security APIs
        if any(api in sig for api in SECURITY_APIS):
            score += 3.0

        # Standalone function call
        if re.match(r'[a-zA-Z_][a-zA-Z0-9_]*\($', sig):
            score += 2.0

        # Uppercase macro (strong anchor)
        if re.match(r'^[A-Z_]{4,}$', sig):
            score += 4.0

        # Return statement
        if re.search(r'\breturn\b', sig):
            score += 1.5

        # Arithmetic operator (helps with math patches like zlib crc32)
        if re.search(r'[+\-*/%&|^]', sig):
            score += 1.0

        # ReDeBug n-gram bonus: space-separated sequence with specific tokens
        if " " in sig and " | " not in sig:
            parts = sig.split()
            if any(p not in {"VAR","NUM","VARIABLE","STRING"} and len(p) > 4
                   for p in parts):
                score += 2.0

        # Prose penalty: comment-derived line with no code structure
        has_prose = any(p in sig.lower() for p in _PROSE)
        has_code  = bool(re.search(r'[=(){};<>]', sig))
        if has_prose and not has_code:
            score -= 5.0

        # Single repeated token penalty
        tokens = sig.split()
        if len(set(tokens)) <= 1:
            score -= 3.0

        # Very short penalty
        if len(sig) < 4:
            score -= 4.0

        return round(float(score), 2)
    except Exception:
        return 0.0


def rank_signatures(signatures):
    scored = [(sig, score_signature(sig) or 0.0) for sig in signatures]
    scored.sort(key=lambda x: x[1], reverse=True)
    return scored
