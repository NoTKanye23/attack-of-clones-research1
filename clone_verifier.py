import re



# Normalization helpers


def _normalize(text):

    text = re.sub(r'\s+', ' ', text)
    text = re.sub(r'\s*([(){};,+\-*/<>=!])\s*', r'\1', text)

    return text.strip()


def _tokenize(text):

    tokens = re.findall(r'[A-Za-z_][A-Za-z0-9_]*', text)

    return set(t for t in tokens if len(t) > 1)



# Vulnerable pattern detection


def contains_vulnerable_pattern(code, vuln_sig):

    code_norm = _normalize(code)
    sig_norm = _normalize(vuln_sig)

    # Handle context pairs
    if " | " in vuln_sig:

        left, right = vuln_sig.split(" | ", 1)

        if _normalize(left) in code_norm and _normalize(right) in code_norm:
            return True

    # Exact match
    if sig_norm in code_norm:
        return True

    # Token overlap fallback
    sig_tokens = _tokenize(vuln_sig)
    code_tokens = _tokenize(code)

    if not sig_tokens:
        return False

    overlap = sig_tokens & code_tokens

    return len(overlap) / len(sig_tokens) >= 0.7



# Fix pattern detection


def contains_fix_pattern(code, fix_signatures):

    code_norm = _normalize(code)

    for fix in fix_signatures:

        fix_norm = _normalize(fix)

        if fix_norm in code_norm:
            return True

        # token overlap fallback
        fix_tokens = _tokenize(fix)
        code_tokens = _tokenize(code)

        if not fix_tokens:
            continue

        overlap = fix_tokens & code_tokens

        if len(overlap) / len(fix_tokens) >= 0.8:
            return True

    return False



# Context verification


def verify_from_context(result, vuln_sig, fix_sigs):

    context_lines = (
        result.get("context_before", []) +
        [result.get("context", "")] +
        result.get("context_after", [])
    )

    code_block = "\n".join(context_lines)

    if not contains_vulnerable_pattern(code_block, vuln_sig):
        return False

    if contains_fix_pattern(code_block, fix_sigs):
        return False

    return True



# Full-file verification


def is_vulnerable_clone(code, vuln_sig, fix_sigs):

    if not contains_vulnerable_pattern(code, vuln_sig):
        return False

    if contains_fix_pattern(code, fix_sigs):
        return False

    return True

