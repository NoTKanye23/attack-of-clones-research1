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

GENERIC_MACROS = {
    "SIZE", "TYPE", "MODE", "DATA", "FLAG", "VALUE"
}


def is_noise_macro(text):
    """Filter generic uppercase macros."""
    return text in GENERIC_MACROS


def is_trivial(text):
    """Detect trivial tokens."""
    if text in {"{", "}", ";", "(", ")", ","}:
        return True
    if len(text) < 2:
        return True
    return False


def filter_signatures(signatures):
    """
    Remove noisy or trivial signatures.

    Keeps:
        - comparison expressions
        - function calls
        - domain macros
        - control flow conditions
        - context pairs
    """

    filtered = []
    seen = set()

    for sig in signatures:

        text = sig["signature"] if isinstance(sig, dict) else sig
        text = text.strip()

        if not text or text in seen:
            continue

        if is_trivial(text):
            continue

        if len(text) > 120:
            continue

        if text in C_KEYWORDS:
            continue

        if text in NOISE_TOKENS:
            continue

        # ─────────────────────────────
        # Context pairs (highest value)
        # ─────────────────────────────
        if " | " in text:
            filtered.append(text)
            seen.add(text)
            continue

        # ─────────────────────────────
        # Comparisons
        # ─────────────────────────────
        if re.search(r'(==|!=|<=|>=|<|>)', text):
            filtered.append(text)
            seen.add(text)
            continue

        # ─────────────────────────────
        # Function calls
        # ─────────────────────────────
        if re.search(r'[a-zA-Z_][a-zA-Z0-9_]*\s*\(', text):
            filtered.append(text)
            seen.add(text)
            continue

        # ─────────────────────────────
        # Control-flow conditions
        # ─────────────────────────────
        if re.search(r'\b(if|for|while)\s*\(', text):
            filtered.append(text)
            seen.add(text)
            continue

        # ─────────────────────────────
        # Uppercase macros
        # ─────────────────────────────
        if re.match(r'^[A-Z_]{4,}$', text):
            if not is_noise_macro(text):
                filtered.append(text)
                seen.add(text)
            continue

        # ─────────────────────────────
        # Token diversity check
        # ─────────────────────────────
        tokens = text.split()

        if len(set(tokens)) == 1:
            continue

        # Keep moderately long tokens
        if len(text) >= 5:
            filtered.append(text)
            seen.add(text)

    return filtered

