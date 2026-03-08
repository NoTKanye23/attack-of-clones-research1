import re

def filter_signatures(signatures):

    filtered = []

    for sig in signatures:

        # remove very short tokens
        if len(sig) < 4:
            continue

        # remove single braces or punctuation
        if sig in ["}", "{", ";"]:
            continue

        # remove simple control statements
        if sig.strip() in ["if", "for", "while"]:
            continue

        # ignore extremely long lines (often code blocks)
        if len(sig) > 120:
            continue

        # keep useful tokens
        filtered.append(sig)

    return filtered
