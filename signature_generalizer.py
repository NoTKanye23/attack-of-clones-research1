import re


def generalize_signature(sig):

    # replace variable names
    sig = re.sub(r'[a-zA-Z_][a-zA-Z0-9_]*', 'VAR', sig)

    # replace numbers
    sig = re.sub(r'\b\d+\b', 'NUM', sig)

    # detect length checks
    if "length" in sig:
        sig = sig.replace("length", "LENGTH_CHECK")

    # detect path traversal
    if ".." in sig:
        sig = sig.replace("..", "PATH_TRAVERSAL")

    # normalize operators
    sig = sig.replace("!==", "NEQ")
    sig = sig.replace("===", "EQ")

    return sig


def generalize_signatures(signatures):

    generalized = []

    for sig in signatures:
        generalized.append(generalize_signature(sig))

    return list(set(generalized))
