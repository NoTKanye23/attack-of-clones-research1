import re

def score_signature(sig):
    score = 0

    # longer signatures are usually more meaningful
    score += len(sig) / 10

    # control-flow patterns are important
    if "if (" in sig or "for (" in sig or "while (" in sig:
        score += 5

    # macros/constants
    if re.match(r'^[A-Z_]{4,}$', sig):
        score += 3

    # ignore very short tokens
    if len(sig) < 4:
        score -= 2

    return score


def rank_signatures(signatures):
    scored = []

    for sig in signatures:
        score = score_signature(sig)
        scored.append((sig, score))

    scored.sort(key=lambda x: x[1], reverse=True)

    return scored
