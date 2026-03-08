import re

def tokenize(code):
    """
    Break code into tokens
    """
    tokens = re.findall(r"[A-Za-z_]+", code)
    return set(tokens)


def similarity_score(sig, candidate):
    """
    Compute similarity score between signature and candidate code
    """

    sig_tokens = tokenize(sig)
    cand_tokens = tokenize(candidate)

    if not sig_tokens or not cand_tokens:
        return 0.0

    intersection = sig_tokens.intersection(cand_tokens)
    union = sig_tokens.union(cand_tokens)

    score = len(intersection) / len(union)

    return round(score, 3)


def rank_candidates(signature, results):

    ranked = []

    for r in results:
        score = similarity_score(signature, r)
        ranked.append((r, score))

    ranked.sort(key=lambda x: x[1], reverse=True)

    return ranked
