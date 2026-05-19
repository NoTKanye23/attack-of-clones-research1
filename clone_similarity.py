import re

def tokenize(text):
    tokens = re.findall(r'[A-Za-z_][A-Za-z0-9_]*', text)
    return set(t for t in tokens if len(t) > 1)


def extract_macros(tokens):
    return {t for t in tokens if re.match(r'[A-Z][A-Z0-9_]{3,}', t)}


def extract_function_calls(text):
    return set(re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', text))


def weighted_similarity(sig_tokens, cand_tokens, sig_text, cand_text):
    if not sig_tokens or not cand_tokens:
        return 0.0
    intersection = sig_tokens & cand_tokens
    union = sig_tokens | cand_tokens
    base_score = len(intersection) / len(union)
    score = base_score
    if extract_macros(sig_tokens) & extract_macros(cand_tokens):
        score += 0.2
    if extract_function_calls(sig_text) & extract_function_calls(cand_text):
        score += 0.15
    if "|" in sig_text:
        score += 0.1
    if len(sig_text) > 40:
        score += 0.05
    return round(min(score, 1.0), 3)


def similarity_score(signature, result):
    sig_tokens = tokenize(signature)
    if isinstance(result, dict):
        context_lines = (
            result.get("context_before", [])
            + [result.get("context", "")]
            + result.get("context_after", [])
        )
        candidate_text = " ".join(context_lines)
    else:
        candidate_text = result
    cand_tokens = tokenize(candidate_text)
    return weighted_similarity(sig_tokens, cand_tokens, signature, candidate_text)


def rank_candidates(signature, results, fix_signatures=None):
    ranked = [
        (r, similarity_score(signature, r))
        for r in results
    ]
    ranked.sort(key=lambda x: x[1], reverse=True)
    return ranked  # FIX: was typo `rankeds`
