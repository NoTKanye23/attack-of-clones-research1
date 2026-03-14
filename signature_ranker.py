import re


SECURITY_APIS = {
    "malloc", "free", "realloc", "memcpy", "memset",
    "strcpy", "strcat", "sprintf", "gets", "NULL", "nullptr"
}


def score_signature(sig):

    score = 0.0

    
    # Context pairs (highest value)
    
    if " | " in sig:
        score += 6.0

    
    # Length bonus
    
    score += min(len(sig) / 10, 5.0)

    
    # Control-flow checks
    
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

    
    # Function calls
    
    if re.match(r'[a-zA-Z_][a-zA-Z0-9_]*\($', sig):
        score += 2.0

    
    # Uppercase macros (excellent anchors)
    
    if re.match(r'^[A-Z_]{4,}$', sig):
        score += 4.0

    
    # Token diversity
    
    tokens = sig.split()

    if len(set(tokens)) <= 1:
        score -= 3.0

    
    # Short signatures penalty
    
    if len(sig) < 4:
        score -= 4.0

    return round(score, 2)


def rank_signatures(signatures):

    scored = [(sig, score_signature(sig)) for sig in signatures]

    scored.sort(key=lambda x: x[1], reverse=True)

    return scored

