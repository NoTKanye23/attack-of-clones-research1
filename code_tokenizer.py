import re


C_KEYWORDS = {
    "if", "for", "while", "return", "else", "switch",
    "case", "break", "continue", "do", "sizeof"
}


def tokenize_code(code):
    """
    Extract meaningful tokens from code.

    Returns a set of normalized tokens used for
    similarity scoring and clone detection.
    """

    tokens = set()

    
    # identifiers
    

    identifiers = re.findall(r'[A-Za-z_][A-Za-z0-9_]*', code)

    for t in identifiers:

        if t in C_KEYWORDS:
            continue

        tokens.add(t)

    
    # macros (strong anchors)
    

    macros = re.findall(r'[A-Z][A-Z0-9_]{3,}', code)

    tokens.update(macros)

    
    # function calls
    

    calls = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', code)

    tokens.update(calls)

    
    # numeric constants
    

    if re.search(r'\b\d+\b', code):
        tokens.add("NUM")

    return tokens

