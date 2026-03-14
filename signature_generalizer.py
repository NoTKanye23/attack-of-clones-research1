import re
from clone_detector import PRESERVE_TOKENS



# Token rules


MACRO_PATTERN = re.compile(r'[A-Z][A-Z0-9_]{3,}')
IDENTIFIER_PATTERN = re.compile(r'[a-zA-Z_][a-zA-Z0-9_]*')


def _generalize_tokens(sig):

    def replace(match):

        word = match.group(0)

        # Preserve important APIs
        if word in PRESERVE_TOKENS:
            return word

        # Preserve macros
        if MACRO_PATTERN.fullmatch(word):
            return word

        # Preserve common keywords
        if word in {"if", "for", "while", "return"}:
            return word

        return "VAR"

    return IDENTIFIER_PATTERN.sub(replace, sig)



# Main generalization


def generalize_signature(sig, patch_type='generic'):

    # Context pairs handled separately
    if " | " in sig:

        left, right = sig.split(" | ", 1)

        left = generalize_signature(left, patch_type)
        right = generalize_signature(right, patch_type)

        return f"{left} | {right}"

    
    # Language specific handling
    

    if patch_type.startswith("js_"):

        sig = _generalize_tokens(sig)

        sig = re.sub(r'\b\d+\b', "NUM", sig)

        sig = sig.replace("..", "PATH_TRAVERSAL")

        return sig

    elif patch_type.startswith("go_") or patch_type.startswith("rust_"):

        def replace(match):

            word = match.group(0)

            if word in PRESERVE_TOKENS:
                return word

            if word[0].isupper():  # CamelCase type
                return word

            return "VAR"

        sig = IDENTIFIER_PATTERN.sub(replace, sig)

        sig = re.sub(r'\b\d+\b', "NUM", sig)

        return sig

    elif patch_type == "c_cpp_inline":

        sig = _generalize_tokens(sig)

        sig = re.sub(r'\b\d+\b', "NUM", sig)

        return sig

    
    # Default case
    

    sig = _generalize_tokens(sig)

    # Normalize numbers
    sig = re.sub(r'\b\d+\b', "NUM", sig)

    # Normalize comparisons
    sig = sig.replace("!==", "NEQ")
    sig = sig.replace("===", "EQ")

    # Normalize path traversal
    sig = sig.replace("..", "PATH_TRAVERSAL")

    return sig



# Batch generalization


def generalize_signatures(signatures, patch_type='generic'):

    generalized = {
        generalize_signature(sig, patch_type)
        for sig in signatures
    }

    return list(generalized)

