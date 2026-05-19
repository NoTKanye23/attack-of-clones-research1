import re
from clone_detector import PRESERVE_TOKENS


MACRO_PATTERN = re.compile(r'[A-Z][A-Z0-9_]{3,}')
IDENTIFIER_PATTERN = re.compile(r'[a-zA-Z_][a-zA-Z0-9_]*')


def _generalize_tokens(sig):

    def replace(match):
        word = match.group(0)

        if word in PRESERVE_TOKENS:
            return word

        if MACRO_PATTERN.fullmatch(word):
            return word

        if word in {"if", "for", "while", "return"}:
            return word

        return "VAR"

    return IDENTIFIER_PATTERN.sub(replace, sig)


def generalize_signature(sig, patch_type='generic'):
    if " | " in sig:
        left, right = sig.split(" | ", 1)
        left = generalize_signature(left, patch_type)
        right = generalize_signature(right, patch_type)
        return f"{left} | {right}"

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

            if word[0].isupper():
                return word

            return "VAR"

        sig = IDENTIFIER_PATTERN.sub(replace, sig)
        sig = re.sub(r'\b\d+\b', "NUM", sig)
        return sig

    elif patch_type == "c_cpp_inline":
        sig = _generalize_tokens(sig)
        sig = re.sub(r'\b\d+\b', "NUM", sig)
        return sig

    sig = _generalize_tokens(sig)
    sig = re.sub(r'\b\d+\b', "NUM", sig)
    sig = sig.replace("!==", "NEQ")
    sig = sig.replace("===", "EQ")
    sig = sig.replace("..", "PATH_TRAVERSAL")
    return sig


def generalize_signatures(signatures, patch_type='generic'):
    generalized = {
        generalize_signature(sig, patch_type)
        for sig in signatures
    }
    return list(generalized)
