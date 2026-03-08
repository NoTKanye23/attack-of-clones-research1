import re


def extract_signatures_from_patch(patch_file):
    """
    Extract potential vulnerability signatures from patch.
    """

    signatures = set()

    with open(patch_file, "r", errors="ignore") as f:
        for line in f:

            if not line.startswith("+") or line.startswith("+++"):
                continue

            code = line[1:].strip()

            if not code:
                continue

            # extract macros / constants
            macros = re.findall(r'\b[A-Z_]{4,}\b', code)
            signatures.update(macros)

            # control flow conditions
            if re.search(r'\b(if|for|while)\s*\(', code):
                signatures.add(code)

            # function calls
            func_calls = re.findall(r'\b[A-Za-z_][A-Za-z0-9_]*\s*\(', code)
            for fc in func_calls:
                signatures.add(fc.strip())

            # boundary checks
            if re.search(r'[<>]=?', code):
                signatures.add(code)

    return list(signatures)
