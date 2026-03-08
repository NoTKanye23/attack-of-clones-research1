import re
import sys

def extract_added_lines(patch_file):
    signatures = []

    with open(patch_file, "r", errors="ignore") as f:
        for line in f:
            if line.startswith("+") and not line.startswith("+++"):
                code = line[1:].strip()

                # extract uppercase tokens (macros, constants)
                tokens = re.findall(r'[A-Z_]{4,}', code)
                signatures.extend(tokens)

                # also keep control-flow patterns
                if "for (" in code or "if (" in code:
                    signatures.append(code)

    return list(set(signatures))


def main():
    if len(sys.argv) < 2:
        print("Usage: python clone_detector.py patch.patch")
        return

    patch = sys.argv[1]
    signatures = extract_added_lines(patch)

    print("\nExtracted Signatures:\n")

    for s in signatures:
        print(s)


if __name__ == "__main__":
    main()
