import sys
import re

def extract_added_lines(patch_file):
    signatures = []

    with open(patch_file, "r", errors="ignore") as f:
        for line in f:
            if line.startswith("+") and not line.startswith("+++"):
                code = line[1:].strip()

                if len(code) > 5:
                    signatures.append(code)

    return signatures


def generate_regex_patterns(signatures):
    patterns = []

    for s in signatures:
        s = re.escape(s)
        s = s.replace(r"\ ", r"\s+")
        patterns.append(s)

    return patterns


def main():

    if len(sys.argv) < 2:
        print("Usage: python clone_detector.py patch.patch")
        return

    patch = sys.argv[1]

    signatures = extract_added_lines(patch)
    patterns = generate_regex_patterns(signatures)

    print("\nExtracted Signatures:\n")

    for p in patterns:
        print(p)


if __name__ == "__main__":
    main()
