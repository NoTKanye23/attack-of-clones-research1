import sys
import re

if len(sys.argv) != 2:
    print("Usage: python3 extract_signature.py <patchfile>")
    sys.exit(1)

patch_file = sys.argv[1]

with open(patch_file, "r", errors="ignore") as f:
    for line in f:
        # only consider added lines in patch
        if line.startswith("+") and not line.startswith("+++"):
            code = line[1:].strip()

            # ignore comments or empty lines
            if not code or code.startswith("//") or code.startswith("#"):
                continue

            # basic filter for code-like patterns
            if re.search(r"\w+\(", code) or "if" in code or "=" in code:
                print(code)
