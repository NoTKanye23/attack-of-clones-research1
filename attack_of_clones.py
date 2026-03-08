import subprocess
import sys

def extract_signature(patch):
    result = subprocess.run(
        ["python3", "clone_detector.py", patch],
        capture_output=True,
        text=True
    )

    lines = result.stdout.split("\n")

    signatures = []

    for line in lines:
        if line.strip() and "Extracted" not in line:
            signatures.append(line.strip())

    return signatures


def search_archive(signature):
    subprocess.run(["python3", "codesearch_query.py", signature])


def main():

    if len(sys.argv) < 2:
        print("Usage: python attack_of_clones.py patch.patch")
        return

    patch = sys.argv[1]

    print("\n=== Extracting signatures ===\n")

    signatures = extract_signature(patch)

    for s in signatures:

        print("\nSignature:", s)

        print("\nSearching Debian archive...\n")

        search_archive(s)


if __name__ == "__main__":
    main()
