import subprocess
import sys
from signature_ranker import rank_signatures


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


def search_signature(sig):
    result = subprocess.run(
        ["python3", "codesearch_query.py", sig],
        capture_output=True,
        text=True
    )

    print("\nSearching Debian archive...\n")
    print(result.stdout)


def main():

    if len(sys.argv) < 2:
        print("Usage: python attack_of_clones.py patch.patch")
        return

    patch = sys.argv[1]

    print("\n=== Extracting signatures ===\n")

    signatures = extract_signature(patch)

    # rank signatures
    ranked = rank_signatures(signatures)

    print("\n=== Ranked Signatures ===\n")

    for sig, score in ranked:
        print(f"{sig}  -> score {score:.2f}")

    # search only top 5 signatures
    print("\n=== Searching top signatures ===\n")

    top = [sig for sig, score in ranked[:5]]

    for sig in top:
        print(f"\nSignature: {sig}")
        search_signature(sig)


if __name__ == "__main__":
    main()
