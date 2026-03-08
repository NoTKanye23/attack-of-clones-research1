import sys

from clone_detector import extract_signatures_from_patch
from signature_ranker import rank_signatures
from signature_filter import filter_signatures
from signature_generalizer import generalize_signatures
from clone_similarity import rank_candidates
from codesearch_query import search_codesearch


def main():

    if len(sys.argv) < 2:
        print("Usage: python attack_of_clones.py patch.patch")
        return

    patch = sys.argv[1]

    print("\n=== Extracting signatures ===\n")

    signatures = extract_signatures_from_patch(patch)

    print("\n=== Raw Signatures ===\n")
    print(len(signatures), "signatures extracted")

    signatures = filter_signatures(signatures)

    print("\n=== After Noise Filtering ===\n")
    print(len(signatures), "signatures remaining")

    generalized = generalize_signatures(signatures)

    print("\n=== Generalized Signatures ===\n")

    for s in generalized:
        print(s)

    ranked = rank_signatures(generalized)

    print("\n=== Ranked Signatures ===\n")

    for sig, score in ranked:
        print(f"{sig} -> score {score:.2f}")

    print("\n=== Searching top signatures ===\n")

    top = ranked[:5]

    for sig, score in top:

        print(f"\nSignature: {sig}")

        results = search_codesearch(sig)

        if not results:
            continue

        ranked_candidates = rank_candidates(sig, results)

        print("\nTop Similar Candidates:\n")

        for r, s in ranked_candidates[:5]:
            print(s, r)


if __name__ == "__main__":
    main()
