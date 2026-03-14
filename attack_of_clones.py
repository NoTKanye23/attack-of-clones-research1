import sys

from clone_detector import extract_signatures_from_patch
from signature_filter import filter_signatures
from signature_ranker import rank_signatures
from signature_generalizer import generalize_signature
from clone_similarity import rank_candidates
from codesearch_query import search_codesearch
from file_fetcher import fetch_source_file
from clone_verifier import verify_from_context, is_vulnerable_clone


def print_section(title):
    print("\n" + "=" * 50)
    print(f"  {title}")
    print("=" * 50 + "\n")


def main():

    if len(sys.argv) < 2:
        print("Usage: python attack_of_clones.py patch.patch")
        return

    patch = sys.argv[1]

    
    # Step 1: Extract signatures
    

    print_section("Step 1: Extracting Signatures")

    extracted = extract_signatures_from_patch(patch)

    vulnerable_sigs = extracted["vulnerable"]
    fix_sigs = extracted["fix"]
    patch_type = extracted["patch_type"]

    print(f"Patch type detected   : {patch_type}")
    print(f"Vulnerable signatures : {len(vulnerable_sigs)}")
    print(f"Fix signatures        : {len(fix_sigs)}")

    if not vulnerable_sigs:
        print("No vulnerable signatures found. Falling back to fix signatures.")
        vulnerable_sigs = fix_sigs

    if not vulnerable_sigs:
        print("No usable signatures. Exiting.")
        return

    
    # Step 2: Filter noise
    

    print_section("Step 2: Noise Filtering")

    filtered = filter_signatures(vulnerable_sigs)

    print(f"{len(filtered)} signatures remaining after filtering")

    if not filtered:
        print("All signatures filtered out.")
        return

    
    # Step 3: Rank signatures
    

    print_section("Step 3: Ranking Signatures")

    ranked = rank_signatures(filtered)

    for sig, score in ranked[:10]:
        print(f"[{score:5.2f}]  {sig}")

    
    # Step 4: Search archive
    

    print_section("Step 4: Searching Debian Archive")

    search_pool = [sig for sig, _ in ranked[:5]]

    searched = set()
    seen_candidates = set()
    file_cache = {}

    confirmed_clones = []
    total_candidates = 0

    for sig in search_pool:

        if sig in searched:
            continue

        searched.add(sig)

        print(f"\nSignature: {sig}")

        results = search_codesearch(sig, patch_type=patch_type)

        if not results:
            continue

        total_candidates += len(results)

        gen_sig = generalize_signature(sig, patch_type=patch_type)

        ranked_candidates = rank_candidates(gen_sig, results, fix_sigs)

        print("\n  Top Candidates:")

        for result, sim_score in ranked_candidates[:5]:

            package = result.get("package", "unknown")
            path = result.get("path", "")
            context = result.get("context", "").strip()

            key = (package, path)

            if key in seen_candidates:
                continue

            seen_candidates.add(key)

            print(f"    [{sim_score:.3f}]  {package}/{path}")
            print(f"            {context}")

            
            # Context verification
            

            if verify_from_context(result, sig, fix_sigs):

                print("\n Context-level clone detected!")
                confirmed_clones.append({
                    "package": package,
                    "path": path,
                    "matched_sig": sig,
                    "verification": "context"
                })

                continue

            
            # Full file verification
            

            if key not in file_cache:
                file_cache[key] = fetch_source_file(result)

            code = file_cache[key]

            if code and is_vulnerable_clone(code, sig, fix_sigs):

                print("\n Full-file clone detected!")

                confirmed_clones.append({
                    "package": package,
                    "path": path,
                    "matched_sig": sig,
                    "verification": "full_file"
                })

    
    # Step 5: Summary
    

    print_section("Step 5: Summary")

    print(f"Patch type            : {patch_type}")
    print(f"Signatures searched   : {len(searched)}")
    print(f"Total candidates found: {total_candidates}")
    print(f"Confirmed clones      : {len(confirmed_clones)}")

    if confirmed_clones:

        print("\nConfirmed vulnerable clones:")

        for c in confirmed_clones:
            print(f"[{c['verification']}]  {c['package']}/{c['path']}")
            print(f"  Matched signature: {c['matched_sig']}")

    else:

        print("\nNo confirmed clones found.")
        print("The vulnerability may be unique or signatures may need refinement.")

    if fix_sigs:
        print(f"\nFix pattern ({len(fix_sigs)} signatures) was used to")
        print("exclude already-patched candidates.")


if __name__ == "__main__":
    main()

