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
    print(f"\
{'='*50}")
    print(f"  {title}")
    print(f"{'='*50}\
")


def main():

    if len(sys.argv) < 2:
        print("Usage: python attack_of_clones.py patch.patch")
        return

    patch = sys.argv[1]

    # Derive a source package hint from the patch filename.
    # Used to exclude the patched package itself from clone results.
    # Git commit hashes (e.g. c60770d7.patch) give no hint → pass None.
    import re as _re, os as _os
    _stem = _os.path.splitext(_os.path.basename(patch))[0]
    if _re.match(r'^[0-9a-f]{7,40}$', _stem):
        patch_pkg_hint = None
    else:
        patch_pkg_hint = _stem.split('_')[0].lower() or None

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
        print("\
No vulnerable signatures found. Falling back to fix signatures.")
        vulnerable_sigs = fix_sigs

    if not vulnerable_sigs:
        print("No signatures found. Exiting.")
        return

    #  Step 2: Filter noise 
    print_section("Step 2: Noise Filtering")

    filtered = filter_signatures(vulnerable_sigs)
    print(f"{len(filtered)} signatures remaining after filtering")

    if not filtered:
        print("All signatures filtered out.")
        return

    #  Step 3: Rank signatures 
    print_section("Step 3: Ranking Signatures")

    ranked = rank_signatures(filtered)
    for sig, score in ranked[:10]:
        print(f"  [{score:5.2f}]  {sig}")

    # Step 4: Search archive 
    print_section("Step 4: Searching Debian Archive")

    # Search top 5 vulnerable signatures + up to 3 fix sigs as fallback
    # Only search signatures with meaningful specificity score.
    # Negative or near-zero scores indicate generic/noisy tokens.
    search_pool = [sig for sig, score in ranked[:8] if score > 2.0]
    # fix_sigs are used only for verification, not as search queries.
    # Searching them would find already-patched code, not clones.

    searched = set()
    all_results = {}
    confirmed_clones = []

    for sig in search_pool:

        if sig in searched:
            continue
        searched.add(sig)

        print(f"\
Signature: {sig}")

        results = search_codesearch(sig, patch_type=patch_type, source_package=patch_pkg_hint)

        if not results:
            continue

        all_results[sig] = results
        gen_sig = generalize_signature(sig, patch_type=patch_type)
        ranked_candidates = rank_candidates(gen_sig, results, fix_sigs)

        print("\
  Top Candidates:")

        for result, sim_score in ranked_candidates[:5]:

            package = result.get("package", "unknown")
            path = result.get("path", "")
            context = result.get("context", "").strip()

            print(f"    [{sim_score:.3f}]  {package} \u2014 {path}")
            print(f"            {context}")

            # Context-based verification (no fetch needed) 
            if verify_from_context(result, sig, fix_sigs, patch_type=patch_type):
                print(f"\
  \u26a0  Context-level clone detected!")
                print(f"     Package : {package}")
                print(f"     File    : {path}")
                confirmed_clones.append({
                    "package": package,
                    "path": path,
                    "matched_sig": sig,
                    "verification": "context"
                })
                continue

            #  Full file verification (fetch if available) 
            code = fetch_source_file(result)
            if code and is_vulnerable_clone(code, sig, fix_sigs, patch_type=patch_type, result_path=path):
                print(f"\
  \u26a0  Full-file clone detected!")
                print(f"     Package : {package}")
                print(f"     File    : {path}")
                confirmed_clones.append({
                    "package": package,
                    "path": path,
                    "matched_sig": sig,
                    "verification": "full_file"
                })

    #  Step 5: Summary 
    print_section("Step 5: Summary")

    total_candidates = sum(len(v) for v in all_results.values())
    print(f"Patch type            : {patch_type}")
    print(f"Signatures searched   : {len(all_results)}")
    print(f"Total candidates found: {total_candidates}")
    print(f"Confirmed clones      : {len(confirmed_clones)}")

    if confirmed_clones:
        print("\
Confirmed vulnerable clones:")
        for c in confirmed_clones:
            print(f"  [{c['verification']}]  {c['package']} \u2014 {c['path']}")
            print(f"    Matched: {c['matched_sig']}")

    if not confirmed_clones:
        print("\
No confirmed clones found for this patch.")
        print("This may indicate the vulnerability is relatively unique,")
        print("or that the signatures need further refinement.")

    if fix_sigs:
        print(f"\
Fix pattern ({len(fix_sigs)} signatures) was used to")
        print("exclude already-patched candidates from results.")


if __name__ == "__main__":
    main()
