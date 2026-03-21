import sys

from clone_detector import extract_signatures_from_patch
from signature_filter import filter_signatures
from signature_ranker import rank_signatures
from signature_generalizer import generalize_signature
from clone_similarity import rank_candidates
from codesearch_query import search_codesearch, search_by_filename
from file_fetcher import fetch_source_file
from clone_verifier import verify_from_context, is_vulnerable_clone
from vendoring_search import extract_vendoring_signals


def print_section(title):
    print(f"\n{'='*50}")
    print(f"  {title}")
    print(f"{'='*50}\n")


def main():
    if len(sys.argv) < 2:
        print("Usage: python attack_of_clones.py patch.patch")
        return

    patch = sys.argv[1]

    # Derive a source package hint from the patch filename.
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
        print("\nNo vulnerable signatures found. Falling back to fix signatures.")
        vulnerable_sigs = fix_sigs
    if not vulnerable_sigs:
        print("No signatures found. Exiting.")
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
        print(f"  [{score:5.2f}]  {sig}")

    # Step 4: Search archive
    print_section("Step 4: Searching Debian Archive")
    search_pool = [sig for sig, score in ranked[:8] if score > 2.0]

    searched = set()
    all_results = {}
    confirmed_clones = []

    for sig in search_pool:
        if sig in searched:
            continue
        searched.add(sig)
        print(f"\nSignature: {sig}")

        results = search_codesearch(sig, patch_type=patch_type, source_package=patch_pkg_hint)
        if not results:
            continue

        all_results[sig] = results
        gen_sig = generalize_signature(sig, patch_type=patch_type)
        ranked_candidates = rank_candidates(gen_sig, results, fix_sigs)

        print("\n  Top Candidates:")
        for result, sim_score in ranked_candidates[:5]:
            package = result.get("package", "unknown")
            path = result.get("path", "")
            context = result.get("context", "").strip()
            print(f"    [{sim_score:.3f}]  {package} — {path}")
            print(f"            {context}")

            if verify_from_context(result, sig, fix_sigs, patch_type=patch_type):
                print(f"\n  ⚠  Context-level clone detected!")
                print(f"     Package : {package}")
                print(f"     File    : {path}")
                confirmed_clones.append({
                    "package": package,
                    "path": path,
                    "matched_sig": sig,
                    "verification": "context"
                })
                continue

            code = fetch_source_file(result)
            if code and is_vulnerable_clone(code, sig, fix_sigs, patch_type=patch_type, result_path=path):
                print(f"\n  ⚠  Full-file clone detected!")
                print(f"     Package : {package}")
                print(f"     File    : {path}")
                confirmed_clones.append({
                    "package": package,
                    "path": path,
                    "matched_sig": sig,
                    "verification": "full_file"
                })

    # Step 5: Summary
    print_section("Step 5: Summary")
    total_candidates = sum(len(v) for v in all_results.values())
    print(f"Patch type            : {patch_type}")
    print(f"Signatures searched   : {len(all_results)}")
    print(f"Total candidates found: {total_candidates}")
    print(f"Confirmed clones      : {len(confirmed_clones)}")

    if confirmed_clones:
        print("\nConfirmed vulnerable clones:")
        for c in confirmed_clones:
            print(f"  [{c['verification']}]  {c['package']} — {c['path']}")
            print(f"    Matched: {c['matched_sig']}")

    if not confirmed_clones:
        print("\nNo confirmed clones found for this patch.")
        print("This may indicate the vulnerability is relatively unique,")
        print("or that the signatures need further refinement.")

    if fix_sigs:
        print(f"\nFix pattern ({len(fix_sigs)} signatures) was used to")
        print("exclude already-patched candidates from results.")

    # Step 6: filename-based vendoring search
    run_vendoring_search(patch, patch_type, vulnerable_sigs, fix_sigs, confirmed_clones)

    if confirmed_clones:
        print(f"\nTotal confirmed clones (all methods): {len(confirmed_clones)}")


def run_vendoring_search(patch, patch_type, vulnerable_sigs, fix_sigs, confirmed_clones):
    """
    Search for vendored copies using filename signals.
    Uses the top vulnerable signature (if available) for verification.
    """
    print_section("Step 6: Vendoring / Filename Search")
    signals = extract_vendoring_signals(patch)

    if not signals:
        print("  No distinctive filenames found in patch paths.")
        return

    print(f"  {len(signals)} filename signal(s):")
    for s in signals:
        lib = f" (library: {s['library']})" if s['library'] else ""
        print(f"    [{s['confidence']:6s}]  {s['query']}{lib}")

    # Choose the best vulnerable signature for verification (e.g., the first one)
    vuln_pattern = vulnerable_sigs[0] if vulnerable_sigs else None

    for s in signals:
        q = s["query"]
        print(f"\nFilename: {q}")
        results = search_by_filename(q)
        if not results:
            continue

        # Optionally filter results to actual source files (not build files)
        source_extensions = {'.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.go', '.rs', '.py', '.js', '.ts'}
        filtered_results = []
        for r in results:
            path = r.get("path", "")
            if any(path.endswith(ext) for ext in source_extensions):
                filtered_results.append(r)

        print(f"  {len(filtered_results)} source file(s) containing '{q}' (out of {len(results)} total)")
        for result in filtered_results[:8]:  # limit to top 8 for readability
            pkg = result.get("package", "unknown")
            path = result.get("path", "")
            print(f"    {pkg}  --  {path}")

            if vuln_pattern and verify_from_context(result, vuln_pattern, fix_sigs, patch_type=patch_type):
                print(f"  ⚠  Vendoring clone confirmed (vulnerable pattern present)!")
                confirmed_clones.append({
                    "package": pkg,
                    "path": path,
                    "matched_sig": f"[filename] {q}",
                    "verification": "vendoring+context"
                })
            # If you also want to try full-file verification for vendoring, you could add that here


if __name__ == "__main__":
    main()
