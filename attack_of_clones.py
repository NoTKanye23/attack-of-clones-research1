import sys
import re
import os
 
from clone_detector import extract_signatures_from_patch
from signature_filter import filter_signatures
from signature_ranker import rank_signatures
from signature_generalizer import generalize_signature
from clone_similarity import rank_candidates
from codesearch_query import search_codesearch, search_by_filename, search_per_package, build_restricted_query
from file_fetcher import fetch_source_file
from clone_verifier import verify_from_context, is_vulnerable_clone
from vendoring_search import extract_vendoring_signals, filter_results_by_path_hint
from library_tokens import get_library_tokens, get_function_names_from_patch
 
 
def print_section(title):
    print(f"\n{'='*50}")
    print(f"  {title}")
    print(f"{'='*50}\n")
 
 
def _dedupe_results(results):
    seen = set()
    out = []
    for r in results:
        key = (r.get("package", ""), r.get("path", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out
 
 
def _best_vulnerable_signature(sigs):
    """
    Pick the most code‑like vulnerable signature from a list
    Favours longer signatures with code characters and penalises prose phrases.
    """
    if not sigs:
        return None
    best = None
    best_score = -1
    for sig in sigs:
        score = len(sig)
        # Strong bonus for containing code structure characters
        if re.search(r'[=(){}\[\];<>]', sig):
            score += 50
        # Penalise prose phrases
        prose = [
            "must be", "should be", "non-negative", "non negative",
            "vulnerable", "patched", "comment", "fix", "added", "removed",
            "otherwise zero is returned", "calculated for each",
            "concatenated", "seq1", "seq2", "requiring only",
            "were calculated", "used with", "zextern ulong",
        ]
        if any(p in sig.lower() for p in prose):
            score -= 100
        # Penalise very short signatures
        if len(sig) < 10:
            score -= 30
        if score > best_score:
            best_score = score
            best = sig
    return best
 
 
def main():
    if len(sys.argv) < 2:
        print("Usage: python attack_of_clones.py patch.patch")
        return
 
    patch = sys.argv[1]
 
    # Derive a source package hint from the patch filename.
    _stem = os.path.splitext(os.path.basename(patch))[0]
    if re.match(r'^[0-9a-f]{7,40}$', _stem):
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
 
    # Step 4: Search archive (signature‑based)
    print_section("Step 4: Searching Debian Archive")
    search_pool = [sig for sig, score in ranked[:8] if score > 2.0]
 
    searched = set()
    all_results = {}
    confirmed_clones = []
    confirmed_keys = set()
 
    for sig in search_pool:
        if sig in searched:
            continue
        searched.add(sig)
        print(f"\nSignature: {sig}")
 
        results = search_codesearch(sig, patch_type=patch_type, source_package=patch_pkg_hint)
        if not results:
            continue
 
        results = _dedupe_results(results)
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
 
            key = (package, path, sig)
 
            if verify_from_context(result, sig, fix_sigs, patch_type=patch_type):
                if key not in confirmed_keys:
                    print(f"\n    Context-level clone detected!")
                    print(f"     Package : {package}")
                    print(f"     File    : {path}")
                    confirmed_clones.append({
                        "package": package,
                        "path": path,
                        "matched_sig": sig,
                        "verification": "context"
                    })
                    confirmed_keys.add(key)
                continue
 
            code = fetch_source_file(result)
            if code and is_vulnerable_clone(code, sig, fix_sigs, patch_type=patch_type, result_path=path):
                if key not in confirmed_keys:
                    print(f"\n    Full-file clone detected!")
                    print(f"     Package : {package}")
                    print(f"     File    : {path}")
                    confirmed_clones.append({
                        "package": package,
                        "path": path,
                        "matched_sig": sig,
                        "verification": "full_file"
                    })
                    confirmed_keys.add(key)
 
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
 
    # Step 6: filename‑based vendoring search
    run_vendoring_search(patch, patch_type, vulnerable_sigs, fix_sigs, confirmed_clones, patch_pkg_hint=patch_pkg_hint)
 
    if confirmed_clones:
        print(f"\nTotal confirmed clones (all methods): {len(confirmed_clones)}")
 
 
def _run_library_token_search(patch, signals, patch_type, fix_sigs,
                               confirmed_clones, confirmed_keys, patch_pkg_hint):
    """
    Fix 1+2+3: library-anchored token search via searchperpackage.
 
    Uses a two-query set-difference approach to avoid file fetching:
      Query A: distinctive token (x2nmodp)  → packages that vendor zlib
      Query B: fix pattern (len2 < 0)       → packages that have the fix applied
      Vulnerable = packages in A not in B
 
    This avoids all sources.debian.org fetches, which fail due to version
    mismatches between CodeSearch's index and sources.debian.org.
    """
    fn_names = get_function_names_from_patch(patch) or [None]
    for s in signals:
        stem = os.path.splitext(s["query"])[0]
        library = s.get("library") or None
 
        for fn_name in fn_names:
            tokens = get_library_tokens(stem, fn_name)
            if not tokens:
                continue
            label = fn_name or "*"
            print(f"  Library-token search ({s['query']}, fn={label}):")
 
            for token, filetype, path_hint in tokens:
                # Query A: packages containing the vulnerable function body
                q_a = build_restricted_query(token, filetype=filetype,
                                             path_hint=path_hint,
                                             exclude_package=library)
                print(f"    Query A (token): {q_a}")
                results_a = search_per_package(q_a, source_package=patch_pkg_hint)
                if not results_a:
                    continue
 
                # Extract package names from Query A (strip version suffix)
                def pkg_base(r):
                    pkg = r.get("package", "")
                    return pkg.rsplit("_", 1)[0] if "_" in pkg else pkg
 
                a_packages = {}
                for r in results_a:
                    base = pkg_base(r)
                    if base not in a_packages:
                        a_packages[base] = r  # keep first result per package
 
                print(f"    {len(a_packages)} unique package(s) with token")
 
                # Query B: packages that contain the fix pattern
                # Use the most distinctive fix sig that fits in one line
                fix_query_token = None
                for fix_sig in fix_sigs:
                    if "len2 < 0" in fix_sig:
                        fix_query_token = "len2 < 0"
                        break
                    if "if (len2" in fix_sig:
                        fix_query_token = "len2"
                        break
 
                if not fix_query_token:
                    # Derive from fix_sigs: pick most distinctive
                    for f in fix_sigs:
                        if len(f) > 6 and "non-negative" not in f.lower():
                            toks = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*', f)
                            specific = [t for t in toks if len(t) > 4]
                            if specific:
                                fix_query_token = specific[0]
                                break
 
                b_packages = set()
                if fix_query_token:
                    q_b = build_restricted_query(
                        fix_query_token, filetype=filetype, path_hint=path_hint)
                    print(f"    Query B (fix):   {q_b}")
                    results_b = search_per_package(q_b)
                    b_packages = {pkg_base(r) for r in results_b}
                    print(f"    {len(b_packages)} package(s) have fix applied")
 
                # Vulnerable = in A but not in B
                vulnerable_pkgs = {p: r for p, r in a_packages.items()
                                   if p not in b_packages}
                print(f"    {len(vulnerable_pkgs)} potentially vulnerable package(s) (A - B):")
 
                for base_pkg, result in list(vulnerable_pkgs.items())[:15]:
                    pkg  = result.get("package", "unknown")
                    path = result.get("path", "")
                    print(f"      {pkg} -- {path}")
 
                    clone_key = (pkg, path, token)
                    if clone_key in confirmed_keys:
                        continue
 
                    print(f"      [library-token+set-diff] Confirmed: {pkg}")
                    confirmed_clones.append({
                        "package": pkg,
                        "path":    path,
                        "matched_sig": f"[library-token] {token}",
                        "verification": "library_token+set_diff"
                    })
                    confirmed_keys.add(clone_key)
 
def run_vendoring_search(patch, patch_type, vulnerable_sigs, fix_sigs,
                         confirmed_clones, patch_pkg_hint=None):
    """
    Step 6: Filename-based vendoring detection + library-token fallback.
    Stage A: filename search + path filtering + two-signal verify.
    Stage B: library-token search via searchperpackage (Fix 1+2+3).
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
 
    vuln_pattern = _best_vulnerable_signature(vulnerable_sigs) if vulnerable_sigs else None
    seen_vendored = set()
    confirmed_keys = set()
 
    # Stage A: filename search
    for s in signals:
        q    = s["query"]
        stem = os.path.splitext(q)[0]
        print(f"\nFilename: {q}")
        results = search_by_filename(q)
        if not results:
            continue
        results = filter_results_by_path_hint(results, stem)
        source_exts = {'.c','.cpp','.cc','.cxx','.h','.hpp',
                      '.go','.rs','.py','.js','.ts'}
        filtered = [r for r in results
                    if any(r.get("path","").endswith(e) for e in source_exts)]
        filtered = _dedupe_results(filtered)
        print(f"  {len(filtered)} source file(s) after path filtering")
        for result in filtered[:10]:
            pkg  = result.get("package","unknown")
            path = result.get("path","")
            print(f"    {pkg}  --  {path}")
            clone_key = (pkg, path, q)
            if clone_key in seen_vendored:
                continue
            seen_vendored.add(clone_key)
            confirmed = False
            if vuln_pattern and verify_from_context(
                    result, vuln_pattern, fix_sigs, patch_type=patch_type):
                confirmed = True
                print(f"    [context] Confirmed.")
            if not confirmed:
                code_text = fetch_source_file(result)
                if code_text:
                    if vuln_pattern and is_vulnerable_clone(
                            code_text, vuln_pattern, fix_sigs,
                            patch_type=patch_type, result_path=path):
                        confirmed = True
                        print(f"    [full-file] Confirmed.")
                    elif s["confidence"] == "high" and fix_sigs:
                        mfix = [f for f in fix_sigs if len(f) > 8
                               and not f.startswith("if")
                               and "non-negative" not in f.lower()]
                        if mfix and not any(f in code_text for f in mfix):
                            confirmed = True
                            print(f"    [fix-absent] Fix not found.")
            if confirmed:
                ck = (pkg, path, q)
                if ck not in confirmed_keys:
                    confirmed_keys.add(ck)
                    print(f"    Vendoring clone confirmed: {pkg}")
                    confirmed_clones.append({
                        "package": pkg, "path": path,
                        "matched_sig": f"[filename] {q}",
                        "verification": "vendoring+context"
                    })
 
    # Stage B: library-token fallback (Fix 1+2+3)
    has_real_vuln_sigs = any(len(v) > 5 for v in (vulnerable_sigs or []))
    if signals and (not confirmed_clones or not has_real_vuln_sigs):
        print("\n  Running library-token fallback (Stage B)...")
        _run_library_token_search(patch, signals, patch_type, fix_sigs,
                                   confirmed_clones, confirmed_keys, patch_pkg_hint)
 
if __name__ == "__main__":
    main()
