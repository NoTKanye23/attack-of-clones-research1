# Summary of Preliminary Findings

Six exploratory experiments were conducted using real security patches from
upstream projects and the Debian Security Tracker. The goal was to evaluate
whether security patches can be transformed into effective search signals for
detecting vulnerability clones across the Debian archive using two
complementary methods: **signature-based code matching** (Steps 1–5) and
**filename-based vendoring detection** (Step 6).

The experiments applied the prototype pipeline to different vulnerability
types across C, C++, and JavaScript patches.

---

## Experiment Overview

| Experiment | CVE / Source | Type | Method | Matches | Key Outcome |
|---|---|---|---|---|---|
| E1: APT nullptr | APT (launchpad) | null_deref | Signature | 4 candidates, 1 TP | Context pairs: highest-precision signal |
| E2: libtiff | CVE-2025-61144 | bounds_check | Signature | 3 candidates, 0 TP | Macro alone noisy; combined sig returned 0 (correct) |
| E3: libvips | CVE-2026-3147 | input_validation | Signature | 1 candidate, 0 TP | Project-specific APIs rarely generalize |
| E4: rollup | CVE-2026-27606 | js_bundling | Signature | 0 after fixes (2 FP eliminated) | Language cross-check essential |
| E5: generalization | CVE-2026-27606 | abstraction | Signature | 0 | VAR sigs unusable for search |
| E6: zlib minizip | CVE-2023-45853 | bounds_check | Vendoring | 3 confirmed clones | Filename search: fast Type-1 clone recovery |

---

## Seven Key Findings

### Finding 1 — Context pairs are the highest-value signature type

Two-line context pairs from adjacent vulnerable lines almost never appear
coincidentally in unrelated code. In E1, the context pair
`PyString_FromStringAndSize( | if (Obj == nullptr)` narrowed 4 candidates
to 1 confirmed true positive. Searching the API call alone produced 4
candidates with 3 false positives; adding the context pair verification
raised precision to 1.0 on the same candidate set.

### Finding 2 — Hybrid pipeline is required

Original signatures yield better search recall (exact token match).
Generalized VAR-substituted signatures are better for scoring structural
similarity. E5 confirmed that generalized signatures (`VAR`, `NUM`) return
zero results from CodeSearch because the engine performs lexical matching,
not structural matching. VAR substitution belongs only in
`signature_generalizer.py` for candidate ranking, never for search query
generation.

### Finding 3 — Vulnerability type classification reduces noise by ~60%

Using type-specific extraction (macro anchors for `bounds_check`, module
paths for `js_bundling`) reduced false candidates compared to applying all
extractors uniformly. Based on manual inspection of E1 and E2 results, the
reduction is approximately 60%.

### Finding 4 — Language cross-check eliminates a major false-positive class

E4 (rollup, `js_bundling`) produced 2 confirmed clones before the fix was
applied — both against `.go` files due to token coincidence on
`firstPathSegment` in the Azure MSAL library vendored inside gitaly and
docker.io. Adding a file-extension check against the patch language reduced
confirmed clones to 0 with no loss of true positives. The check runs before
any API calls and costs nothing.

### Finding 5 — JSON/lockfile lines are a serious source of noise

The rollup patch touches `package-lock.json`, producing signatures like
`"madeAt": 1771566180086` and npm dependency chains. These scored positively
under the original ranker and wasted API quota. Removing generated files at
parse time (before any extraction) is the correct fix — not post-hoc
filtering.

### Finding 6 — Zero results can be correct

E3–E5 returning zero confirmed clones correctly reflects that the affected
code is not widely bundled in the Debian archive. The system distinguishes
"no clones exist" from "signatures were too generic" by logging which query
variants were attempted and whether they hit the ≥200 noise threshold.

### Finding 7 — Filename-based vendoring detection is a fast, independent axis

E6 demonstrated that a single literal filename query (`zip.c`) recovered 3
confirmed vulnerable clones of CVE-2023-45853 in one API call — the same 3
packages the signature pipeline found after 6 query variants. For Type-1
clones (verbatim copies), vendoring search is faster and requires no
signature extraction or ranking. The two methods are complementary:

- Signature search succeeds when code was modified across codebases
- Vendoring search succeeds when a file was copied verbatim and the
  filename was preserved

**Secondary finding from E6**: the 8-character stem minimum in
`_is_distinctive_filename()` incorrectly discards short but library-canonical
filenames (`zip.c`, `lz4.c`, `sha1.c`). The fix is to bypass the length
check when the parent directory already provides a strong library signal
(i.e., matches `KNOWN_VENDOR_DIRS`).

---

## Why No Single Strategy Is Sufficient

| Strategy | Strength | Weakness |
|---|---|---|
| API signatures alone | High recall | High noise (E1, E3) |
| Macro signatures alone | Specific anchors | Reused in unrelated code (E2) |
| Context pairs | Highest precision | May miss renamed variables |
| Generalized (VAR) sigs | Structural matching | Cannot search CodeSearch (E5) |
| Filename search | Fast for Type-1 clones | Fails if filename was changed |
| Language cross-check | Eliminates language FPs | Requires correct type classification |

No experiment produced perfect results from a single method. The final
pipeline combines all six techniques, each compensating for the others'
weaknesses.

---

## Pipeline Architecture Validated by Experiments

```
Patch
  ├─ Signature path (E1–E5)
  │    ├── Type classification (Finding 3)
  │    ├── Context pair extraction (Finding 1)
  │    ├── Lockfile skip (Finding 5)
  │    ├── Score gating > 2.0 (Finding 2)
  │    ├── Archive search with noise threshold (Finding 6)
  │    └── Language cross-check + two-signal verify (Finding 4)
  │
  └─ Vendoring path (E6)
       ├── Filename extraction from patch headers
       ├── Known-vendor-dir confidence assignment
       └── Literal search + context verify (Finding 7)
```

Both paths produce the same output structure and append to the same
confirmed-clones list.
