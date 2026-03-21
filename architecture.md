# System Architecture: Attack of the Clones

## 1. Objective

Automatically detect **vulnerable code clones** across the Debian source archive
by transforming security patches into searchable vulnerability signatures and
filename-based vendoring signals.

When a vulnerability is fixed in one package, the same vulnerable code often
exists in other packages due to copy-paste reuse, vendoring, and bundled
library copies. Debian security researchers currently find these clones
manually. This project automates that workflow.

---

## 2. Core Insight: Two-Signal Approach

A security patch contains two distinct signals:

| Signal | Source | Purpose |
|--------|--------|---------|
| Vulnerable pattern | Removed lines (`-`) | Search the archive for code clones |
| Fix pattern | Added lines (`+`) | Confirm that a clone is unpatched |

A **true vulnerable clone** matches the vulnerable pattern AND does not
contain the fix pattern.

---

## 3. Dual-Method Detection Pipeline

The system implements two complementary detection methods running from the
same patch input:

```
Security Patch (.patch / .diff)
        │
        ▼
┌───────────────┐
│  Patch Parser │  patch_parser.py
│               │  - Separates removed lines (vulnerable) from added lines (fix)
│               │  - Classifies vulnerability type and language
│               │  - Skips lockfiles, node_modules, minified JS, vendor dirs
└───────┬───────┘
        │
        ├─────────────────────────────────────────┐
        │  (Method A: Signature Search)            │  (Method B: Vendoring Search)
        ▼                                          ▼
┌───────────────┐                        ┌──────────────────────┐
│   Signature   │  clone_detector.py     │  Vendoring Signal    │  vendoring_search.py
│   Extractor   │  - Language-aware      │  Extractor           │  - Parses --- / +++ paths
│               │  - Comparisons, API    │                      │  - Extracts filenames
│               │  - Macros, context     │                      │  - High/medium confidence
│               │  - No VAR in search    │                      │  - 30+ known vendor dirs
└───────┬───────┘                        └──────────┬───────────┘
        │                                           │
        ▼                                           ▼
┌───────────────┐                        ┌──────────────────────┐
│  Filter &     │  signature_filter.py   │  Filename Search     │  codesearch_query.py
│  Rank         │  + signature_ranker.py │                      │  search_by_filename()
│               │  - Lockfile rejection  │                      │  - Literal query
│               │  - Generic call block  │                      │  - Up to 50 results
│               │  - Score > 2.0 gate    │                      │
└───────┬───────┘                        └──────────┬───────────┘
        │                                           │
        ▼                                           ▼
┌───────────────┐                        ┌──────────────────────┐
│  Archive      │  codesearch_query.py   │  Pattern             │  clone_verifier.py
│  Search       │  - RE2 query variants  │  Verification        │  verify_from_context()
│               │  - Specificity guard   │                      │  - Language cross-check
│               │  - Noise threshold     │                      │  - Two-signal check
│               │  - Source exclusion    │                      │
└───────┬───────┘                        └──────────┬───────────┘
        │                                           │
        ▼                                           │
┌───────────────┐                                   │
│  Clone        │  clone_verifier.py                │
│  Verifier     │  - Language cross-check           │
│               │  - Context-based (5-line)         │
│               │  - Full-file fallback             │
└───────┬───────┘                                   │
        │                                           │
        └───────────────────┬───────────────────────┘
                            ▼
                   ┌────────────────┐
                   │ Report / JSON  │  attack_of_clones.py
                   │ Generator      │  - Per-CVE JSON output
                   │                │  - Summary triage list
                   └────────────────┘
```

---

## 4. Vulnerability Classification

The parser classifies patches into 11 types to guide language-appropriate
signature extraction:

| Type | Detection Signal | Extraction Strategy |
|------|-----------------|---------------------|
| `null_deref` | NULL, nullptr in content | API calls + control-flow |
| `bounds_check` | C-style MAX_/MIN_ macros | Macro constants + comparisons |
| `memory_management` | malloc, free, realloc | Memory API call sequences |
| `buffer_overflow` | strcpy, strcat, gets | Unsafe string API names |
| `path_traversal` | `../` patterns | Token + path normalization |
| `go_static` | .go file extension | Go-specific CamelCase types |
| `rust_static` | .rs file extension | Rust-specific trait types |
| `js_bundling` | require/import/module | Module paths + camelCase |
| `js_generic` | .js extension (other) | Boolean conditions + literals |
| `c_cpp_inline` | .h or `template<` | Template structure + casts |
| `generic` | All others | All extractors combined |

Language is detected from file extension first. Content-based JS detection
(requires 2+ JS-specific markers: `===`, `!==`, `=>`, `const`, etc.) applies
as a fallback when the last file processed was a lockfile.

---

## 5. Component Details

### patch_parser.py
Parses unified diff format. Separates removed lines (vulnerable pattern) from
added lines (fix pattern). Skips test files and **generated files**: lockfiles
(`package-lock.json`, `yarn.lock`, `cargo.lock`, `go.sum`, etc.),
`node_modules` vendored copies, minified JS, and dist/bundle/vendor
directories. Deduplicates lines and inserts file-boundary sentinels to prevent
cross-file context pairs.

### clone_detector.py
Extracts structured signatures from code lines. Four generic extractors:
- `extract_comparisons()` — e.g. `s < MAX_SAMPLES`
- `extract_function_calls()` — e.g. `PyString_FromStringAndSize(`
- `extract_macros()` — e.g. `MAX_SAMPLES`
- `extract_context_pairs()` — two-line joins, highest-value signal type

Three language-specific extractors for JS, Go/Rust, and C++ inline.

**VAR substitution is NOT done here.** It belongs only in
`signature_generalizer.py` for similarity scoring.

Context pairs are only generated when at least one line contains a function
call, comparison, control-flow keyword, or uppercase macro — preventing
JSON key-value lines from pairing.

### signature_filter.py
Removes four noise categories in order:
1. Bare quoted string literals (no operators/parens inside)
2. JSON lockfile lines (`"key": value`, dependency chains with `>`)
3. Standalone generic function calls (`shift(`, `push(`, `join(`, etc.)
4. Signatures scoring ≤ 2.0 after ranking

### signature_ranker.py
Rule-based scoring. Context pairs (+6), control-flow (+5), equality
comparisons (+4), security APIs (+3), uppercase macros (+4), length bonus
(up to +5). Generic token diversity penalty (-3).

### codesearch_query.py
Queries Debian CodeSearch via `x-dcs-apikey` header. Generates query variants
from most to least specific. Key guards:
- **Specificity guard**: 40+ generic tokens blocked as standalone queries
- **Noise threshold**: queries returning ≥200 results skipped
- **Retry**: 30s timeout with single retry
- **Source exclusion**: patched package filtered from results

Also exports `search_by_filename()` for vendoring detection — literal match,
up to 50 results.

### vendoring_search.py
Extracts filename signals from `---`/`+++` patch headers.

**High confidence**: path contains a known vendor directory name from a
curated list of 30+ libraries (`zlib`, `libpng`, `sqlite3`, `openssl`, `lz4`,
`pcre2`, `third_party`, `bundled`, etc.)

**Medium confidence**: filename stem ≥8 characters, not in a generic-name
blocklist, has a code extension.

This method is complementary to signature search:
- Signature search: succeeds when code was modified/renamed across codebases
- Vendoring search: succeeds when a file was copied verbatim (Type-1 clones)

### clone_verifier.py
Two-step verification:

1. **Language cross-check** (first): file extension must match expected
   language for the patch type. JS patches only confirm
   `.js`/`.ts`/`.mjs`/`.cjs`/`.tsx` files. Prevents cross-language token
   coincidence false positives (e.g. JS patch matching Go files).

2. **Two-signal check**: candidate must contain the vulnerable pattern AND
   lack the fix pattern. Context-based uses 5 lines from the API response.
   Full-file fetches from `sources.debian.org` as fallback.

### clone_similarity.py
Jaccard similarity on token sets with bonuses: +0.2 for shared uppercase macros,
+0.15 for shared function call names, +0.1 for context pair signatures.

### signature_generalizer.py
Replaces generic variable names with `VAR` and numeric literals with `NUM`.
Preserves API names and uppercase macros. Used **only** for similarity scoring
and candidate ranking — never for search query generation.

### file_fetcher.py
Fetches raw source files from `sources.debian.org`. Splits package field
`mesa_26.0.1-2` into name and version. Strips the leading package-directory
component from path (per CodeSearch OpenAPI v1.4.0 spec). Caps file size at
500KB.

### attack_of_clones.py
End-to-end orchestrator. Runs Steps 1–5 (signature-based detection) followed
by Step 6 (vendoring detection). Both methods append to the same
`confirmed_clones` list. Final output includes total clone count across both
methods.

---

## 6. Known Limitations

1. **Context-based verification** uses only the 5-line window returned by the
   CodeSearch API. Multi-hunk patches and complex control flows may require
   full-file verification.

2. **Vendoring filename collisions**: common filenames like `sha256.c` appear
   in many unrelated packages. The 200-result noise threshold and
   `_is_distinctive_filename()` guard mitigate this but do not eliminate it.

3. **Single-patch processing**: the full GSoC system will process patches at
   archive scale via Debian Security Tracker integration.

4. **sources.debian.org path format**: epoch versions and `+dfsg` suffixes
   in package version strings occasionally cause file fetch failures.

---

## 7. Planned GSoC Extensions

- Automated CVE ingestion from the Debian Security Tracker JSON feed
- Integration with `data/embedded-code-copies` for targeted package scanning
- Parallel signature search (thread pool, configurable concurrency)
- Bloom filter pre-screening for performance at archive scale
- Structured JSON reports per CVE for Debian security team triage
- Evaluation on 20+ CVE benchmark with precision/recall measurement
- Debian Python packaging and man page for distribution
