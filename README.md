![Python](https://img.shields.io/badge/python-3.9+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-research%20prototype-orange)
![Commits](https://img.shields.io/badge/commits-49%2B-brightgreen)

# Attack of the Clones – Vulnerability Clone Detection

Prototype pipeline for the Debian GSoC 2026 project:

**Attack of the Clones: Fight Back Using Code Duplication Detection from Security Patches in the Debian Archive**

Automatically detects clones of vulnerable code across the Debian package
archive by analysing upstream security patches and searching for similar
patterns using two complementary methods: **signature-based code matching**
and **filename-based vendoring detection**.

---

## Motivation

When a vulnerability is fixed in an upstream project, the same vulnerable
code often exists in other Debian packages due to:

- copy-paste reuse
- vendored library copies (`third_party/`, `bundled/`, etc.)
- derived implementations of the same logic

These **vulnerability clones** remain undetected unless actively searched for.
Debian security researchers currently do this manually.

This project automates the workflow:

1. Extract vulnerability patterns from security patches (two-signal approach)
2. Generate structural search signatures and filename signals
3. Query the Debian source archive via CodeSearch API
4. Identify and verify candidate vulnerable clones
5. Report confirmed clones for security team triage

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/NoTKanye23/attack-of-clones-research1.git
cd attack-of-clones-research1
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Set Debian CodeSearch API key

Get a key at <https://codesearch.debian.net/apikeys/> (requires Salsa login).

```bash
export DCS_API_KEY=your_key_here
```

### 4. Run the pipeline on a patch

```bash
python3 attack_of_clones.py path/to/CVE-YYYY-NNNN.patch
```

Example:

```bash
python3 attack_of_clones.py examples/88cf9dbb.patch
```

### 5. Batch mode (Security Tracker integration)

```bash
python3 batch_scan.py --release bookworm --urgency high --max 20 --dry-run
python3 batch_scan.py --release bookworm --urgency high --max 20
```

---

## Pipeline Overview

The system runs two detection methods from the same patch:

```
Security Patch
      │
      ▼
Patch Parser          ← classifies type, skips lockfiles/generated files
      │
      ├──────────────────────────────────┐
      │  Method A: Signature Search      │  Method B: Vendoring Search
      ▼                                  ▼
Signature Extractor                Vendoring Signal Extractor
      │                                  │   (filename from patch paths)
      ▼                                  ▼
Filter & Rank                      Filename Search (literal)
      │  (score > 2.0 gate)             │
      ▼                                  ▼
Archive Search (RE2)               Pattern Verification
      │                                  │
      ▼                                  │
Clone Verifier                          │
  ├─ Language cross-check               │
  ├─ Context verification (5 lines)     │
  └─ Full-file fallback                 │
      │                                 │
      └────────────────┬────────────────┘
                       ▼
               Report Generator
          (results/CVE-YYYY-NNNN.json)
```

---

## Repository Structure

```
attack-of-clones/
│
├── attack_of_clones.py        # Main pipeline (Steps 1–6)
├── patch_parser.py            # Diff parsing, classification, lockfile skip
├── clone_detector.py          # Signature extraction (no VAR substitution)
├── signature_filter.py        # Noise rejection (lockfiles, generics, strings)
├── signature_ranker.py        # Rule-based scoring; score > 2.0 gate
├── signature_generalizer.py   # VAR/NUM substitution for scoring only
├── clone_similarity.py        # Jaccard + macro/call bonuses
├── clone_verifier.py          # Language cross-check + two-signal verification
├── codesearch_query.py        # RE2 query generation + search_by_filename()
├── file_fetcher.py            # sources.debian.org raw file fetcher
├── code_tokenizer.py          # Token extraction utilities
├── vendoring_search.py        # Filename signals, high/medium confidence
│
├── tracker_ingest.py          # Debian Security Tracker JSON integration
├── embed_map.py               # embedded-code-copies parser
├── batch_scan.py              # Batch CVE processing via Security Tracker
│
├── experiments/               # Experiment notes (5 CVEs documented)
├── architecture.md            # Full system architecture
└── README.md
```

---

## Key Design Decisions

### Two-Signal Detection

A patch's removed lines (`-`) encode the **vulnerable pattern** used for
search. The added lines (`+`) encode the **fix pattern** used to confirm
a clone is unpatched. A confirmed clone must match the first and not the second.

### Language Cross-Check

Before any token matching, the file extension of a candidate result is checked
against the patch language type. A `js_bundling` patch only confirms
`.js`/`.ts`/`.mjs` files. This eliminated a class of false positives where
camelCase JS identifiers matched unrelated Go files in vendored Azure libraries.

### Filename-Based Vendoring Detection (Step 6)

A second detection axis operates on filenames from the patch paths rather than
code content. If a patch touches `vendor/zlib/inflate.c`, searching for
`inflate.c` finds all Debian packages containing that file — likely vendored
zlib copies — without needing to extract or score any signatures.

Two confidence levels:
- **High**: path contains a known vendor directory (`zlib`, `sqlite3`,
  `third_party`, `bundled`, etc.)
- **Medium**: filename stem ≥8 characters and not in a generic-name blocklist

### VAR Substitution: Scoring Only, Never Search

Early versions generalized variable names to `VAR` before searching. This
produced completely unsearchable signatures and hit 131,000 results for `VAR(`.
VAR substitution now happens only in `signature_generalizer.py` for ranking
candidate similarity, never for CodeSearch query generation.

---

## Preliminary Experiments

Five experiments across real CVEs established the key findings:

| Experiment | CVE / Source | Type | Matches | Key Finding |
|---|---|---|---|---|
| E1: APT nullptr | APT (launchpad) | null_deref | 4 | Context pairs: highest-precision signal |
| E2: libtiff | CVE-2025-61144 | bounds_check | 3 | Macro alone noisy; combined sig correct |
| E3: libvips | CVE-2026-3147 | input_validation | 1 | Project-specific APIs rarely generalize |
| E4: rollup | CVE-2026-27606 | js_bundling | 0 (after fixes) | Language cross-check eliminated 2 FP |
| E5: generalization | CVE-2026-27606 | abstraction | 0 | VAR sigs unusable for search |

### Seven Key Findings

1. **Context pairs** are the highest-value signature type — two-line joins rarely coincide in unrelated code.
2. **Hybrid pipeline required** — original sigs for search recall, VAR-generalized sigs for ranking.
3. **Vulnerability type classification** reduces false candidates by ~60%.
4. **Language cross-check** eliminates a major false-positive class (JS patch matching Go files).
5. **JSON/lockfile lines** are a serious noise source; removing generated files at parse time is essential.
6. **Zero results can be correct** — the system distinguishes "no clones" from "signatures too generic".
7. **Filename-based vendoring detection** is complementary — succeeds on verbatim copies where signature search also works, and provides a fast independent confirmation path.

---

## Tracker Integration

The `tracker_ingest.py` module reads the Debian Security Tracker JSON feed
(`security-tracker.debian.org/tracker/data/json`) directly, using the same
data model as the official `tracker_data.py`. The `embed_map.py` module parses
`data/embedded-code-copies` from the security-tracker repository to expand
scan targets with known embedded library copies.

```bash
# Dry run: show what would be scanned
python3 batch_scan.py --release bookworm --urgency medium --dry-run

# Run for real on top 5 high-urgency CVEs
python3 batch_scan.py --release bookworm --urgency high --max 5
```

---

## Output Format

Results are written to `results/CVE-YYYY-NNNN.json`:

```json
{
  "cve_id": "CVE-2026-27606",
  "patch_type": "js_bundling",
  "confirmed_clones": [
    {
      "package": "libwebp_1.3.2-0.4",
      "path": "src/utils/huffman_encode_utils.c",
      "matched_sig": "PyString_FromStringAndSize( | if (Obj == nullptr)",
      "verification": "context"
    },
    {
      "package": "chromium_120.0.6099.109",
      "path": "third_party/zlib/inflate.c",
      "matched_sig": "[filename] inflate.c",
      "verification": "vendoring+context"
    }
  ]
}
```

---

## Current Status

The prototype implements the full dual-method detection pipeline:

- [x] Patch parsing with lockfile/generated-file skip
- [x] 11-type vulnerability classification with content-based JS detection
- [x] Signature extraction (comparisons, API calls, macros, context pairs)
- [x] Four-rule noise filter with score gating
- [x] RE2 query generation with specificity guard and noise threshold
- [x] Language cross-check verification
- [x] Two-signal clone verification (context + full-file)
- [x] Filename-based vendoring detection (Step 6)
- [x] Debian Security Tracker integration (`tracker_ingest.py`)
- [x] Embedded-code-copies integration (`embed_map.py`)
- [x] Batch scanning mode (`batch_scan.py`)

---

## License

Released under the MIT License.

Developed as preliminary work for the Debian GSoC 2026 programme.
Mentor: Bastien Roucariès (rouca), Debian Security Team.
