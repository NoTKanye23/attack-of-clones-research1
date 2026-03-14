# Attack of the Clones – Vulnerability Clone Detection Prototype

This repository contains a **prototype implementation** for the Debian GSoC project idea:

**Attack of the Clones: Detecting Vulnerable Code Clones from Security Patches**

The goal of this project is to automatically detect **clones of vulnerable code across the Debian package archive** by analyzing upstream security patches and searching for similar patterns in other packages.

---

# Motivation

When a vulnerability is fixed in an upstream project, the fix often modifies a **small fragment of code**.

However, similar vulnerable code may exist in other projects within the Debian ecosystem due to:

* copy-paste reuse
* shared libraries
* derived implementations of the same logic

These **vulnerability clones** can remain undetected if the fix is not propagated across all affected packages.

Currently, Debian security researchers often perform **manual searches** to locate these clones.

This project explores an automated workflow to:

1. Extract vulnerability patterns from security patches
2. Generate structural search signatures
3. Query the Debian source archive
4. Identify candidate vulnerable clones

---

# Prototype Pipeline

This repository implements a **prototype pipeline** for vulnerability clone detection.

Pipeline overview:

```
Security Patch
      │
      ▼
Patch Parser
      │
      ▼
Signature Extraction
      │
      ▼
Signature Filtering
      │
      ▼
Signature Generalization
      │
      ▼
Signature Ranking
      │
      ▼
Debian CodeSearch Query
      │
      ▼
Candidate Clone Detection
```

Core implementation entry point:

```
attack_of_clones.py
```

The prototype currently demonstrates the **patch-to-search workflow**, which is the key research step for detecting vulnerability clones.

---

# Repository Structure

```
attack-of-clones/
│
├── attack_of_clones.py          # Main pipeline entry point
├── patch_parser.py              # Extract vulnerable and fix lines from patches
├── clone_detector.py            # Signature extraction logic
├── signature_filter.py          # Remove noisy or trivial signatures
├── signature_ranker.py          # Ranking heuristic for signatures
├── signature_generalizer.py     # Token generalization for similarity scoring
├── clone_similarity.py          # Similarity scoring between signatures and results
├── clone_verifier.py            # Verification of candidate clones
├── codesearch_query.py          # Debian CodeSearch query generation
├── code_tokenizer.py            # Tokenization utilities
├── file_fetcher.py              # Fetch candidate source files
│
├── experiments/                 # Experiment notes and evaluation
└── README.md
```

---

# Example Usage

Run the full pipeline using:

```
python3 attack_of_clones.py path/to/patch.patch
```

Example:

```
python3 attack_of_clones.py 88cf9dbb48f6e172629795ecffae35d5052f68aa.patch
```

Example output:

```
Step 1: Extracting Signatures
Patch type detected : bounds_check
Vulnerable signatures : 2

Step 3: Ranking Signatures
[ 9.50] for (s = 0; s < spp; s++)
[ 2.70] s < spp

Step 4: Searching Debian Archive
Query: MAX_SAMPLES
Candidates found: 7
```

---

# Preliminary Experiments

Several exploratory experiments were conducted using real patches from the **Debian Security Tracker**.

These experiments helped evaluate which types of signatures are most effective for detecting vulnerability clones.

---

## 1. APT Null Pointer Vulnerability

Tested extraction of API-based and control-flow signatures.

Observation:

Combining **API calls with control-flow conditions** produced meaningful archive matches.

---

## 2. libtiff Integer Overflow

Used macro-based signatures such as:

```
MAX_SAMPLES
```

Observation:

Macro identifiers generate many matches but can introduce **noise** when macros are reused across unrelated projects.

---

## 3. libvips Validation Logic

Focused on validation-related signatures.

Observation:

Project-specific APIs often **do not generalize well across the Debian archive**, resulting in few matches.

---

## 4. rollup Path Normalization Patch

Examined regex and path normalization patterns.

Observation:

Highly project-specific identifiers produce **zero matches**, highlighting the need for signature generalization.

---

## 5. Generalized Signature Experiment

Tested replacing identifiers with abstract tokens such as:

```
VAR
NUM
```

Observation:

Generalized signatures help with **similarity scoring and ranking**, but they are too abstract to be used directly for archive search.

---

# Security Patches Used

Experiments used real patches from:

* Debian Security Tracker (APT)
* libtiff vulnerability fixes
* libvips validation fixes
* rollup path normalization patches

These patches were used to extract vulnerability signatures and evaluate the prototype pipeline.

---

# Current Status

The prototype currently implements:

 Patch parsing and vulnerability classification
 Signature extraction from security patches
 Signature filtering and ranking
 Query generation for Debian CodeSearch
 Candidate clone detection logic

This demonstrates the **core feasibility of patch-based vulnerability clone detection**.

---

# Planned Work (GSoC Scope)

The full project will extend the prototype with:

* Integration with the **Debian CodeSearch API**
* Automated retrieval of candidate source files
* Improved clone similarity detection
* Large-scale scanning of the Debian package archive
* Automated vulnerability reporting

---

# License

This repository contains **exploratory prototype work for the Debian GSoC program**.

