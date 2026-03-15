# Experiment 5 – Original vs Generalized Signature Search

## Objective

This experiment evaluates the impact of **signature generalization** on archive search results.

Two types of signatures are compared:

1. **Original signatures** extracted directly from the security patch
2. **Generalized signatures** produced by the prototype pipeline through token abstraction

The goal is to understand how abstraction affects **search recall, precision, and noise** when querying the Debian source archive.

---

## Patch Source

CVE:
CVE-2026-27606

Project:
rollup

Commit:
c60770d7aaf750e512c1b2774989ea4596e660b2

---

## Original Signature

Example fragment extracted directly from the patch:

```javascript
if (normalized.length > 0 && normalized[normalized.length - 1] !== '..')
```

This signature preserves the **exact identifiers and structure** used in the original code.

---

## Generalized Signature

After token generalization performed by the pipeline, the pattern becomes:

```
VAR (VAR.VAR > NUM && VAR[VAR.VAR - NUM] NEQ 'PATH_TRAVERSAL')
```

Generalization replaces specific identifiers with abstract tokens such as:

* `VAR` – variable identifiers
* `NUM` – numeric constants
* symbolic operators representing comparisons

The purpose of generalization is to capture **structural similarity** rather than exact token matches.

---

## Search Platform

Debian CodeSearch

https://codesearch.debian.net

---

## Results

### Original Signature Search

Number of matches found: **1**

Example result:

https://codesearch.debian.net/src/path.ts

These results correspond to code that closely resembles the original fragment.

---

### Generalized Signature Search

Matches found: **0**

Estimated false positives: **0**
Estimated true positives: **0**

---

## Observation

Aggressive token generalization produces abstract patterns that cannot be used directly with **text-based code search engines** such as Debian CodeSearch.

Since CodeSearch performs lexical matching, generalized patterns such as:

```
VAR (VAR.VAR > NUM ...)
```

do not correspond to literal text present in source files.

As a result, generalized signatures are ineffective when used directly as search queries.

---

## Insight

Despite their limitations for archive search, generalized signatures remain valuable for **post-search analysis**.

A practical approach is to use generalized signatures during later stages of the pipeline, such as:

* candidate verification
* structural similarity comparison
* ranking of potential vulnerability clones

---

## Implication for the Attack-of-Clones System

The experiment suggests a hybrid architecture:

```
Patch
   ↓
Original signature extraction
   ↓
Archive search (CodeSearch)
   ↓
Candidate retrieval
   ↓
Generalized pattern matching
   ↓
Similarity scoring
   ↓
Ranked vulnerability clones
```

In this design:

* **original signatures** maximize search recall
* **generalized signatures** improve structural comparison and ranking

---

## Conclusion

Generalized signatures are not suitable for direct archive search using lexical code search engines.

However, they are valuable for **structural comparison and clone similarity analysis**.

Combining both approaches allows the system to balance:

* **search recall** (using original signatures)
* **structural matching and ranking** (using generalized signatures)

This hybrid approach provides a more effective strategy for detecting vulnerability clones across large software archives.

