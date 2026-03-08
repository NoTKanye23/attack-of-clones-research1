# Experiment 5: Original vs Generalized Signature Search

## Objective

Evaluate the effect of signature generalization on Debian code search results.

Specifically we compare:

1. Original signature extracted from patch
2. Generalized signature produced by the pipeline

The goal is to understand how abstraction affects search recall and noise.

---

## Patch Source

CVE: CVE-2026-27606  
Project: rollup  
Commit: c60770d7aaf750e512c1b2774989ea4596e660b2

---

## Original Signature

Example extracted line:

if (normalized.length > 0 && normalized[normalized.length - 1] !== '..')

---

## Generalized Signature

After token generalization:

VAR (VAR.VAR > NUM && VAR[VAR.VAR - NUM] NEQ 'PATH_TRAVERSAL')

---

## Search Platform

https://codesearch.debian.net

---

## Results

### Original Signature Search

Matches found:

- (record URLs returned by search)

Example:

https://codesearch.debian.net/src/path.ts

Number of matches: X

---

### Generalized Signature Search

Matches found:

None

Number of matches: 0

---

## Observation

Aggressive token generalization produces abstract patterns that are not
directly searchable using text-based code search engines.

While generalized signatures help identify structural vulnerability
patterns, they reduce recall when used directly as search queries.

---

## Insight

A hybrid strategy may be required:

1. Use **original signatures for archive search**
2. Use **generalized signatures for ranking and similarity scoring**

This approach preserves search recall while enabling structural
pattern detection.

---

## Implication for Attack-of-Clones System

Future system architecture may combine:

Patch -> Original signature search -> Candidate matches -> Generalized pattern matching -> Similarity scoring -> Ranked vulnerability clones
