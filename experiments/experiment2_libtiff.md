# Experiment 2 – libtiff Integer Overflow / Bounds Check

## Patch Source

CVE:
CVE-2025-61144

Project:
libtiff

Patch Link:
https://gitlab.com/libtiff/libtiff/-/commit/88cf9dbb48f6e172629795ecffae35d5052f68aa

Bug Type:
Stack overflow / integer overflow caused by a missing bounds check.

---

## Methodology

This experiment evaluates whether vulnerability patterns extracted from a real security patch can identify similar code fragments across the Debian archive.

The prototype pipeline performs the following steps:

1. Parse the security patch and extract vulnerable and fix fragments
2. Generate candidate vulnerability signatures
3. Filter noisy or trivial signatures
4. Rank signatures based on structural importance
5. Query the Debian CodeSearch archive
6. Inspect candidate matches

---

## Patch Fragment Extracted

The patch introduces an additional bounds check in a loop condition.

Example fragment extracted from the patch:

```c
for (s = 0; (s < spp) && (s < MAX_SAMPLES); s++)
```

This change prevents the loop index from exceeding the allowed number of samples.

---

## Candidate Signatures

The prototype extracted several candidate signatures:

```
MAX_SAMPLES
s < spp
for (s = 0
```

These signatures represent:

* macro identifiers
* loop bounds
* control-flow structure

---

## CodeSearch Experiments

Search platform:

https://codesearch.debian.net

Example query used:

```
MAX_SAMPLES
```

---

## Results

Matches found in packages such as:

* mesa (Gallium llvmpipe driver)

Example files:

* mesa/src/gallium/drivers/llvmpipe/lp_state_fs.c
* mesa/src/gallium/drivers/llvmpipe/lp_state_fs.h
* mesa/src/gallium/drivers/llvmpipe/lp_setup_context.h

Total matches found: **3**

Manual classification:

* Estimated false positives: **3**
* Estimated true positives: **0**

---

## Observation

The macro-based signature `MAX_SAMPLES` produced several matches across unrelated packages.

This occurs because macro identifiers are frequently reused in different codebases.

As a result, macro-only signatures generate **high noise**.

To reduce noise, a more specific signature was tested:

```
(s < spp) && (s < MAX_SAMPLES)
```

This signature combines:

* loop structure
* bounds-check condition
* macro constraint

---

## Second Signature Attempt

Signature tested:

```
(s < spp) && (s < MAX_SAMPLES)
```

Search results:

Matches found: **0**

---

## Interpretation

The combined signature significantly reduced noise compared to the macro-only signature.

However, no matches were found in the Debian archive.

This suggests that the specific loop-bound validation logic introduced in the libtiff patch may be relatively unique to that codebase.

---

## Conclusion

Macro-based signatures such as `MAX_SAMPLES` provide high recall but produce significant noise.

More specific structural signatures improve precision but may reduce recall.

An effective vulnerability clone detection pipeline should therefore combine:

* macro identifiers
* control-flow structures
* contextual patterns

Balancing **recall and precision** is essential for large-scale clone detection across the Debian archive.

