# Attack of the Clones – Preliminary Research

This repository contains exploratory work for the Debian GSoC project:

**Attack of the Clones: Detecting Vulnerable Code Clones from Security Patches**

## Goal

Automatically detect vulnerable code patterns across the Debian package archive by:

1. Extracting security patch fragments
2. Generating fuzzy signatures
3. Searching the Debian archive
4. Identifying potential vulnerable clones

## Current Work

- Signature extraction prototype
- Experiments on multiple CVEs
- Observations on noise vs precision

## Preliminary Experiments

To evaluate the feasibility of detecting vulnerability clones using patch-derived signatures, several preliminary experiments were conducted using real patches from the Debian Security Tracker.

### 1. APT Null Pointer Vulnerability
Tested extraction of API-based and control-flow signatures from an APT patch.  
This experiment demonstrated that combining API signatures with control-flow conditions can produce meaningful matches in the Debian archive.

### 2. libtiff Integer Overflow
Evaluated macro-based signatures such as `MAX_SAMPLES`.  
Results showed that macro identifiers can produce many matches, but they often introduce noise when the macro name is reused across unrelated projects.

### 3. libvips Validation Logic
Focused on validation-related signatures.  
This experiment showed that project-specific APIs may fail to generalize across the Debian archive.

### 4. rollup Regex-Based Patch
Analyzed a patch involving path normalization and regex-related logic.  
The experiment revealed that signatures derived from project-specific identifiers often produce zero matches, highlighting limitations of overly specific token-based signatures.

### 5. Generalized Signature Experiment
Tested a prototype generalization step where variable identifiers were replaced with abstract tokens (e.g., `VAR`, `NUM`).  
The results showed that generalized signatures can help with ranking similarity between candidates, but they are too abstract to be used directly for archive search.

These experiments informed the final prototype pipeline:

Patch -> Signature Extraction -> Filtering -> Generalization -> Ranking ->  CodeSearch -> Candidate Clone Detection

## Prototype Pipeline

This repository implements a preliminary prototype of the
Attack of the Clones workflow.

Pipeline:

Patch -> Signature Extraction (clone_detector.py) -> Signature Filtering -> Signature Generalization -> Signature Ranking -> Debian CodeSearch Query -> Candidate clone detection


---

## Usage Example

Run the complete pipeline using:

```bash
python attack_of_clones.py path/to/patch.patch
```

Example:

```bash
python attack_of_clones.py ../88cf9dbb48f6e172629795ecffae35d5052f68aa.patch.1
```

Example output:

```
=== Extracting signatures ===

Signature: MAX_SAMPLES

Searching Debian archive...

Top matches:
https://codesearch.debian.net/src/gallium/drivers/llvmpipe/lp_state_fs.c
https://codesearch.debian.net/src/gallium/drivers/llvmpipe/lp_state_fs.h
```

