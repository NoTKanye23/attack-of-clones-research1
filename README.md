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

## Experiments

1. NULL pointer dereference (APT)
2. Stack overflow (libtiff)
3. Input validation bug (libvips)

## Prototype Pipeline

This repository implements a preliminary prototype of the
Attack of the Clones workflow.

Pipeline:

Patch
  ↓
Signature Extraction
  ↓
Debian CodeSearch Query
  ↓
Candidate Clone Locations
