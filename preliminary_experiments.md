# Preliminary Experiments for Debian Clone Detection

This document summarizes early exploratory experiments conducted to evaluate
whether **security patches can be transformed into effective search signatures**
for detecting vulnerable code clones across the Debian archive.

The goal of these experiments is to understand:

* what types of code fragments produce useful search signatures
* which signatures generalize across projects
* what sources of noise appear during archive search

These insights guide the design of the prototype detection pipeline.

---

# Experiment 1 – NULL Pointer Dereference

**Target vulnerability type:** NULL pointer dereference
**Example project:** APT

### Patch fragment

Typical NULL pointer fixes introduce explicit checks:

```
if (ptr == NULL)
```

or defensive conditions such as:

```
if (!ptr)
```

### Candidate signatures

* `ptr == NULL`
* `if (!ptr)`
* surrounding control-flow context

### Observation

Control-flow based signatures combined with API calls often produce
**relevant matches in other projects**, particularly when the same API
usage pattern exists.

However, very small signatures such as `ptr == NULL` can generate many
irrelevant matches because NULL checks are extremely common.

### Insight

NULL dereference patches require **additional context (API usage or
surrounding code)** to generate useful search signatures.

---

# Experiment 2 – Integer Overflow / Bounds Check (libtiff)

**CVE:** CVE-2025-61144

### Patch fragment

```
for (s = 0; (s < spp) && (s < MAX_SAMPLES); s++)
```

### Candidate signatures

* `s < MAX_SAMPLES`
* `MAX_SAMPLES`
* loop boundary patterns

### Observation

Macro-based signatures such as `MAX_SAMPLES` generate **many archive
matches**, but most are unrelated.

This occurs because macros are frequently reused across projects.

### Insight

Macro identifiers alone are **too general** and must be combined with
additional structural context (loops, conditions, or surrounding code).

---

# Experiment 3 – Input Validation Logic (libvips)

**CVE:** CVE-2026-3147

### Patch fragment

```
if (!g_str_is_ascii(csv->whitespace) || ...)
```

### Candidate signatures

* `g_str_is_ascii`
* validation conditions
* control-flow patterns involving input checks

### Observation

Project-specific API calls (e.g. GLib validation functions) generate
**strong signatures with fewer false positives**.

However, they may fail to match clones outside projects that depend on
the same libraries.

### Insight

API-based signatures are **high precision but low recall**.

---

# Experiment 4 – Path Normalization Logic (rollup)

### Patch fragment

```
while (parts[0] === '.' || parts[0] === '..')
```

### Candidate signatures

* path normalization conditions
* string comparison logic
* array iteration patterns

### Observation

These signatures are **highly project-specific** and produced few
or zero matches in the Debian archive.

### Insight

Some vulnerability fixes rely heavily on **project-specific logic**,
which makes them difficult to detect using simple signature search.

---

# Experiment 5 – Signature Generalization

To improve clone detection, signatures were generalized by replacing
identifiers with abstract tokens.

Example transformation:

```
s < MAX_SAMPLES
```

becomes

```
VAR < CONST
```

or

```
VAR < NUM
```

### Observation

Generalized signatures improve **similarity scoring and ranking**
between candidate fragments.

However, they are **too abstract to be used directly for archive
search queries**, because they produce excessive matches.

### Insight

Generalized signatures are best used **after retrieval**, during
candidate comparison and ranking.

---

# Key Findings

From these experiments, several practical insights emerged:

* Control-flow conditions combined with API calls produce useful signatures.
* Macro identifiers alone generate excessive noise.
* API-based signatures provide strong signals but may lack generality.
* Project-specific identifiers reduce recall across the archive.
* Signature generalization is valuable for **similarity scoring**, not search.

These findings informed the design of the current prototype pipeline.

---

# Next Steps

Future experiments will focus on:

* evaluating signature effectiveness across larger patch datasets
* improving ranking heuristics for candidate clones
* integrating full-file verification for vulnerable patterns
* measuring precision and recall of detected clones

