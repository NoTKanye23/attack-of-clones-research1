# Experiment 2: libtiff Stack Overflow# Experiment 2: Stack Overflow Detection from Security Patch

CVE:
CVE-2025-61144

Project:
libtiff

Vulnerability Type:
Stack overflow caused by missing bounds check in loop iteration.

Patch Source:
https://gitlab.com/libtiff/libtiff/-/commit/88cf9dbb48f6e172629795ecffae35d5052f68aa

Patch Fragment Extracted:
for (s = 0; (s < spp) && (s < MAX_SAMPLES); s++)

Candidate Signatures:
MAX_SAMPLES
s < spp
for (s = 0

Search Platform:
https://codesearch.debian.net

Matches Found:
mesa_26.0.1-2/src/gallium/drivers/llvmpipe/lp_state_fs.c
mesa_26.0.1-2/src/gallium/drivers/llvmpipe/lp_state_fs.h
mesa_26.0.1-2/src/gallium/drivers/llvmpipe/lp_setup_context.h

Observation:
Token-level signatures such as "MAX_SAMPLES" generate matches in unrelated
projects (e.g., Mesa). This indicates that simple lexical signatures
introduce significant noise.

More precise signatures based on control-flow structure or semantic
patterns (e.g., loop bounds checks) may improve detection accuracy.

Patch Source:
CVE-2025-61144

Repository:
libtiff

Bug Type:
Stack overflow

Patch Fragment Extracted:
for (s = 0; (s < spp) && (s < MAX_SAMPLES); s++)

Candidate Signatures:
MAX_SAMPLES
s < spp
for (s = 0

Search Platform:
https://codesearch.debian.net

Matches Found:
mesa_26.0.1-2/src/gallium/drivers/llvmpipe/lp_state_fs.c
mesa_26.0.1-2/src/gallium/drivers/llvmpipe/lp_state_fs.h
mesa_26.0.1-2/src/gallium/drivers/llvmpipe/lp_setup_context.h

Observation:
Macro-based signatures like MAX_SAMPLES produce matches in unrelated
packages such as Mesa. This suggests that simple token-level signatures
can introduce noise. More contextual signatures (control-flow patterns
or API combinations) may improve detection precision

Observation

Full-line regex signatures extracted directly from patches
are often too specific and may fail to match similar code
in other packages. Token-level signatures such as macro
names (e.g. MAX_SAMPLES) produce broader matches but also
increase noise.

This suggests the need for a multi-level signature system
combining:
- control-flow patterns
- API usage
- macro tokens
