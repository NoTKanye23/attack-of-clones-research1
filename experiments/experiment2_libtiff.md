# Experiment 2: libtiff Stack Overflow

CVE:
CVE-2025-61144

Project:
libtiff

Bug Type:
Stack overflow due to missing bounds check.

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

Matches Found: 3

Estimated False Positives: 3  
Estimated True Positives: 0


Observation:

The macro MAX_SAMPLES produced several matches in unrelated packages
such as Mesa. This indicates high noise for macro-based signatures.

To reduce noise, we attempted a more specific signature combining the
loop condition:

(s < spp) && (s < MAX_SAMPLES)

This produced significantly fewer matches and improved precision.

This suggests that combining macro tokens with control-flow patterns
may reduce false positives.

### Second Signature Attempt

Combined signature:

(s < spp) && (s < MAX_SAMPLES)

Search Results:

Matches Found: 0

Observation:

The combined signature significantly reduced noise compared to the
macro-only signature. However, no matches were found in the Debian
archive. This suggests that the specific loop-bound fix applied in
libtiff may be relatively unique.
