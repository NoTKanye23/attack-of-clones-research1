# Experiment 3: libvips Input Validation Fix

CVE:
CVE-2026-3147

Project:
libvips

Bug Type:
Missing input validation (ASCII check)

Patch Source:
https://github.com/libvips/libvips/commit/b3ab458a25e0e261cbd1788474bbc763f7435780


Patch Fragment Extracted:

if (!g_str_is_ascii(csv->whitespace) ||
    !g_str_is_ascii(csv->separator)) {
    vips_error("csvload", "%s",
        _("whitespace and separator must be ASCII"));
}


Candidate Signatures Extracted:

g_str_is_ascii
!g_str_is_ascii(
vips_error("csvload"


After Ranking (Strongest Anchors):

g_str_is_ascii
vips_error


Search Platform:
https://codesearch.debian.net


Matches Found:

1 candidate match:

https://codesearch.debian.net/src/ws/websocketconnection.c


Estimated False Positives:
1 potential false positive


Estimated True Positives:
0 confirmed clones


Observation:

The extracted signatures relied on project-specific API calls, particularly:

g_str_is_ascii
vips_error

These API-level tokens acted as strong search anchors and allowed the
system to retrieve at least one candidate match in the Debian archive.
However, the detected file appears to use the same API for unrelated
validation logic rather than replicating the same vulnerability pattern.


Interpretation:

API-level signatures can improve recall by identifying code that uses
similar validation functions. However, project-specific APIs may also
retrieve unrelated code that simply uses the same library functions.


Implication:

Effective patch signature extraction should balance:

- semantic anchors (APIs, constants, macros)
- structural patterns (validation logic or control flow)

Combining both types of signals may improve clone detection accuracy
while reducing unrelated matches.


Key Insight:

Security patches often contain library-specific validation APIs that
act as strong search anchors. However, relying solely on such APIs may
produce unrelated matches. Hybrid signatures combining API usage with
structural patterns are likely to provide more reliable vulnerability
clone detection.
