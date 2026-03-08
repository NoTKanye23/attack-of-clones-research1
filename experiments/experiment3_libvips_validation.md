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

Candidate Signatures:
g_str_is_ascii
!g_str_is_ascii(
vips_error("csvload"

Search Platform:
https://codesearch.debian.net

Matches Found: 0

Estimated False Positives: 0  
Estimated True Positives: 0


Observation:

No matches were found in the Debian archive.

This suggests that validation fixes relying on project-specific APIs
(such as g_str_is_ascii) may not generalize across unrelated codebases.

This result highlights the importance of selecting signatures that
capture generic vulnerability patterns rather than project-specific
implementation details.

Implication:

Signature extraction should prioritize widely reused APIs
or structural code patterns rather than library-specific
functions.
