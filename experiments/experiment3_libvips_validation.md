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

Matches Found:
(To be tested)

Observation:
API-based signatures such as g_str_is_ascii are more
specific than macro-based tokens but may still appear
in unrelated validation code across other packages.

Further filtering may be needed to distinguish
security-relevant clones from benign validation logic.
