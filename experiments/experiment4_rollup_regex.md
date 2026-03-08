# Experiment 4: Rollup Regex Vulnerability

Patch Source:
CVE-2026-27606

Repository:
rollup

Bug Type:
Regular expression vulnerability

Patch Link:
https://github.com/rollup/rollup/commit/c60770d7aaf750e512c1b2774989ea4596e660b2

Patch Fragment Extracted:
<insert line extracted from patch>

Candidate Signatures:
regex
function name
API call

Search Platform:
https://codesearch.debian.net

Matches Found:
<list results returned by codesearch>

Observation:
Regex-related signatures produced several matches but also
introduced noise due to common regex handling patterns in
JavaScript tooling.

The extracted identifiers (FILE_NAME_OUTSIDE_OUTPUT_DIRECTORY,
ANY_SLASH_REGEX) are highly project-specific and do not appear
in other Debian packages.

This results in zero matches in Debian Code Search.

This experiment highlights a limitation of token-based
signatures: they may be overly specific and fail to detect
similar vulnerabilities across unrelated codebases.

Future work could attempt to extract more generalized
patterns such as path normalization logic or control-flow
structures instead of project-specific identifiers.

This suggests that an effective clone detection pipeline should
combine multiple signature types (tokens, control-flow patterns,
and API usage) and rank them by their generality to balance
precision and recall.
