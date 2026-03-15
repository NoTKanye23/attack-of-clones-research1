# Experiment 3 – libvips Input Validation Vulnerability

## Patch Source

CVE:
CVE-2026-3147

Project:
libvips

Patch Link:
https://github.com/libvips/libvips/commit/b3ab458a25e0e261cbd1788474bbc763f7435780

Bug Type:
Missing input validation (ASCII validation check)

---

## Methodology

This experiment evaluates whether validation logic introduced by a security patch can be used to discover similar code fragments across the Debian archive.

The prototype pipeline performs the following steps:

1. Parse the security patch and extract vulnerable and fix fragments
2. Generate candidate vulnerability signatures from the patch
3. Filter noisy or trivial signatures
4. Rank signatures by structural importance
5. Query the Debian CodeSearch archive
6. Inspect and verify candidate matches

---

## Patch Fragment Extracted

The patch introduces validation checks ensuring that CSV parsing parameters contain only ASCII characters.

Example fragment extracted from the patch:

```c
if (!g_str_is_ascii(csv->whitespace) ||
    !g_str_is_ascii(csv->separator)) {
    vips_error("csvload", "%s",
        _("whitespace and separator must be ASCII"));
}
```

This code ensures that invalid character encodings cannot propagate into CSV parsing logic.

---

## Candidate Signatures

The prototype pipeline extracted several candidate signatures from the patch:

```
g_str_is_ascii
!g_str_is_ascii(
vips_error("csvload"
```

After ranking and filtering, the strongest anchors were:

```
g_str_is_ascii
vips_error
```

These identifiers represent **project-specific validation APIs** used within libvips.

---

## CodeSearch Experiments

Search platform:

https://codesearch.debian.net

Example query used:

```
g_str_is_ascii
```

---

## Results

Number of candidate matches retrieved: **1**

Example match:

https://codesearch.debian.net/src/ws/websocketconnection.c

Manual classification:

Estimated false positives: **1**
Estimated true positives: **0**

The candidate match used the same API but did not replicate the same vulnerability pattern.

---

## Observation

The extracted signatures rely heavily on project-specific API calls, particularly:

```
g_str_is_ascii
vips_error
```

These API-level tokens serve as strong search anchors and successfully retrieved candidate matches.

However, the matched code used the same API for unrelated validation logic rather than replicating the vulnerable behavior.

---

## Interpretation

API-level signatures improve recall by locating code that uses similar validation functions.

However, project-specific APIs may also retrieve unrelated code that simply uses the same library functionality.

This highlights the limitation of relying solely on API identifiers for vulnerability clone detection.

---

## Implication

Effective vulnerability clone detection requires balancing multiple signal types, including:

* semantic anchors (APIs, constants, macros)
* structural patterns (validation logic and control-flow conditions)

Combining these signals may reduce unrelated matches while preserving useful candidate results.

---

## Conclusion

This experiment demonstrates that **API-based signatures can successfully retrieve related code fragments across the Debian archive**.

However, API-level matches alone may produce unrelated results.

More reliable clone detection can be achieved by combining:

* API usage patterns
* structural validation logic
* contextual code fragments

Such hybrid signatures are likely to provide more accurate vulnerability clone detection across large software repositories.

