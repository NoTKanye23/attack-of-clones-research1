# Experiment 4: Rollup Path Normalization Vulnerability

Patch Source:
CVE-2026-27606

Repository:
rollup

Bug Type:
Path normalization / directory traversal logic

Patch Link:
https://github.com/rollup/rollup/commit/c60770d7aaf750e512c1b2774989ea4596e660b2

---

## Patch Fragment Extracted

Example fragment extracted from the patch:

```javascript
while (parts[0] === '.' || parts[0] === '..') {
    const part = parts.shift();
}
```

Another relevant fragment:

```javascript
if (!firstPathSegment) {
    return '/';
}
```

These fragments represent logic related to **path normalization and traversal handling**.

---

## Candidate Signatures Generated

The prototype pipeline extracted several structural signatures from the patch.

Examples include:

```
while (parts[0] === '.' || parts[0] === '..')
const parts = path.split(ANY_SLASH_REGEX)
const firstPathSegment = paths.shift()
if (!firstPathSegment)
ANY_SLASH_REGEX
```

Context-pair signatures were also generated, for example:

```
const parts = path.split(ANY_SLASH_REGEX) | while (parts[0] === '.' || parts[0] === '..')
```

These signatures capture both **individual operations and multi-line structural patterns**.

---

## Search Platform

Debian CodeSearch

https://codesearch.debian.net

The prototype uses the Debian CodeSearch API to query the Debian source archive using generated signatures.

---

## Search Results

Total candidate matches retrieved from Debian CodeSearch:
≈ 60 candidate fragments

Example candidate packages identified:

* node-rollup
* docker.io
* gitaly
* symfony
* simplesamlphp

Example matched fragment:

```
tenant, err := firstPathSegment(u)
```

These matches were retrieved using query tokens such as:

```
firstPathSegment
ANY_SLASH_REGEX
resolvedParts
```

---

## Clone Verification

All candidates were passed through the verification stage.

Verification checks:

1. Presence of the vulnerable pattern
2. Absence of the fix pattern
3. Token similarity between the patch and candidate fragment

After verification:

Confirmed vulnerable clones: **0**

---

## Observation

Although several candidate fragments were retrieved, none satisfied the full verification criteria.

The primary reason is that the vulnerability logic relies on **project-specific identifiers**, including:

```
ANY_SLASH_REGEX
firstPathSegment
resolvedParts
```

These identifiers rarely appear in other projects within the Debian archive.

As a result, the extracted signatures are **highly specific to the Rollup codebase**, limiting cross-project clone detection.

---

## Implication

This experiment demonstrates an important limitation of signature-based clone detection.

Highly project-specific identifiers reduce the likelihood of detecting clones across unrelated projects.

Effective vulnerability clone detection therefore requires a combination of:

* token-based signatures
* control-flow signatures
* generalized structural patterns

Balancing **precision and generality** is critical for achieving useful results.

---

## Conclusion

The Rollup experiment highlights a case where the vulnerability is strongly tied to project-specific implementation details.

While the search pipeline successfully retrieved candidate fragments, no confirmed vulnerable clones were identified after verification.

This suggests that additional generalization techniques may be necessary when analyzing patches that rely on project-specific identifiers.

