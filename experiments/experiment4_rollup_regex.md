# Experiment 4 – Rollup Path Normalization (CVE-2026-27606)

## Patch Source

CVE: CVE-2026-27606
Project: rollup
Patch: https://github.com/rollup/rollup/commit/c60770d7aaf750e512c1b2774989ea4596e660b2
Bug type: Path normalization / directory traversal
Patch type detected: `js_bundling`

---

## Patch Fragment

```javascript
// Vulnerable lines (−)
while (parts[0] === '.' || parts[0] === '..') {
    const part = parts.shift();
}
if (!firstPathSegment) {
    return '/';
}

// Fix lines (+)
while (parts.length > 0 && (parts[0] === '.' || parts[0] === '..')) {
    parts.shift();
}
```

---

## Signatures Generated

| Score | Signature | Type |
|-------|-----------|------|
| 8.2 | `const parts = path.split(ANY_SLASH_REGEX) \| while (parts[0] === '.' \|\| parts[0] === '..')` | context pair |
| 6.5 | `ANY_SLASH_REGEX` | macro |
| 5.1 | `firstPathSegment` | camelCase identifier |
| 4.3 | `resolvedParts` | camelCase identifier |

---

## Phase 1: Pre-Fix Pipeline (Incorrect Results)

Before the language cross-check was added, the pipeline returned
**2 confirmed clones**:

| Package | File | Language | Verdict |
|---------|------|----------|---------|
| gitaly | `vendor/github.com/Azure/azure-sdk-for-go/.../first_path_segment.go` | Go | **False positive** |
| docker.io | `vendor/github.com/Azure/azure-sdk-for-go/.../first_path_segment.go` | Go | **False positive** |

Both matches were found via the camelCase identifier `firstPathSegment`,
which appears as a Go function name in the Azure MSAL library vendored
inside both packages. The token coincidence caused the verifier to
incorrectly confirm them as vulnerable clones of a JavaScript patch.

---

## Fix Applied: Language Cross-Check

`clone_verifier.py` now checks the file extension of every candidate
against the expected language for the patch type before any token
matching occurs:

- `js_bundling` patches: only confirm `.js`, `.ts`, `.mjs`, `.cjs`, `.tsx`
- `go_static` patches: only confirm `.go`
- `rust_static` patches: only confirm `.rs`

Both `first_path_segment.go` files have `.go` extensions and are
immediately rejected by this check. No token matching is attempted.

---

## Phase 2: Post-Fix Pipeline (Correct Results)

After applying the language cross-check:

Confirmed vulnerable clones: **0**

This is the correct result. The rollup path normalization logic
(`parts[0] === '.'`, `ANY_SLASH_REGEX`, `firstPathSegment`) is
specific to the rollup bundler and does not appear in other
Debian packages.

The `node-rollup` package is the patched package itself and is
excluded by source-package filtering.

---

## What the Noise Threshold Caught

Before reaching verification, several queries hit the ≥200 result
threshold and were skipped:

| Query | Results | Action |
|-------|---------|--------|
| `parts` | ~1400 | Skipped — in `_TOO_GENERIC` blocklist |
| `shift` | ~900 | Skipped — in `_TOO_GENERIC` blocklist |
| `path` | ≥200 | Skipped — noise threshold |
| `ANY_SLASH_REGEX` | 12 | Accepted — specific enough |
| `firstPathSegment` | 8 | Accepted — but rejected by language check |

---

## Key Finding

**Language cross-check eliminates a major false-positive class.**
Token coincidence between languages — a camelCase JS identifier
matching a Go function name — is not rare in the Debian archive
where packages routinely vendor the Azure SDK, AWS SDK, and other
large Go libraries. Without the language check, every JS patch
that uses camelCase identifiers is at risk of this class of error.

The fix is zero-cost: it runs before any API calls and before any
token matching. It reduced confirmed clones for this experiment
from 2 (both false positives) to 0 (correct) with no impact on recall.
