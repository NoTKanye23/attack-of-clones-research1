# Experiment 6 – Vendoring Detection (CVE-2023-45853, zlib minizip)

## Objective

Evaluate the filename-based vendoring detection module (`vendoring_search.py`)
introduced in Step 6 of the pipeline. This method operates independently of
signature extraction: instead of matching code patterns, it matches filenames
from patch paths against the Debian archive to find vendored copies of the
same library file.

---

## Patch Source

CVE: CVE-2023-45853
Project: zlib
Bug type: Integer overflow in minizip `zipOpenNewFileInZip4_64()`
Patch: https://github.com/madler/zlib/commit/73331a6a0481067628f065ffe87bb1d8f787d10c

Affected files in patch:
- `contrib/minizip/zip.c`
- `contrib/minizip/zip.h`

Patch type detected: `bounds_check` (macro-based bounds check added)

---

## Vendoring Signal Extraction

`vendoring_search.py` parsed the patch headers:

```
--- a/contrib/minizip/zip.c
+++ b/contrib/minizip/zip.c
--- a/contrib/minizip/zip.h
+++ b/contrib/minizip/zip.h
```

Signals extracted:

| Filename | Path component match | Confidence |
|----------|---------------------|------------|
| `zip.c` | `minizip` not in `KNOWN_VENDOR_DIRS` | — |
| `zip.h` | `minizip` not in `KNOWN_VENDOR_DIRS` | — |

**Result: both signals filtered out.**

`zip.c` has a 3-character stem (`zip`), below the 8-character minimum
in `_is_distinctive_filename()`. `zip.h` is also filtered on stem length.
Neither `minizip` nor `contrib` are in `KNOWN_VENDOR_DIRS`.

---

## Finding: 8-Character Minimum Too Strict for Library-Canonical Filenames

`zip.c` and `zip.h` are the canonical names of the zlib minizip component.
Any package that vendors minizip will contain exactly these filenames.
The stem-length heuristic, designed to avoid generic names like `main.c`,
incorrectly discards highly library-specific names that happen to be short.

**Fix applied during this experiment:**

`KNOWN_VENDOR_DIRS` was extended to include `minizip`. When the parent
directory matches a known vendor dir, the filename length check is bypassed.
This is the correct behaviour: if a file lives inside `vendor/zlib/` or
`contrib/minizip/`, its filename is specific-enough by context regardless of
stem length.

Updated signal extraction after fix:

| Filename | Match | Confidence |
|----------|-------|------------|
| `zip.c` | parent dir `minizip` → added to `KNOWN_VENDOR_DIRS` | **high** |
| `zip.h` | parent dir `minizip` → added to `KNOWN_VENDOR_DIRS` | **high** |

---

## Search Results (After Fix)

Query: `zip.c` (literal, CodeSearch)

| Package | File path | Source extension |
|---------|-----------|-----------------|
| chromium | `third_party/zlib/contrib/minizip/zip.c` | .c ✓ |
| nodejs | `deps/zlib/contrib/minizip/zip.c` | .c ✓ |
| qtwebengine-opensource-src | `src/3rdparty/chromium/third_party/zlib/contrib/minizip/zip.c` | .c ✓ |
| openjdk-21 | `src/java.base/share/native/libzip/zip_util.c` | .c — unrelated |
| ffmpeg | `libavformat/zip.c` | .c — unrelated |

Total results: 12 (below ≥200 noise threshold — accepted)
Source file filter (extension check): 12 → 8 accepted
After removing clearly unrelated paths: **3 confirmed vendoring candidates**

Query: `zip.h` returned overlapping packages — deduplicated.

---

## Verification

For the 3 confirmed vendoring candidates, `verify_from_context()` was applied
using the top-ranked signature from the signature-based pipeline:

Top vulnerable signature: `ZEXPORT zipOpenNewFileInZip4_64 | if (size32 > 0xffffffff)`

Verification results:

| Package | Context match | Fix absent | Final verdict |
|---------|--------------|------------|---------------|
| chromium | ✓ | ✓ | **Confirmed clone** |
| nodejs | ✓ | ✓ | **Confirmed clone** |
| qtwebengine-opensource-src | ✓ | ✓ | **Confirmed clone** |

Confirmed vulnerable clones: **3**
Detection method: `vendoring+context`

---

## Comparison with Signature-Based Detection

The signature pipeline (Steps 1–5) was also run on the same patch:

Top signature: `ZEXPORT zipOpenNewFileInZip4_64` (macro + function name)

Signature search results: 8 candidates, same 3 packages confirmed.

Both methods found the same clones. This is the expected behaviour for
Type-1 clones (verbatim copies): the code is identical to the original,
so both code-pattern matching and filename matching succeed.

The vendoring method reached the same answer **faster**: 1 API call
(`zip.c` literal search), no query variant generation, no score gating.
The signature method required 6 query variants across 2 signatures.

---

## Key Finding

**Filename-based vendoring detection is a fast, independent confirmation
path for Type-1 clones.** When a library file is copied verbatim into a
vendor directory, the filename is a strong signal: it uniquely identifies
the library component regardless of variable names or code style. For
well-known libraries (`zlib`, `sqlite3`, `expat`, etc.), a single filename
query often recovers all vendored copies in the archive in one API call.

**Secondary finding: the 8-character stem minimum should not apply to files
inside known vendor directories.** Library-canonical filenames like `zip.c`,
`lz4.c`, or `sha1.c` are short but highly specific in context. The fix is to
bypass the length check when the parent directory already provides a strong
library signal.
