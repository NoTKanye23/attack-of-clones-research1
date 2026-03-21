import os
import re

# Well-known vendored library directory names found in Debian packages.
# When one of these appears in a patch path, it strongly indicates vendoring.
# The search query becomes: filename.c  (specific enough, ~few dozen results)
KNOWN_VENDOR_DIRS = {
    # C/C++ libraries commonly vendored
    "zlib", "libpng", "libjpeg", "expat", "openssl", "libssl",
    "sqlite", "sqlite3", "lz4", "lzma", "xz", "bzip2", "zstd",
    "pcre", "pcre2", "libffi", "libuv", "libevent", "libcurl",
    "libtiff", "libwebp", "libvpx", "libopus", "libvorbis",
    "jansson", "cjson", "yajl", "rapidjson", "nlohmann",
    "mbedtls", "wolfssl", "botan",
    # JS/Node libraries
    "lodash", "underscore", "moment", "axios", "node-fetch",
    "rollup", "webpack", "esbuild", "parcel",
    # Go/Rust vendored modules
    "vendor",  # Go modules vendor directory
    # Generic vendoring directory names
    "third_party", "third-party", "thirdparty",
    "bundled", "embedded", "external", "ext",
    "deps", "dependencies",
}

# Generic filename suffixes that are too common to be useful on their own.
# These appear in thousands of packages — skip them as standalone queries.
_SKIP_FILENAMES = {
    "main.c", "main.cpp", "main.go", "main.rs",
    "utils.c", "util.c", "utils.cpp",
    "test.c", "test.cpp",
    "Makefile", "CMakeLists.txt",
    "config.h", "config.c",
    "types.h", "types.c",
    "common.h", "common.c",
    "string.c", "string.h",
    "memory.c", "memory.h",
}


def extract_vendoring_signals(patch_file: str) -> list[dict]:
    """
    Parse a patch file's --- / +++ headers and extract vendoring search signals.

    Returns a list of dicts:
        {
            "query":       "inflate.c",        # CodeSearch literal query
            "library":     "zlib",             # library hint (for context/logging)
            "source_file": "inflate.c",        # filename
            "confidence":  "high" | "medium",  # high = known vendor dir
        }

    High confidence: path contains a known vendor directory name
    Medium confidence: filename is distinctive enough on its own
    """
    signals = []
    seen_queries = set()

    try:
        with open(patch_file, "r", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return signals

    for line in lines:
        # Only look at diff path headers
        if not (line.startswith("--- ") or line.startswith("+++ ")):
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        raw_path = parts[1]
        # Strip a/ b/ git prefixes
        if raw_path.startswith(("a/", "b/")):
            raw_path = raw_path[2:]

        # Skip /dev/null (new files with no original)
        if raw_path == "/dev/null":
            continue

        filename = os.path.basename(raw_path)
        if not filename or filename in _SKIP_FILENAMES:
            continue

        path_parts = raw_path.lower().replace("\\", "/").split("/")

        # Check for known vendor directory names in the path
        library_hint = None
        for part in path_parts[:-1]:   # exclude the filename itself
            if part in KNOWN_VENDOR_DIRS:
                library_hint = part
                break

        # Also check the directory immediately containing the file —
        # e.g. "src/zlib/inflate.c" → library_hint = "zlib"
        if not library_hint and len(path_parts) >= 2:
            parent_dir = path_parts[-2]
            if parent_dir in KNOWN_VENDOR_DIRS:
                library_hint = parent_dir

        query = filename
        if query in seen_queries:
            continue
        seen_queries.add(query)

        if library_hint:
            signals.append({
                "query":       query,
                "library":     library_hint,
                "source_file": filename,
                "confidence":  "high",
            })
        else:
            # Medium confidence: filename is specific enough on its own
            # Only include if it looks like a real source file with a
            # distinctive enough name (not too generic)
            if _is_distinctive_filename(filename):
                signals.append({
                    "query":       query,
                    "library":     None,
                    "source_file": filename,
                    "confidence":  "medium",
                })

    return signals


def _is_distinctive_filename(filename: str) -> bool:
    """
    Return True if a filename is specific enough to use as a literal
    CodeSearch query and likely to return only a small set of results.

    Criteria:
    - Source file (has a recognised code extension)
    - Not in the skip list
    - Stem is at least 8 characters (shorter names are too common)
    - Not a generic framework/tooling name
    """
    code_extensions = {
        ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp",
        ".go", ".rs", ".py", ".js", ".ts",
    }
    stem, ext = os.path.splitext(filename)
    if ext.lower() not in code_extensions:
        return False
    if len(stem) < 8:
        return False
    # Reject overly generic stems — including common framework file names
    generic_stems = {
        # C/system generics
        "main", "util", "utils", "common", "string", "memory",
        "test", "debug", "error", "types", "config", "init",
        "io", "net", "hash", "list", "queue", "stack",
        "buffer", "socket", "thread", "mutex", "signal",
        # JS/TS framework generics
        "bundle", "index", "module", "webpack", "rollup",
        "vite", "esbuild", "parcel", "tsconfig",
        # Config/build
        "_config", "gulpfile", "gruntfile", "makefile",
    }
    if stem.lower() in generic_stems:
        return False
    # Reject names starting with _ (private/config convention — usually generic)
    if stem.startswith("_"):
        return False
    return True


def vendoring_signals_to_queries(signals: list[dict]) -> list[str]:
    """
    Convert vendoring signals to CodeSearch query strings.

    For high-confidence signals (known vendor dir): search for the filename
    directly — it will return only packages that contain that specific file.

    Example: "inflate.c" → finds all Debian packages with an inflate.c file,
    which are likely vendored copies of zlib.
    """
    return [s["query"] for s in signals]
