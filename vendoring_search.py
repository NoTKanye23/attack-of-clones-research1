import os
import re

# Well-known vendored library directory names found in Debian packages.
KNOWN_VENDOR_DIRS = {
    "zlib", "libpng", "libjpeg", "expat", "openssl", "libssl",
    "sqlite", "sqlite3", "lz4", "lzma", "xz", "bzip2", "zstd",
    "pcre", "pcre2", "libffi", "libuv", "libevent", "libcurl",
    "libtiff", "libwebp", "libvpx", "libopus", "libvorbis",
    "jansson", "cjson", "yajl", "rapidjson", "nlohmann",
    "mbedtls", "wolfssl", "botan",
    "minizip",
    "lodash", "underscore", "moment", "axios", "node-fetch",
    "rollup", "webpack", "esbuild", "parcel",
    "vendor",
    "third_party", "third-party", "thirdparty",
    "bundled", "embedded", "external", "ext",
    "deps", "dependencies",
}

# Known library source filenames that are distinctive even when short (e.g., crc32.c)
KNOWN_LIBRARY_FILES = {
    "crc32", "inflate", "deflate", "trees", "zutil", "adler32",
    "compress", "uncompr", "gzio", "crc32_combine", "crc32_combine64",
    "x2nmodp", "multmodp",
}

# For known library filenames, filter results to paths that contain
# a library-related directory segment.  This cuts 2141 crc32.c results
# down to the ~20 that actually live inside a vendored zlib copy.
KNOWN_LIBRARY_PATH_HINTS = {
    # stem -> list of path segments that indicate vendoring
    "crc32":        ["zlib", "zlib-src", "gzip", "libz"],
    "inflate":      ["zlib", "zlib-src", "gzip", "libz"],
    "deflate":      ["zlib", "zlib-src", "gzip", "libz"],
    "adler32":      ["zlib", "zlib-src", "gzip", "libz"],
    "trees":        ["zlib", "zlib-src", "libz"],
    "compress":     ["zlib", "zlib-src", "libz"],
    "zip":          ["minizip", "zlib"],
    "inflate":      ["zlib", "zlib-src"],
    "sha256":       ["sha2", "openssl", "libssl", "crypto"],
    "sha1":         ["sha1", "openssl", "libssl", "crypto"],
    "md5":          ["md5", "openssl", "libssl", "crypto"],
    "aes":          ["aes", "openssl", "mbedtls", "wolfssl"],
    "sqlite3":      ["sqlite", "sqlite3"],
    "expat":        ["expat", "libexpat"],
    "pcre":         ["pcre", "pcre2"],
}


def filter_results_by_path_hint(results: list, stem: str) -> list:
    """
    If stem has known path hints, return only results where the path
    contains at least one of the hint segments.
    If no hints exist, return all results unmodified.
    """
    hints = KNOWN_LIBRARY_PATH_HINTS.get(stem.lower(), [])
    if not hints:
        return results
    filtered = []
    for r in results:
        path = r.get("path", "").lower()
        if any(h in path for h in hints):
            filtered.append(r)
    if filtered:
        return filtered
    # If path filtering removes everything (conservative), return originals
    # so we don't silently drop genuine results from unusual vendoring paths
    return results


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
    """
    signals = []
    seen_queries = set()

    try:
        with open(patch_file, "r", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return signals

    for line in lines:
        if not (line.startswith("--- ") or line.startswith("+++ ")):
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        raw_path = parts[1]
        if raw_path.startswith(("a/", "b/")):
            raw_path = raw_path[2:]

        if raw_path == "/dev/null":
            continue

        filename = os.path.basename(raw_path)
        if not filename or filename in _SKIP_FILENAMES:
            continue

        path_parts = raw_path.lower().replace("\\", "/").split("/")

        library_hint = None
        for part in path_parts[:-1]:
            if part in KNOWN_VENDOR_DIRS:
                library_hint = part
                break

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
                "query": query,
                "library": library_hint,
                "source_file": filename,
                "confidence": "high",
            })
        else:
            if _is_distinctive_filename(filename):
                signals.append({
                    "query": query,
                    "library": None,
                    "source_file": filename,
                    "confidence": "medium",
                })

    return signals


def _is_distinctive_filename(filename: str) -> bool:
    """
    Return True if a filename is specific enough to use as a literal
    CodeSearch query and likely to return only a small set of results
    """
    code_extensions = {
        ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp",
        ".go", ".rs", ".py", ".js", ".ts",
    }
    stem, ext = os.path.splitext(filename)
    if ext.lower() not in code_extensions:
        return False

    if len(stem) < 8:
        return stem in KNOWN_LIBRARY_FILES

    generic_stems = {
        "main", "util", "utils", "common", "string", "memory",
        "test", "debug", "error", "types", "config", "init",
        "io", "net", "hash", "list", "queue", "stack",
        "buffer", "socket", "thread", "mutex", "signal",
        "bundle", "index", "module", "webpack", "rollup",
        "vite", "esbuild", "parcel", "tsconfig",
        "_config", "gulpfile", "gruntfile", "makefile",
    }
    if stem.lower() in generic_stems:
        return False
    if stem.startswith("_"):
        return False
    return True


def vendoring_signals_to_queries(signals: list[dict]) -> list[str]:
    return [s["query"] for s in signals]
