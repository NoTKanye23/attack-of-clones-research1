LIBRARY_FUNCTION_TOKENS = {
 
    # -----------------------------------------------------------------------
    # zlib — crc32.c
    # CVE-2026-27171: crc32_combine64/crc32_combine_gen64 missing negative check
    # CVE-2023-45853: minizip zipOpenNewFileInZip4_64 integer overflow
    # -----------------------------------------------------------------------
    "crc32": {
        "*": [
            # x2nmodp and multmodp are zlib-internal static helpers.
            # They appear in EVERY copy of zlib's crc32.c and virtually nowhere else.
            ("x2nmodp",  "c", "crc32"),
            ("multmodp", "c", "crc32"),
        ],
        "crc32_combine64": [
            ("x2nmodp",  "c", "crc32"),
            ("multmodp", "c", "crc32"),
            ("crc32_combine_gen64", "c", None),
        ],
        "crc32_combine_gen64": [
            ("x2nmodp",  "c", "crc32"),
            ("crc32_combine_gen64", "c", None),
        ],
    },
 
    # -----------------------------------------------------------------------
    # zlib — inflate.c
    # -----------------------------------------------------------------------
    "inflate": {
        "*": [
            ("inflate_fast", "c", "inflate"),
            ("NEEDBITS",     "c", "inflate"),
        ],
        "inflate": [
            ("inflate_fast", "c", "inflate"),
            ("PULLBYTE",     "c", "inflate"),
        ],
    },
 
    # -----------------------------------------------------------------------
    # zlib — deflate.c
    # -----------------------------------------------------------------------
    "deflate": {
        "*": [
            ("longest_match",  "c", "deflate"),
            ("INSERT_STRING",  "c", "deflate"),
        ],
    },
 
    # -----------------------------------------------------------------------
    # zlib — adler32.c
    # -----------------------------------------------------------------------
    "adler32": {
        "*": [
            ("adler32_combine", "c", "adler32"),
            ("BASE",            "c", "adler32"),  # BASE is adler32-specific
        ],
    },
 
    # -----------------------------------------------------------------------
    # minizip (part of zlib contrib/)
    # CVE-2023-45853: zipOpenNewFileInZip4_64
    # -----------------------------------------------------------------------
    "zip": {
        "*": [
            ("zipOpenNewFileInZip4_64", "c", None),
            ("ZEXPORT",                "c", "minizip"),
        ],
        "zipOpenNewFileInZip4_64": [
            ("zipOpenNewFileInZip4_64", "c", None),
        ],
    },
    "unzip": {
        "*": [
            ("unzGetCurrentFileInfo64", "c", None),
        ],
    },
 
    # -----------------------------------------------------------------------
    # expat — xmlparse.c
    # -----------------------------------------------------------------------
    "xmlparse": {
        "*": [
            ("XML_ErrorString",  "c", "expat"),
            ("XML_ParseBuffer",  "c", "expat"),
        ],
    },
 
    # -----------------------------------------------------------------------
    # libpng — pngwrite.c, pngread.c
    # -----------------------------------------------------------------------
    "pngwrite": {
        "*": [
            ("png_write_image",  "c", "libpng"),
            ("png_write_chunk",  "c", "libpng"),
        ],
    },
    "pngread": {
        "*": [
            ("png_read_image",   "c", "libpng"),
        ],
    },
 
    # -----------------------------------------------------------------------
    # sqlite3 — sqlite3.c (amalgamation)
    # -----------------------------------------------------------------------
    "sqlite3": {
        "*": [
            ("sqlite3_exec",    "c", "sqlite"),
            ("sqlite3_prepare", "c", "sqlite"),
        ],
    },
 
    # -----------------------------------------------------------------------
    # OpenSSL — sha256.c, aes.c
    # -----------------------------------------------------------------------
    "sha256": {
        "*": [
            ("SHA256_Update", "c", "openssl"),
            ("SHA256_Final",  "c", "openssl"),
        ],
    },
    "aes": {
        "*": [
            ("AES_encrypt", "c", "openssl"),
        ],
    },
 
    # -----------------------------------------------------------------------
    # pcre2 — pcre2_compile.c, pcre2_match.c
    # -----------------------------------------------------------------------
    "pcre2_compile": {
        "*": [
            ("pcre2_compile", "c", "pcre"),
        ],
    },
    "pcre2_match": {
        "*": [
            ("pcre2_match", "c", "pcre"),
        ],
    },
}
 
 
def get_library_tokens(filename_stem: str,
                       function_name: str = None) -> list:
    """
    Return a list of (token, filetype, path_hint) tuples for the given
    filename stem and optional function name.
 
    Merges wildcard ('*') entries with function-specific entries.
    Returns an empty list if no tokens are known.
 
    Args:
        filename_stem:  stem of the patched filename, e.g. 'crc32'
        function_name:  name of the changed function, e.g. 'crc32_combine64'
                        If None, returns only wildcard tokens.
 
    Returns:
        List of (token, filetype, path_hint) tuples, deduplicated.
    """
    stem = filename_stem.lower()
    fn_map = LIBRARY_FUNCTION_TOKENS.get(stem, {})
    if not fn_map:
        return []
 
    seen = set()
    result = []
 
    # Wildcard tokens always apply
    for entry in fn_map.get("*", []):
        key = entry[0]
        if key not in seen:
            seen.add(key)
            result.append(entry)
 
    # Function-specific tokens
    if function_name:
        for entry in fn_map.get(function_name, []):
            key = entry[0]
            if key not in seen:
                seen.add(key)
                result.append(entry)
 
    return result
 
 
def get_function_names_from_patch(patch_file: str) -> list:
    """
    Extract function names from the unified diff's hunk headers.
    The hunk header format is: @@ -a,b +c,d @@ function_name
    This is populated by git diff -p (the default) for C files.
 
    Returns a list of function name strings (may be empty for non-C files
    or if git didn't include the function name).
    """
    import re
    names = []
    seen = set()
    try:
        with open(patch_file, "r", errors="ignore") as f:
            for line in f:
                if line.startswith("@@"):
                    # @@ -a,b +c,d @@ optional_function_name
                    m = re.match(r'^@@[^@]+@@\s+(.*)', line)
                    if m:
                        name = m.group(1).strip()
                        # Extract just the function name (strip return type etc.)
                        # In C, git usually puts just the enclosing function name
                        # e.g. "crc32_combine64" or "uLong crc32_combine64(..."
                        fn_match = re.search(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', name)
                        if fn_match:
                            fn = fn_match.group(1)
                            if fn not in seen and fn not in {
                                "if","for","while","return","else","switch"
                            }:
                                seen.add(fn)
                                names.append(fn)
    except OSError:
        pass
    return names
