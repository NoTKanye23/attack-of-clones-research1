import re
from patch_parser import parse_patch


PRESERVE_TOKENS = {
    "NULL", "nullptr", "malloc", "free", "realloc", "calloc",
    "memcpy", "memset", "strlen", "strcpy", "strcat", "sprintf",
    "fprintf", "printf", "assert", "abort", "exit"
}


# Generic Extractors


def normalize_line(line):
    """Remove extra whitespace and normalize indentation."""
    return re.sub(r'\s+', ' ', line.strip())


def extract_comparisons(line):
    pattern = r'([a-zA-Z0-9_]+)\s*(==|!=|<=|>=|<|>)\s*([a-zA-Z0-9_]+)'
    matches = re.findall(pattern, line)

    sigs = []
    for l, op, r in matches:
        sigs.append(f"{l} {op} {r}")

        # Generalized numeric comparisons
        if r.isdigit():
            sigs.append(f"{l} {op} NUM")

    return sigs


def extract_function_calls(line):
    calls = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', line)

    skip = {"if", "for", "while", "switch", "return", "sizeof"}

    sigs = []
    for c in calls:
        if c not in skip:
            sigs.append(c + "(")

    return sigs


def extract_macros(line):
    return re.findall(r'\b[A-Z_]{4,}\b', line)


def extract_control_flow(line):
    if re.search(r'\b(if|for|while)\s*\(', line):
        return [normalize_line(line)]
    return []


def _line_is_meaningful(line):
    """
    A line is meaningful if it contains a function call, comparison,
    control-flow keyword, or uppercase macro.
    Pure JSON, string literals, closing braces, and version numbers are not.
    """
    if re.search(r'[a-zA-Z_][a-zA-Z0-9_]*\s*\(', line):  # function call
        return True
    if re.search(r'(==|!=|<=|>=|<|>)\s*[a-zA-Z0-9_]', line):  # comparison
        return True
    if re.search(r'\b(if|for|while|return)\b', line):  # control flow
        return True
    if re.search(r'\b[A-Z_]{4,}\b', line):  # uppercase macro
        return True
    return False


def extract_context_pairs(lines):
    pairs = []

    for i in range(len(lines) - 1):
        l1 = normalize_line(lines[i])
        l2 = normalize_line(lines[i + 1])

        if not l1 or not l2:
            continue

        if len(l1) < 3 or len(l2) < 3:
            continue

        if len(l1) > 80 or len(l2) > 80:
            continue

        # At least one line must contain code, not just JSON/metadata
        if not (_line_is_meaningful(l1) or _line_is_meaningful(l2)):
            continue

        pairs.append(f"{l1} | {l2}")

    return pairs


# Language Specific Extractors


def extract_js_signatures(lines):
    sigs = set()

    for line in lines:
        line = normalize_line(line)

        sigs.update(extract_function_calls(line))

        # string literals
        for _, s in re.findall(r'(["\'])(.*?)\1', line):
            if len(s) > 4 and not s.isdigit():
                sigs.add(f'"{s}"')

        if '&&' in line or '||' in line:
            cond = re.sub(r'[a-zA-Z_][a-zA-Z0-9_]*', 'VAR', line)
            sigs.add(cond)

        modules = re.findall(
            r'(?:require|import)\s*\(?\s*[\'"]([^\'"]+)[\'"]',
            line
        )

        for m in modules:
            sigs.add(f"module:{m}")

    return list(sigs)


def extract_go_rust_signatures(lines):
    sigs = set()

    for line in lines:
        line = normalize_line(line)

        sigs.update(extract_function_calls(line))

        for t in re.findall(r'\b[A-Z][a-zA-Z0-9]*\b', line):
            if len(t) > 2 and t not in PRESERVE_TOKENS:
                sigs.add(t)

        sigs.update(extract_comparisons(line))
        sigs.update(extract_control_flow(line))

    return list(sigs)


def extract_c_cpp_inline_signatures(lines):
    sigs = set()

    for line in lines:
        line = normalize_line(line)

        if 'template<' in line:
            sigs.add('template<')

        for c in re.findall(
            r'\b(static|dynamic|const|reinterpret)_cast<', line
        ):
            sigs.add(f"{c}_cast<")

        sigs.update(extract_comparisons(line))

    return list(sigs)



# Dispatcher


def extract_signatures_from_lines(lines, patch_type='generic'):
    sigs = set()

    if patch_type.startswith('js_'):
        sigs.update(extract_js_signatures(lines))

    elif patch_type.startswith('go_') or patch_type.startswith('rust_'):
        sigs.update(extract_go_rust_signatures(lines))

    elif patch_type == 'c_cpp_inline':
        sigs.update(extract_c_cpp_inline_signatures(lines))

    else:
        for line in lines:
            line = normalize_line(line)

            sigs.update(extract_comparisons(line))
            sigs.update(extract_function_calls(line))
            sigs.update(extract_macros(line))
            sigs.update(extract_control_flow(line))

    # context pairs (very important)
    sigs.update(extract_context_pairs(lines))

    return list(sigs)


# Main Entry


def extract_signatures_from_patch(patch_file):

    parsed = parse_patch(patch_file)

    vulnerable_lines = parsed["vulnerable_lines"]
    fix_lines = parsed["fix_lines"]
    patch_type = parsed["patch_type"]

    fix_set = set(fix_lines)

    truly_vulnerable = [
        l for l in vulnerable_lines
        if l not in fix_set
    ]

    return {
        "vulnerable": extract_signatures_from_lines(
            truly_vulnerable, patch_type
        ),
        "fix": extract_signatures_from_lines(
            fix_lines, patch_type
        ),
        "patch_type": patch_type,
        "vulnerable_lines": truly_vulnerable,
        "fix_lines": fix_lines
    }
