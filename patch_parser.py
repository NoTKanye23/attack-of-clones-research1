import re

def extract_added_lines(patch_file):
    lines = []

    with open(patch_file) as f:
        for line in f:
            if line.startswith("+") and not line.startswith("+++"):
                cleaned = line[1:].strip()

                if cleaned:
                    lines.append(cleaned)

    return lines


def remove_comments(line):
    line = re.sub(r'//.*', '', line)
    line = re.sub(r'/\*.*?\*/', '', line)
    return line.strip()


def normalize_whitespace(line):
    return re.sub(r'\s+', ' ', line)


def parse_patch(patch_file):
    extracted = extract_added_lines(patch_file)

    cleaned = []
    for line in extracted:
        line = remove_comments(line)
        line = normalize_whitespace(line)

        if line:
            cleaned.append(line)

    return cleaned
