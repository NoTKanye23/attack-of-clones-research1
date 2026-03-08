import requests
import re


def clean_query(q):
    """
    Preserve regex operators but remove problematic characters.
    """
    q = re.sub(r'[^\w\s<>=!().|*+-]', ' ', q)
    return re.sub(r'\s+', ' ', q).strip()


def search_codesearch(pattern):

    pattern = clean_query(pattern)

    url = "https://codesearch.debian.net/search"

    params = {"q": pattern}

    headers = {"User-Agent": "attack-of-clones-research"}

    r = requests.get(url, params=params, headers=headers)

    if r.status_code != 200:
        print("Request failed:", r.status_code)
        return []

    html = r.text

    matches = re.findall(r'/src/[A-Za-z0-9_\-./]+', html)

    if not matches:
        print("No matches found")
        return []

    seen = set()
    results = []

    print("\nTop matches:\n")

    for m in matches:

        url = "https://codesearch.debian.net" + m

        if url not in seen:
            seen.add(url)
            results.append(url)
            print(url)

        if len(results) >= 10:
            break

    return results
