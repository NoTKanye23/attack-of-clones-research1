import requests
import sys
import re

def search_codesearch(pattern):

    url = "https://codesearch.debian.net/search"

    params = {
        "q": pattern
    }

    headers = {
        "User-Agent": "attack-of-clones-research"
    }

    r = requests.get(url, params=params, headers=headers)

    if r.status_code != 200:
        print("Request failed:", r.status_code)
        return

    html = r.text

    # extract file paths from search results
    matches = re.findall(r'/src/[A-Za-z0-9_\-./]+', html)

    if not matches:
        print("No matches found")
        return

    seen = set()

    print("\nTop matches:\n")

    for m in matches:
        if m not in seen:
            seen.add(m)
            print("https://codesearch.debian.net" + m)

        if len(seen) >= 10:
            break


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python codesearch_query.py <pattern>")
        sys.exit()

    pattern = sys.argv[1]

    search_codesearch(pattern)
