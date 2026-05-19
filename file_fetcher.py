import requests
 
 
BASE_URL = "https://sources.debian.org/src"
HEADERS = {"User-Agent": "attack-of-clones-research"}
TIMEOUT = 15
 
 
def build_raw_url(package, version, path):
    """
    Construct a raw file URL for sources.debian.org.
    """
    return f"{BASE_URL}/{package}/{version}/{path}/raw/"
 
 
def split_package(package_field):
    """
    Convert "mesa_26.0.1-2" -> ("mesa", "26.0.1-2")
    Convert "erlang_1:27.3.4.11+dfsg-3" -> ("erlang", "27.3.4.11+dfsg-3")
    Strips Debian epoch prefix (e.g. "1:") from version.
    """
    if "_" not in package_field:
        return None, None
 
    name, version = package_field.rsplit("_", 1)
    # Strip epoch (e.g. "1:27.3.4.11+dfsg-3" -> "27.3.4.11+dfsg-3")
    if ":" in version:
        version = version.split(":", 1)[1]
    return name, version
 
 
def normalize_path(path):
    """
    Some CodeSearch paths start with the package directory.
    Example:
        i3bar/src/xcb.c
    or:
        src/xcb.c
    """
    parts = path.split("/")
 
    if len(parts) > 1 and parts[0] != "src":
        return "/".join(parts[1:])
 
    return path
 
 
def fetch_source_file(result_dict):
    """
    Fetch raw source file from sources.debian.org
    using Debian CodeSearch result fields.
    """
    package_field = result_dict.get("package")
    path = result_dict.get("path")
 
    if not package_field or not path:
        return None
 
    pkg_name, pkg_version = split_package(package_field)
 
    if not pkg_name:
        return None
 
    file_path = normalize_path(path)
    url = build_raw_url(pkg_name, pkg_version, file_path)
 
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
 
        if r.status_code != 200:
            # Fallback: try without /raw/ suffix (some versions use different URL)
            url_alt = url.rstrip('/').rsplit('/raw', 1)[0]
            if url_alt != url:
                r = requests.get(url_alt + '/raw/', headers=HEADERS, timeout=TIMEOUT)
            if r.status_code != 200:
                return None
 
        text = r.text
 
        if len(text) > 500000:
            return None
 
        return text
 
    except requests.exceptions.RequestException:
        return None
