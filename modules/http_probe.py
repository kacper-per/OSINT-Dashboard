import re

import requests


TITLE_PATTERN = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _title_from_html(text):
    match = TITLE_PATTERN.search(text or "")
    if not match:
        return ""
    return " ".join(match.group(1).split())[:300]


def probe_host(hostname, timeout=8, user_agent=None):
    """Try HTTPS first, then HTTP, returning one result per reachable scheme."""
    headers = {"User-Agent": user_agent} if user_agent else {}
    results = []
    errors = []
    https_available = False

    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}"
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=True,
                stream=True,
            )
            https_available = https_available or scheme == "https"
            content_type = response.headers.get("Content-Type", "")
            title = ""
            if "text/html" in content_type.lower():
                response.raw.decode_content = True
                body = response.raw.read(262144, decode_content=True).decode(
                    response.encoding or "utf-8", errors="replace"
                )
                title = _title_from_html(body)
            results.append(
                {
                    "url": url,
                    "status_code": response.status_code,
                    "title": title,
                    "server_header": response.headers.get("Server", ""),
                    "final_url": response.url,
                    "https_available": scheme == "https",
                    "headers": dict(response.headers),
                }
            )
            response.close()
        except requests.RequestException as exc:
            errors.append(f"{url}: {exc}")

    for result in results:
        result["https_available"] = https_available
    return results, errors
