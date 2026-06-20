import re
from collections import deque
from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin, urlparse

import requests


EMAIL_PATTERN = re.compile(
    r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![A-Za-z0-9._%+-])"
)
SKIPPED_EXTENSIONS = (
    ".7z",
    ".avi",
    ".css",
    ".doc",
    ".docx",
    ".gif",
    ".gz",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".mp3",
    ".mp4",
    ".pdf",
    ".png",
    ".ppt",
    ".pptx",
    ".rar",
    ".svg",
    ".tar",
    ".webp",
    ".xls",
    ".xlsx",
    ".zip",
)


class LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return
        for name, value in attrs:
            if name.lower() == "href" and value:
                self.links.append(value)
                return


def find_homepage_emails(domain, timeout=8, user_agent=None):
    """Inspect only the root-domain homepage; this deliberately does not crawl."""
    headers = {"User-Agent": user_agent} if user_agent else {}
    errors = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            response.raise_for_status()
            emails = {match.lower() for match in EMAIL_PATTERN.findall(response.text)}
            return sorted(emails), response.url, errors
        except requests.RequestException as exc:
            errors.append(f"{url}: {exc}")
    return [], "", errors


def deep_search_emails(domain, timeout=8, user_agent=None, max_pages=100, max_bytes=1048576):
    """Crawl in-scope HTML pages from the root domain and return public emails."""
    headers = {"User-Agent": user_agent} if user_agent else {}
    queue = deque([f"https://{domain}", f"http://{domain}"])
    visited = set()
    emails = {}
    errors = []
    pages_checked = 0

    while queue and pages_checked < max_pages:
        url = _normalize_url(queue.popleft())
        if not url or url in visited or not _is_in_scope(url, domain):
            continue
        visited.add(url)
        if not _is_probably_html_url(url):
            continue

        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=True,
                stream=True,
            )
            response.raise_for_status()
            final_url = _normalize_url(response.url) or url
            if not _is_in_scope(final_url, domain):
                response.close()
                continue

            content_type = response.headers.get("Content-Type", "")
            if not _is_html_content(content_type):
                response.close()
                continue

            response.raw.decode_content = True
            body = response.raw.read(max_bytes, decode_content=True).decode(
                response.encoding or "utf-8",
                errors="replace",
            )
            response.close()
        except requests.RequestException as exc:
            errors.append(f"{url}: {exc}")
            continue

        pages_checked += 1
        for email in _extract_emails(body):
            emails.setdefault(email, final_url)

        for link in _extract_links(body):
            next_url = _normalize_url(urljoin(final_url, link))
            if (
                next_url
                and next_url not in visited
                and _is_in_scope(next_url, domain)
                and _is_probably_html_url(next_url)
            ):
                queue.append(next_url)

    return (
        [{"email": email, "source": source} for email, source in sorted(emails.items())],
        {"pages_checked": pages_checked, "errors": errors},
    )


def _extract_emails(text):
    return {match.lower() for match in EMAIL_PATTERN.findall(text or "")}


def _extract_links(text):
    parser = LinkExtractor()
    parser.feed(text or "")
    return parser.links


def _normalize_url(url):
    if not url:
        return ""
    url, _fragment = urldefrag(url.strip())
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return parsed._replace(fragment="").geturl()


def _is_in_scope(url, domain):
    hostname = (urlparse(url).hostname or "").lower().rstrip(".")
    domain = domain.lower().rstrip(".")
    return hostname == domain or hostname.endswith(f".{domain}")


def _is_probably_html_url(url):
    path = urlparse(url).path.lower()
    return not path.endswith(SKIPPED_EXTENSIONS)


def _is_html_content(content_type):
    lowered = content_type.lower()
    return not lowered or "text/html" in lowered or "application/xhtml+xml" in lowered
