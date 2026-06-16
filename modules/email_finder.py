import re

import requests


EMAIL_PATTERN = re.compile(
    r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![A-Za-z0-9._%+-])"
)


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
