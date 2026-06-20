import time

import requests


TRANSIENT_STATUS_CODES = {429, 502, 503, 504}


def discover_subdomains(
    domain,
    timeout=30,
    user_agent=None,
    retries=2,
    retry_delay=1,
    backoff_factor=2,
    max_timeout=120,
):
    """Find domain names in the free crt.sh certificate-transparency feed."""
    response = None
    headers = {"User-Agent": user_agent} if user_agent else None
    attempts = retries + 1
    attempt_notes = []

    for attempt in range(attempts):
        attempt_timeout = min(timeout * (backoff_factor**attempt), max_timeout)
        attempt_label = f"attempt {attempt + 1}/{attempts}, timeout={attempt_timeout:g}s"
        try:
            response = requests.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
                headers=headers,
                timeout=attempt_timeout,
            )
            if response.status_code in TRANSIENT_STATUS_CODES and attempt < retries:
                attempt_notes.append(f"{attempt_label}: HTTP {response.status_code}")
                time.sleep(retry_delay)
                continue
            response.raise_for_status()
            break
        except requests.RequestException as exc:
            attempt_notes.append(f"{attempt_label}: {exc}")
            if attempt < retries:
                time.sleep(retry_delay)
                continue
            details = "\n".join(attempt_notes)
            raise RuntimeError(f"crt.sh failed after {attempts} attempts:\n{details}") from exc

    if response is None:
        raise RuntimeError("crt.sh failed before receiving a response")

    suffix = f".{domain.lower()}"
    names = set()
    for entry in response.json():
        for name in entry.get("name_value", "").splitlines():
            clean = name.strip().lower().rstrip(".")
            if clean.startswith("*."):
                clean = clean[2:]
            if clean == domain.lower() or clean.endswith(suffix):
                names.add(clean)
    names.discard(domain.lower())
    return sorted(names)
