import requests


def discover_subdomains(domain, timeout=12, user_agent=None):
    """Find domain names in the free crt.sh certificate-transparency feed."""
    response = requests.get(
        "https://crt.sh/",
        params={"q": f"%.{domain}", "output": "json"},
        headers={"User-Agent": user_agent} if user_agent else None,
        timeout=timeout,
    )
    response.raise_for_status()

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
