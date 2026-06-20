import whois


def lookup_whois(domain):
    """Return the raw WHOIS response; registries may redact or omit fields."""
    result = whois.whois(domain, inc_raw=True)
    if hasattr(result, "get"):
        raw_text = result.get("raw")
        if raw_text:
            return raw_text
    return str(result)
