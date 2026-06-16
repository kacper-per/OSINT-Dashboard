import json

import whois


def lookup_whois(domain):
    """Return WHOIS data as readable JSON; registries may redact or omit fields."""
    result = whois.whois(domain)

    def serialize(value):
        if isinstance(value, (list, tuple, set)):
            return [serialize(item) for item in value]
        if hasattr(value, "isoformat"):
            return value.isoformat()
        return str(value) if value is not None else None

    cleaned = {key: serialize(value) for key, value in dict(result).items()}
    return json.dumps(cleaned, indent=2, ensure_ascii=True)
