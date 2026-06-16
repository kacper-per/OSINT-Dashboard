SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)


def inspect_headers(url, response_headers):
    normalized = {key.lower(): value for key, value in response_headers.items()}
    return [
        {
            "url": url,
            "header_name": header,
            "header_value": normalized.get(header.lower(), ""),
            "present": header.lower() in normalized,
        }
        for header in SECURITY_HEADERS
    ]
