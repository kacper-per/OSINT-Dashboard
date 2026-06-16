import socket
import ssl


def _name_to_string(name_parts):
    return ", ".join(f"{key}={value}" for group in name_parts for key, value in group)


def fetch_tls_certificate(hostname, timeout=6):
    context = ssl.create_default_context()
    with socket.create_connection((hostname, 443), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as secure_socket:
            certificate = secure_socket.getpeercert()

    sans = [
        value
        for name_type, value in certificate.get("subjectAltName", ())
        if name_type == "DNS"
    ]
    return {
        "hostname": hostname,
        "issuer": _name_to_string(certificate.get("issuer", ())),
        "subject": _name_to_string(certificate.get("subject", ())),
        "not_before": certificate.get("notBefore", ""),
        "not_after": certificate.get("notAfter", ""),
        "san_names": ", ".join(sans),
    }
