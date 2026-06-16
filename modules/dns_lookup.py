import dns.exception
import dns.resolver


RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")


def lookup_dns(domain, timeout=8):
    """Return public DNS records for a domain without attempting zone transfers."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    records = []
    errors = []

    for record_type in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, record_type, raise_on_no_answer=False)
            for answer in answers:
                records.append(
                    {
                        "record_type": record_type,
                        "name": domain,
                        "value": answer.to_text().rstrip("."),
                        "source": "DNS",
                    }
                )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except (dns.resolver.NoNameservers, dns.exception.Timeout, dns.exception.DNSException) as exc:
            errors.append(f"{record_type}: {exc}")

    unique = {
        (item["record_type"], item["name"], item["value"]): item for item in records
    }
    return list(unique.values()), errors
