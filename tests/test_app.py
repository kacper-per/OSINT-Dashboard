from pathlib import Path

import pytest

import database
from app import create_app
from modules import (
    crtsh_lookup,
    dns_lookup,
    email_finder,
    http_probe,
    tls_info,
    whois_lookup,
)


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(
        dns_lookup,
        "lookup_dns",
        lambda domain, timeout: (
            [{"record_type": "A", "name": domain, "value": "192.0.2.10", "source": "DNS"}],
            [],
        ),
    )
    monkeypatch.setattr(
        crtsh_lookup,
        "discover_subdomains",
        lambda domain, timeout, user_agent: [f"www.{domain}"],
    )
    monkeypatch.setattr(
        http_probe,
        "probe_host",
        lambda host, timeout, user_agent: (
            [
                {
                    "url": f"https://{host}",
                    "status_code": 200,
                    "title": "Example",
                    "server_header": "test-server",
                    "final_url": f"https://{host}/",
                    "https_available": True,
                    "headers": {"Content-Security-Policy": "default-src 'self'"},
                }
            ],
            [],
        ),
    )
    monkeypatch.setattr(whois_lookup, "lookup_whois", lambda domain: '{"domain_name": "example.com"}')
    monkeypatch.setattr(
        tls_info,
        "fetch_tls_certificate",
        lambda host, timeout: {
            "hostname": host,
            "issuer": "Test CA",
            "subject": host,
            "not_before": "Jan 1 00:00:00 2026 GMT",
            "not_after": "Jan 1 00:00:00 2027 GMT",
            "san_names": host,
        },
    )
    monkeypatch.setattr(
        email_finder,
        "find_homepage_emails",
        lambda domain, timeout, user_agent: (["hello@example.com"], f"https://{domain}/", []),
    )

    return create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test",
            "DATABASE_PATH": tmp_path / "test.db",
            "REPORTS_DIR": tmp_path / "reports",
            "MAX_SUBDOMAINS_TO_PROBE": 5,
        }
    )


@pytest.fixture()
def client(app):
    return app.test_client()


def create_project(client):
    return client.post(
        "/projects/new",
        data={"company_name": "Example Company", "root_domain": "example.com"},
        follow_redirects=True,
    )


def test_create_project_and_reject_invalid_domain(client):
    response = create_project(client)
    assert response.status_code == 200
    assert b"Example Company" in response.data

    invalid = client.post(
        "/projects/new",
        data={"company_name": "Bad", "root_domain": "https://example.com/path"},
    )
    assert invalid.status_code == 400
    assert b"without a URL or path" in invalid.data


def test_scan_populates_dashboard_and_report(app, client):
    create_project(client)
    scan = client.post("/projects/1/scan", follow_redirects=True)
    assert scan.status_code == 200
    assert b"Passive recon completed successfully" in scan.data
    assert b"www.example.com" in scan.data
    assert b"hello@example.com" in scan.data

    with app.app_context():
        db = database.get_db()
        assert db.execute("SELECT COUNT(*) FROM dns_records").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM security_headers").fetchone()[0] == 12
        assert db.execute("SELECT status FROM scan_runs").fetchone()[0] == "completed"

    report = client.post("/projects/1/reports", follow_redirects=True)
    assert report.status_code == 200
    assert b"OSINT Reconnaissance Report" in report.data
    assert (Path(app.config["REPORTS_DIR"]) / "project-1-report.html").exists()


def test_duplicate_project_is_rejected(client):
    create_project(client)
    duplicate = create_project(client)
    assert duplicate.status_code == 409
    assert b"already exists" in duplicate.data
