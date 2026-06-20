from pathlib import Path

import pytest
import requests

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


def test_crtsh_timeout_backoff(monkeypatch):
    timeouts = []

    class Response:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return [{"name_value": "www.example.com\n*.api.example.com"}]

    def fake_get(_url, params, headers, timeout):
        timeouts.append(timeout)
        if len(timeouts) < 3:
            raise requests.ReadTimeout(f"timeout {timeout}")
        return Response()

    monkeypatch.setattr(crtsh_lookup.requests, "get", fake_get)
    monkeypatch.setattr(crtsh_lookup.time, "sleep", lambda _seconds: None)

    subdomains = crtsh_lookup.discover_subdomains(
        "example.com",
        timeout=30,
        retries=2,
        backoff_factor=2,
        max_timeout=120,
    )

    assert timeouts == [30, 60, 120]
    assert subdomains == ["api.example.com", "www.example.com"]


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
        lambda domain, timeout, user_agent, **kwargs: [f"www.{domain}"],
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
            "CRTSH_TIMEOUT": 30,
            "CRTSH_BACKOFF_FACTOR": 2,
            "CRTSH_MAX_TIMEOUT": 120,
            "SCAN_HISTORY_LIMIT": 5,
            "REPORT_LIMIT": 10,
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

    report = client.post(
        "/projects/1/reports",
        data={"scan_id": 1, "report_intent": "generate_report"},
        follow_redirects=True,
    )
    assert report.status_code == 200
    assert b"HTML report generated" in report.data

    with app.app_context():
        report_row = database.get_db().execute("SELECT * FROM reports").fetchone()
        assert report_row["scan_run_id"] == 1
        assert (Path(app.config["REPORTS_DIR"]) / report_row["filename"]).exists()

    opened = client.get(f"/reports/{report_row['filename']}")
    assert opened.status_code == 200
    assert b"OSINT report - example.com" in opened.data


def test_scan_history_keeps_last_five_runs(app, client):
    create_project(client)
    for _ in range(6):
        response = client.post("/projects/1/scan", follow_redirects=True)
        assert response.status_code == 200

    with app.app_context():
        db = database.get_db()
        assert db.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0] == 5
        assert db.execute("SELECT COUNT(*) FROM dns_records").fetchone()[0] == 5
        assert db.execute("SELECT MIN(id) FROM scan_runs").fetchone()[0] == 2
        assert db.execute("SELECT MIN(scan_number) FROM scan_runs").fetchone()[0] == 2
        assert db.execute("SELECT MAX(scan_number) FROM scan_runs").fetchone()[0] == 6

        database.init_db()
        assert db.execute("SELECT MIN(scan_number) FROM scan_runs").fetchone()[0] == 2
        assert db.execute("SELECT MAX(scan_number) FROM scan_runs").fetchone()[0] == 6
        assert db.execute(
            "SELECT next_scan_number FROM projects WHERE id = 1"
        ).fetchone()[0] == 7

    client.post("/projects/1/scan", follow_redirects=True)
    with app.app_context():
        db = database.get_db()
        assert db.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0] == 5
        assert db.execute("SELECT MIN(scan_number) FROM scan_runs").fetchone()[0] == 3
        assert db.execute("SELECT MAX(scan_number) FROM scan_runs").fetchone()[0] == 7


def test_scan_numbers_are_per_project(app, client):
    create_project(client)
    client.post("/projects/1/scan", follow_redirects=True)
    client.post(
        "/projects/new",
        data={"company_name": "Second Company", "root_domain": "second.example"},
        follow_redirects=True,
    )
    client.post("/projects/2/scan", follow_redirects=True)

    with app.app_context():
        db = database.get_db()
        rows = db.execute(
            "SELECT project_id, scan_number FROM scan_runs ORDER BY id"
        ).fetchall()
        assert [(row["project_id"], row["scan_number"]) for row in rows] == [(1, 1), (2, 1)]


def test_running_scan_blocks_duplicate_request(app, client):
    create_project(client)
    with app.app_context():
        with database.transaction() as db:
            db.execute(
                "INSERT INTO scan_runs (project_id, scan_number, started_at, status) VALUES (?, ?, ?, ?)",
                (1, 1, database.utc_now(), "running"),
            )

    response = client.post("/projects/1/scan", follow_redirects=True)
    assert response.status_code == 200
    assert b"already in progress" in response.data

    with app.app_context():
        assert database.get_db().execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0] == 1


def test_compare_latest_with_previous_scan(client):
    create_project(client)
    client.post("/projects/1/scan", follow_redirects=True)
    client.post("/projects/1/scan", follow_redirects=True)

    response = client.get("/projects/1/compare")
    assert response.status_code == 200
    assert b"Compared scans" in response.data
    assert b"DNS records" in response.data


def test_crtsh_failure_shows_source_diagnostics(monkeypatch, client):
    monkeypatch.setattr(
        crtsh_lookup,
        "discover_subdomains",
        lambda domain, timeout, user_agent, **kwargs: (_ for _ in ()).throw(
            TimeoutError("crt.sh read timeout")
        ),
    )
    create_project(client)
    scan = client.post("/projects/1/scan", follow_redirects=True)
    assert scan.status_code == 200
    assert b"completed with errors" in scan.data
    assert b"Source diagnostics" in scan.data
    assert b"Subdomain discovery failed" in scan.data
    assert b"crt.sh read timeout" in scan.data


def test_compare_marks_incomplete_source_data(monkeypatch, client):
    create_project(client)
    client.post("/projects/1/scan", follow_redirects=True)
    monkeypatch.setattr(
        crtsh_lookup,
        "discover_subdomains",
        lambda domain, timeout, user_agent, **kwargs: (_ for _ in ()).throw(
            TimeoutError("crt.sh read timeout")
        ),
    )
    client.post("/projects/1/scan", follow_redirects=True)

    response = client.get("/projects/1/compare")
    assert response.status_code == 200
    assert b"Comparison diagnostics" in response.data
    assert b"Latest scan #2: crt.sh" in response.data
    assert b"Subdomain discovery failed" in response.data


def test_report_rename_and_delete(app, client):
    create_project(client)
    client.post("/projects/1/scan", follow_redirects=True)
    client.post(
        "/projects/1/reports",
        data={"scan_id": 1, "report_intent": "generate_report"},
        follow_redirects=True,
    )

    rename = client.post(
        "/projects/1/reports/1/rename",
        data={"display_name": "Quarterly OSINT snapshot"},
        follow_redirects=True,
    )
    assert rename.status_code == 200
    assert b"Quarterly OSINT snapshot" in rename.data

    with app.app_context():
        report_row = database.get_db().execute("SELECT * FROM reports").fetchone()
        report_path = Path(app.config["REPORTS_DIR"]) / report_row["filename"]
        assert report_path.exists()

    delete = client.post("/projects/1/reports/1/delete", follow_redirects=True)
    assert delete.status_code == 200
    assert b"Report deleted" in delete.data
    assert not report_path.exists()


def test_report_numbers_survive_pruning_and_restart(app, client):
    create_project(client)
    client.post("/projects/1/scan", follow_redirects=True)

    for _ in range(12):
        response = client.post(
            "/projects/1/reports",
            data={"scan_id": 1, "report_intent": "generate_report"},
            follow_redirects=True,
        )
        assert response.status_code == 200

    with app.app_context():
        db = database.get_db()
        assert db.execute("SELECT COUNT(*) FROM reports").fetchone()[0] == 10
        assert db.execute("SELECT MIN(report_number) FROM reports").fetchone()[0] == 3
        assert db.execute("SELECT MAX(report_number) FROM reports").fetchone()[0] == 12

        database.init_db()
        assert db.execute("SELECT MIN(report_number) FROM reports").fetchone()[0] == 3
        assert db.execute("SELECT MAX(report_number) FROM reports").fetchone()[0] == 12
        assert db.execute(
            "SELECT next_report_number FROM projects WHERE id = 1"
        ).fetchone()[0] == 13

    client.post(
        "/projects/1/reports",
        data={"scan_id": 1, "report_intent": "generate_report"},
        follow_redirects=True,
    )
    with app.app_context():
        db = database.get_db()
        assert db.execute("SELECT COUNT(*) FROM reports").fetchone()[0] == 10
        assert db.execute("SELECT MAX(report_number) FROM reports").fetchone()[0] == 13


def test_report_limit_warning_is_rendered(client):
    create_project(client)
    client.post("/projects/1/scan", follow_redirects=True)

    for _ in range(10):
        client.post(
            "/projects/1/reports",
            data={"scan_id": 1, "report_intent": "generate_report"},
            follow_redirects=True,
        )

    overview = client.get("/projects/1")
    assert overview.status_code == 200
    assert b"Report limit reached" in overview.data
    assert b"delete the oldest report file" in overview.data

    dashboard = client.get("/projects/1/dashboard?scan_id=1")
    assert dashboard.status_code == 200
    assert b"Report limit reached" in dashboard.data


def test_report_requires_explicit_intent(app, client):
    create_project(client)
    client.post("/projects/1/scan", follow_redirects=True)

    response = client.post("/projects/1/reports", data={"scan_id": 1}, follow_redirects=True)
    assert response.status_code == 200
    assert b"requires an explicit report action" in response.data

    with app.app_context():
        assert database.get_db().execute("SELECT COUNT(*) FROM reports").fetchone()[0] == 0


def test_duplicate_project_is_rejected(client):
    create_project(client)
    duplicate = create_project(client)
    assert duplicate.status_code == 409
    assert b"already exists" in duplicate.data


def test_delete_single_scan_keeps_report_snapshot(app, client):
    create_project(client)
    client.post("/projects/1/scan", follow_redirects=True)
    client.post(
        "/projects/1/reports",
        data={"scan_id": 1, "report_intent": "generate_report"},
        follow_redirects=True,
    )

    with app.app_context():
        report_row = database.get_db().execute("SELECT * FROM reports").fetchone()
        report_path = Path(app.config["REPORTS_DIR"]) / report_row["filename"]
        assert report_path.exists()

    response = client.post("/projects/1/scans/1/delete", follow_redirects=True)
    assert response.status_code == 200
    assert b"Deleted scan #1" in response.data

    with app.app_context():
        db = database.get_db()
        assert db.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0] == 0
        report_row = db.execute("SELECT * FROM reports").fetchone()
        assert report_row["scan_run_id"] is None
        assert report_path.exists()


def test_bulk_scan_actions_generate_reports_and_delete_scans(app, client):
    create_project(client)
    for _ in range(3):
        client.post("/projects/1/scan", follow_redirects=True)

    report_response = client.post(
        "/projects/1/scans/bulk",
        data={"scan_ids": ["1", "2"], "bulk_action": "report"},
        follow_redirects=True,
    )
    assert report_response.status_code == 200
    assert b"Generated 2 HTML report" in report_response.data

    delete_response = client.post(
        "/projects/1/scans/bulk",
        data={"scan_ids": ["1", "2"], "bulk_action": "delete"},
        follow_redirects=True,
    )
    assert delete_response.status_code == 200
    assert b"Deleted 2 selected scan" in delete_response.data

    with app.app_context():
        db = database.get_db()
        remaining_scans = db.execute(
            "SELECT scan_number FROM scan_runs ORDER BY scan_number"
        ).fetchall()
        assert [row["scan_number"] for row in remaining_scans] == [3]
        assert db.execute("SELECT COUNT(*) FROM reports").fetchone()[0] == 2
        assert db.execute(
            "SELECT COUNT(*) FROM reports WHERE scan_run_id IS NULL"
        ).fetchone()[0] == 2

    delete_all_response = client.post(
        "/projects/1/scans/bulk",
        data={"bulk_action": "delete_all"},
        follow_redirects=True,
    )
    assert delete_all_response.status_code == 200
    assert b"Deleted 1 scan" in delete_all_response.data

    with app.app_context():
        assert database.get_db().execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0] == 0


def test_delete_project_removes_data_files_and_allows_domain_reuse(app, client):
    create_project(client)
    client.post("/projects/1/scan", follow_redirects=True)
    client.post(
        "/projects/1/reports",
        data={"scan_id": 1, "report_intent": "generate_report"},
        follow_redirects=True,
    )

    with app.app_context():
        report_row = database.get_db().execute("SELECT * FROM reports").fetchone()
        report_path = Path(app.config["REPORTS_DIR"]) / report_row["filename"]
        assert report_path.exists()

    delete_response = client.post("/projects/1/delete", follow_redirects=True)
    assert delete_response.status_code == 200
    assert b"and its local data were deleted" in delete_response.data

    with app.app_context():
        db = database.get_db()
        assert db.execute("SELECT COUNT(*) FROM projects").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM reports").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM dns_records").fetchone()[0] == 0
        assert not report_path.exists()

    recreated = create_project(client)
    assert recreated.status_code == 200
    assert b"Example Company" in recreated.data


def test_index_can_render_project_list_view(client):
    create_project(client)

    response = client.get("/?view=list")
    assert response.status_code == 200
    assert b"Root domain" in response.data
    assert b"example.com" in response.data
    assert b"Cards" in response.data
