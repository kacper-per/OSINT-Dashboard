import json
import os
import re
import sqlite3
from collections import Counter
from pathlib import Path

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)

import database
from config import Config
from modules import (
    crtsh_lookup,
    dns_lookup,
    email_finder,
    http_probe,
    security_headers,
    tls_info,
    whois_lookup,
)


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)


def normalize_domain(value):
    domain = value.strip().lower().rstrip(".")
    if "://" in domain or "/" in domain or not DOMAIN_PATTERN.fullmatch(domain):
        raise ValueError("Enter a root domain such as example.com, without a URL or path.")
    return domain


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    Path(app.config["REPORTS_DIR"]).mkdir(parents=True, exist_ok=True)
    database.init_app(app)

    @app.route("/")
    def index():
        projects = database.get_db().execute(
            """
            SELECT p.*, COUNT(sr.id) AS scan_count, MAX(sr.finished_at) AS last_scan
            FROM projects p
            LEFT JOIN scan_runs sr ON sr.project_id = p.id
            GROUP BY p.id
            ORDER BY p.id DESC
            """
        ).fetchall()
        return render_template("index.html", projects=projects)

    @app.route("/projects/new", methods=("GET", "POST"))
    def new_project():
        if request.method == "POST":
            company_name = request.form.get("company_name", "").strip()
            try:
                root_domain = normalize_domain(request.form.get("root_domain", ""))
            except ValueError as exc:
                flash(str(exc), "danger")
                return render_template("new_project.html"), 400

            if not company_name:
                flash("Company or organization name is required.", "danger")
                return render_template("new_project.html"), 400

            try:
                with database.transaction() as db:
                    cursor = db.execute(
                        """
                        INSERT INTO projects (company_name, root_domain, created_at)
                        VALUES (?, ?, ?)
                        """,
                        (company_name, root_domain, database.utc_now()),
                    )
                    project_id = cursor.lastrowid
            except sqlite3.IntegrityError:
                flash("A project for this root domain already exists.", "warning")
                return render_template("new_project.html"), 409

            flash("Project created. It is ready for a passive recon run.", "success")
            return redirect(url_for("project_detail", project_id=project_id))

        return render_template("new_project.html")

    @app.route("/projects/<int:project_id>")
    def project_detail(project_id):
        project = get_project_or_404(project_id)
        scan_runs = database.get_db().execute(
            "SELECT * FROM scan_runs WHERE project_id = ? ORDER BY id DESC LIMIT 10",
            (project_id,),
        ).fetchall()
        reports = report_files_for_project(project_id)
        summary = project_summary(project_id)
        return render_template(
            "project_detail.html",
            project=project,
            scan_runs=scan_runs,
            reports=reports,
            summary=summary,
        )

    @app.route("/projects/<int:project_id>/dashboard")
    def dashboard(project_id):
        project = get_project_or_404(project_id)
        data = database.fetch_project_data(project_id)
        summary = project_summary(project_id)
        charts = {
            "dns": dict(Counter(row["record_type"] for row in data["dns_records"])),
            "http": dict(
                Counter(
                    str(row["status_code"]) if row["status_code"] is not None else "No response"
                    for row in data["http_results"]
                )
            ),
            "headers": {
                "Present": sum(row["present"] for row in data["security_headers"]),
                "Missing": sum(not row["present"] for row in data["security_headers"]),
            },
        }
        return render_template(
            "dashboard.html",
            project=project,
            data=data,
            summary=summary,
            charts_json=json.dumps(charts),
        )

    @app.post("/projects/<int:project_id>/scan")
    def run_scan(project_id):
        project = get_project_or_404(project_id)
        database.clear_project_results(project_id)
        with database.transaction() as db:
            cursor = db.execute(
                "INSERT INTO scan_runs (project_id, started_at, status) VALUES (?, ?, ?)",
                (project_id, database.utc_now(), "running"),
            )
            scan_id = cursor.lastrowid

        failures = perform_scan(project)
        status = "completed_with_errors" if failures else "completed"
        with database.transaction() as db:
            db.execute(
                "UPDATE scan_runs SET finished_at = ?, status = ? WHERE id = ?",
                (database.utc_now(), status, scan_id),
            )

        if failures:
            flash(
                f"Recon completed with {failures} module warning(s). Details are in Raw Results.",
                "warning",
            )
        else:
            flash("Passive recon completed successfully.", "success")
        return redirect(url_for("dashboard", project_id=project_id))

    @app.post("/projects/<int:project_id>/reports")
    def generate_report(project_id):
        project = get_project_or_404(project_id)
        data = database.fetch_project_data(project_id)
        summary = project_summary(project_id)
        latest_scan = database.get_db().execute(
            "SELECT * FROM scan_runs WHERE project_id = ? ORDER BY id DESC LIMIT 1",
            (project_id,),
        ).fetchone()
        filename = f"project-{project_id}-report.html"
        content = render_template(
            "report.html",
            project=project,
            data=data,
            summary=summary,
            latest_scan=latest_scan,
        )
        report_path = Path(app.config["REPORTS_DIR"]) / filename
        report_path.write_text(content, encoding="utf-8")
        flash("HTML report generated.", "success")
        return redirect(url_for("view_report", filename=filename))

    @app.route("/reports/<path:filename>")
    def view_report(filename):
        if not re.fullmatch(r"project-\d+-report\.html", filename):
            abort(404)
        return send_from_directory(app.config["REPORTS_DIR"], filename)

    def get_project_or_404(project_id):
        project = database.get_db().execute(
            "SELECT * FROM projects WHERE id = ?", (project_id,)
        ).fetchone()
        if project is None:
            abort(404)
        return project

    def report_files_for_project(project_id):
        reports_dir = Path(app.config["REPORTS_DIR"])
        return sorted(
            (path.name for path in reports_dir.glob(f"project-{project_id}-report.html")),
            reverse=True,
        )

    def project_summary(project_id):
        db = database.get_db()
        return {
            "subdomains": db.execute(
                "SELECT COUNT(*) FROM subdomains WHERE project_id = ?", (project_id,)
            ).fetchone()[0],
            "dns_records": db.execute(
                "SELECT COUNT(*) FROM dns_records WHERE project_id = ?", (project_id,)
            ).fetchone()[0],
            "http_results": db.execute(
                "SELECT COUNT(*) FROM http_results WHERE project_id = ?", (project_id,)
            ).fetchone()[0],
            "emails": db.execute(
                "SELECT COUNT(*) FROM emails WHERE project_id = ?", (project_id,)
            ).fetchone()[0],
            "missing_headers": db.execute(
                "SELECT COUNT(*) FROM security_headers WHERE project_id = ? AND present = 0",
                (project_id,),
            ).fetchone()[0],
        }

    def record_raw(project_id, module_name, output):
        database.insert_rows(
            "raw_results",
            ("project_id", "module_name", "raw_output", "created_at"),
            [(project_id, module_name, str(output), database.utc_now())],
        )

    def perform_scan(project):
        project_id = project["id"]
        domain = project["root_domain"]
        timeout = app.config["REQUEST_TIMEOUT"]
        user_agent = app.config["USER_AGENT"]
        failures = 0

        try:
            records, errors = dns_lookup.lookup_dns(domain, timeout)
            database.insert_rows(
                "dns_records",
                ("project_id", "record_type", "name", "value", "source", "created_at"),
                [
                    (
                        project_id,
                        row["record_type"],
                        row["name"],
                        row["value"],
                        row["source"],
                        database.utc_now(),
                    )
                    for row in records
                ],
            )
            if errors:
                record_raw(project_id, "dns_lookup", "\n".join(errors))
        except Exception as exc:
            failures += 1
            record_raw(project_id, "dns_lookup_error", exc)

        subdomains = []
        try:
            subdomains = crtsh_lookup.discover_subdomains(domain, timeout + 4, user_agent)
            database.insert_rows(
                "subdomains",
                ("project_id", "subdomain", "source", "created_at"),
                [
                    (project_id, subdomain, "crt.sh", database.utc_now())
                    for subdomain in subdomains
                ],
            )
        except Exception as exc:
            failures += 1
            record_raw(project_id, "crtsh_lookup_error", exc)

        hosts = [domain] + subdomains[: app.config["MAX_SUBDOMAINS_TO_PROBE"]]
        https_hosts = set()
        for host in hosts:
            try:
                results, errors = http_probe.probe_host(host, timeout, user_agent)
                database.insert_rows(
                    "http_results",
                    (
                        "project_id",
                        "url",
                        "status_code",
                        "title",
                        "server_header",
                        "final_url",
                        "https_available",
                        "created_at",
                    ),
                    [
                        (
                            project_id,
                            row["url"],
                            row["status_code"],
                            row["title"],
                            row["server_header"],
                            row["final_url"],
                            int(row["https_available"]),
                            database.utc_now(),
                        )
                        for row in results
                    ],
                )
                for row in results:
                    if row["url"].startswith("https://"):
                        https_hosts.add(host)
                    inspected = security_headers.inspect_headers(row["url"], row["headers"])
                    database.insert_rows(
                        "security_headers",
                        (
                            "project_id",
                            "url",
                            "header_name",
                            "header_value",
                            "present",
                            "created_at",
                        ),
                        [
                            (
                                project_id,
                                item["url"],
                                item["header_name"],
                                item["header_value"],
                                int(item["present"]),
                                database.utc_now(),
                            )
                            for item in inspected
                        ],
                    )
                if errors:
                    record_raw(project_id, f"http_probe:{host}", "\n".join(errors))
            except Exception as exc:
                failures += 1
                record_raw(project_id, f"http_probe_error:{host}", exc)

        try:
            raw_whois = whois_lookup.lookup_whois(domain)
            database.insert_rows(
                "whois_results",
                ("project_id", "raw_text", "source", "created_at"),
                [(project_id, raw_whois, "python-whois", database.utc_now())],
            )
        except Exception as exc:
            failures += 1
            record_raw(project_id, "whois_lookup_error", exc)

        for host in sorted(https_hosts):
            try:
                certificate = tls_info.fetch_tls_certificate(host, app.config["TLS_TIMEOUT"])
                database.insert_rows(
                    "tls_certificates",
                    (
                        "project_id",
                        "hostname",
                        "issuer",
                        "subject",
                        "not_before",
                        "not_after",
                        "san_names",
                        "created_at",
                    ),
                    [
                        (
                            project_id,
                            certificate["hostname"],
                            certificate["issuer"],
                            certificate["subject"],
                            certificate["not_before"],
                            certificate["not_after"],
                            certificate["san_names"],
                            database.utc_now(),
                        )
                    ],
                )
            except Exception as exc:
                failures += 1
                record_raw(project_id, f"tls_info_error:{host}", exc)

        try:
            emails, source_url, errors = email_finder.find_homepage_emails(
                domain, timeout, user_agent
            )
            database.insert_rows(
                "emails",
                ("project_id", "email", "source", "created_at"),
                [
                    (project_id, email, source_url or domain, database.utc_now())
                    for email in emails
                ],
            )
            if errors and not emails:
                record_raw(project_id, "email_finder", "\n".join(errors))
        except Exception as exc:
            failures += 1
            record_raw(project_id, "email_finder_error", exc)

        return failures

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
