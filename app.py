import json
import os
import re
import sqlite3
from collections import Counter
from datetime import datetime, timezone
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
REPORT_FILENAME_PATTERN = re.compile(r"project-\d+-scan-\d+-\d{8}-\d{6}(?:-\d+)?\.html")
LEGACY_REPORT_FILENAME_PATTERN = re.compile(r"project-(\d+)-report\.html")


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
    migrate_legacy_report_files(app)

    @app.route("/")
    def index():
        view_mode = request.args.get("view", "cards")
        if view_mode not in {"cards", "list"}:
            view_mode = "cards"
        projects = database.get_db().execute(
            """
            SELECT p.*, COUNT(sr.id) AS scan_count, MAX(sr.finished_at) AS last_scan
            FROM projects p
            LEFT JOIN scan_runs sr ON sr.project_id = p.id
            GROUP BY p.id
            ORDER BY p.id DESC
            """
        ).fetchall()
        return render_template("index.html", projects=projects, view_mode=view_mode)

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
        latest_scan = database.get_latest_scan_run(project_id)
        running_scan = database.get_running_scan(project_id)
        scan_runs = database.list_scan_runs_with_summary(
            project_id, app.config["SCAN_HISTORY_LIMIT"]
        )
        reports = database.list_reports(project_id)
        report_count = len(reports)
        summary = database.scan_summary(latest_scan["id"] if latest_scan else None)
        return render_template(
            "project_detail.html",
            project=project,
            latest_scan=latest_scan,
            running_scan=running_scan,
            scan_runs=scan_runs,
            reports=reports,
            report_count=report_count,
            summary=summary,
        )

    @app.route("/projects/<int:project_id>/dashboard")
    def dashboard(project_id):
        project = get_project_or_404(project_id)
        scan_id = request.args.get("scan_id", type=int)
        selected_scan = (
            get_scan_or_404(project_id, scan_id)
            if scan_id
            else database.get_latest_scan_run(project_id)
        )
        data = database.fetch_project_data(
            project_id, selected_scan["id"] if selected_scan else None
        )
        summary = database.scan_summary(selected_scan["id"] if selected_scan else None)
        charts = build_charts(data)
        source_warnings = scan_source_warnings(data)
        scan_runs = database.list_scan_runs(project_id, app.config["SCAN_HISTORY_LIMIT"])
        report_count = database.count_reports(project_id)
        security_header_matrix = build_security_header_matrix(data["security_headers"])
        return render_template(
            "dashboard.html",
            project=project,
            data=data,
            summary=summary,
            source_warnings=source_warnings,
            selected_scan=selected_scan,
            scan_runs=scan_runs,
            report_count=report_count,
            security_header_names=security_headers.SECURITY_HEADERS,
            security_header_matrix=security_header_matrix,
            charts_json=json.dumps(charts),
        )

    @app.post("/projects/<int:project_id>/scans/<int:scan_id>/emails/deep-search")
    def deep_search_emails(project_id, scan_id):
        project = get_project_or_404(project_id)
        scan = get_scan_or_404(project_id, scan_id)
        if scan["status"] == "running":
            flash("Wait for the scan to finish before running deep email search.", "warning")
            return redirect(url_for("dashboard", project_id=project_id, scan_id=scan_id) + "#tab-7")

        before_count = database.scan_summary(scan_id)["emails"]
        try:
            emails, stats = email_finder.deep_search_emails(
                project["root_domain"],
                app.config["REQUEST_TIMEOUT"],
                app.config["USER_AGENT"],
                max_pages=app.config["EMAIL_CRAWL_MAX_PAGES"],
                max_bytes=app.config["EMAIL_CRAWL_MAX_BYTES"],
            )
            database.insert_rows(
                "emails",
                ("scan_run_id", "project_id", "email", "source", "created_at"),
                [
                    (scan_id, project_id, row["email"], row["source"], database.utc_now())
                    for row in emails
                ],
            )
            if stats["errors"]:
                record_raw(project_id, scan_id, "email_deep_search", "\n".join(stats["errors"]))
            after_count = database.scan_summary(scan_id)["emails"]
            flash(
                (
                    f"Deep email search checked {stats['pages_checked']} page(s), "
                    f"found {len(emails)} email(s), and added {after_count - before_count} new email(s)."
                ),
                "success",
            )
        except Exception as exc:
            record_raw(project_id, scan_id, "email_deep_search_error", exc)
            flash("Deep email search failed. Details are in Raw Results.", "danger")
        return redirect(url_for("dashboard", project_id=project_id, scan_id=scan_id) + "#tab-7")

    @app.route("/projects/<int:project_id>/compare")
    def compare_scans(project_id):
        project = get_project_or_404(project_id)
        latest_scan = database.get_latest_scan_run(project_id)
        previous_scan = (
            database.get_previous_scan_run(project_id, latest_scan["id"])
            if latest_scan
            else None
        )
        comparison = None
        if latest_scan and previous_scan:
            previous_data = database.fetch_project_data(project_id, previous_scan["id"])
            latest_data = database.fetch_project_data(project_id, latest_scan["id"])
            comparison = compare_scan_data(
                previous_data,
                latest_data,
            )
            source_warnings = {
                "previous": scan_source_warnings(previous_data),
                "latest": scan_source_warnings(latest_data),
            }
        else:
            source_warnings = {"previous": [], "latest": []}
        return render_template(
            "compare.html",
            project=project,
            latest_scan=latest_scan,
            previous_scan=previous_scan,
            comparison=comparison,
            source_warnings=source_warnings,
        )

    @app.post("/projects/<int:project_id>/scan")
    def run_scan(project_id):
        project = get_project_or_404(project_id)
        if database.get_running_scan(project_id):
            flash("A reconnaissance run is already in progress for this project.", "warning")
            return redirect(url_for("project_detail", project_id=project_id))

        scan_id = database.create_scan_run(project_id)

        failures = 0
        status = "completed"
        try:
            failures = perform_scan(project, scan_id)
            status = "completed_with_errors" if failures else "completed"
        except Exception as exc:
            failures = 1
            status = "failed"
            record_raw(project_id, scan_id, "scan_error", exc)
        finally:
            with database.transaction() as db:
                db.execute(
                    "UPDATE scan_runs SET finished_at = ?, status = ? WHERE id = ?",
                    (database.utc_now(), status, scan_id),
                )
            database.prune_old_scan_runs(project_id, app.config["SCAN_HISTORY_LIMIT"])

        if status == "failed":
            flash("Recon failed unexpectedly. Details are in Raw Results.", "danger")
        elif failures:
            flash(
                f"Recon completed with {failures} module warning(s). Details are in Raw Results.",
                "warning",
            )
        else:
            flash("Passive recon completed successfully.", "success")
        return redirect(url_for("dashboard", project_id=project_id, scan_id=scan_id))

    @app.post("/projects/<int:project_id>/reports")
    def generate_report(project_id):
        project = get_project_or_404(project_id)
        if request.form.get("report_intent") != "generate_report":
            flash("Report generation requires an explicit report action.", "warning")
            return redirect(url_for("project_detail", project_id=project_id))

        scan_id = request.form.get("scan_id", type=int)
        scan = get_scan_or_404(project_id, scan_id) if scan_id else database.get_latest_scan_run(project_id)
        if not scan or scan["status"] == "running":
            flash("Generate a report after a scan has finished.", "warning")
            return redirect(url_for("project_detail", project_id=project_id))

        display_name = request.form.get("display_name", "").strip()
        create_report_snapshot(project, scan, display_name)
        delete_report_files(database.prune_old_reports(project_id, app.config["REPORT_LIMIT"]))

        flash("HTML report generated.", "success")
        return redirect(url_for("project_detail", project_id=project_id))

    @app.post("/projects/<int:project_id>/scans/bulk")
    def bulk_scan_action(project_id):
        project = get_project_or_404(project_id)
        action = request.form.get("bulk_action")
        scan_ids = parse_scan_ids(request.form.getlist("scan_ids"))

        if action == "delete_all":
            deleted = database.delete_all_scans(project_id)
            flash(f"Deleted {len(deleted)} scan(s). Existing HTML reports were kept.", "success")
            return redirect(url_for("project_detail", project_id=project_id))

        if not scan_ids:
            flash("Select at least one scan.", "warning")
            return redirect(url_for("project_detail", project_id=project_id))

        if action == "delete":
            deleted = database.delete_scans(project_id, scan_ids)
            flash(f"Deleted {len(deleted)} selected scan(s). Existing HTML reports were kept.", "success")
            return redirect(url_for("project_detail", project_id=project_id))

        if action == "report":
            scans = [
                scan for scan in database.get_scan_runs(project_id, scan_ids)
                if scan["status"] != "running"
            ]
            for scan in scans:
                create_report_snapshot(project, scan, "")
            delete_report_files(database.prune_old_reports(project_id, app.config["REPORT_LIMIT"]))
            flash(f"Generated {len(scans)} HTML report(s).", "success")
            return redirect(url_for("project_detail", project_id=project_id))

        flash("Unknown scan action.", "danger")
        return redirect(url_for("project_detail", project_id=project_id))

    @app.post("/projects/<int:project_id>/scans/<int:scan_id>/delete")
    def delete_scan(project_id, scan_id):
        get_project_or_404(project_id)
        scan = database.delete_scan(project_id, scan_id)
        if scan is None:
            abort(404)
        if scan["status"] == "running":
            flash("Running scans cannot be deleted.", "warning")
        else:
            flash(f"Deleted scan #{scan['scan_number']}. Existing HTML reports were kept.", "success")
        return redirect(url_for("project_detail", project_id=project_id))

    @app.post("/projects/<int:project_id>/reports/<int:report_id>/rename")
    def rename_report(project_id, report_id):
        get_project_or_404(project_id)
        display_name = request.form.get("display_name", "").strip()
        if not display_name:
            flash("Report name cannot be empty.", "danger")
            return redirect(url_for("project_detail", project_id=project_id))
        database.rename_report(project_id, report_id, display_name)
        flash("Report name updated.", "success")
        return redirect(url_for("project_detail", project_id=project_id))

    @app.post("/projects/<int:project_id>/reports/<int:report_id>/delete")
    def delete_report(project_id, report_id):
        get_project_or_404(project_id)
        report = database.delete_report(project_id, report_id)
        if report:
            delete_report_files([report])
            flash("Report deleted.", "success")
        return redirect(url_for("project_detail", project_id=project_id))

    @app.post("/projects/<int:project_id>/delete")
    def delete_project(project_id):
        project = get_project_or_404(project_id)
        if database.get_running_scan(project_id):
            flash("Stop or wait for the running scan before deleting this project.", "warning")
            return redirect(url_for("project_detail", project_id=project_id))

        reports = database.list_reports(project_id)
        deleted = database.delete_project(project_id)
        if deleted:
            delete_report_files(reports)
            flash(f"Project {project['root_domain']} and its local data were deleted.", "success")
        return redirect(url_for("index"))

    @app.route("/reports/<path:filename>")
    def view_report(filename):
        if not (
            REPORT_FILENAME_PATTERN.fullmatch(filename)
            or LEGACY_REPORT_FILENAME_PATTERN.fullmatch(filename)
        ):
            abort(404)
        if database.get_report_by_filename(filename) is None:
            abort(404)
        return send_from_directory(app.config["REPORTS_DIR"], filename)

    def get_project_or_404(project_id):
        project = database.get_project(project_id)
        if project is None:
            abort(404)
        return project

    def get_scan_or_404(project_id, scan_id):
        scan = database.get_scan_run(project_id, scan_id)
        if scan is None:
            abort(404)
        return scan

    def record_raw(project_id, scan_run_id, module_name, output):
        database.insert_rows(
            "raw_results",
            ("scan_run_id", "project_id", "module_name", "raw_output", "created_at"),
            [(scan_run_id, project_id, module_name, str(output), database.utc_now())],
        )

    def perform_scan(project, scan_id):
        project_id = project["id"]
        domain = project["root_domain"]
        timeout = app.config["REQUEST_TIMEOUT"]
        user_agent = app.config["USER_AGENT"]
        failures = 0

        try:
            records, errors = dns_lookup.lookup_dns(domain, timeout)
            database.insert_rows(
                "dns_records",
                (
                    "scan_run_id",
                    "project_id",
                    "record_type",
                    "name",
                    "value",
                    "source",
                    "created_at",
                ),
                [
                    (
                        scan_id,
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
                record_raw(project_id, scan_id, "dns_lookup", "\n".join(errors))
        except Exception as exc:
            failures += 1
            record_raw(project_id, scan_id, "dns_lookup_error", exc)

        subdomains = []
        try:
            subdomains = crtsh_lookup.discover_subdomains(
                domain,
                app.config["CRTSH_TIMEOUT"],
                user_agent,
                retries=app.config["CRTSH_RETRIES"],
                retry_delay=app.config["CRTSH_RETRY_DELAY"],
                backoff_factor=app.config["CRTSH_BACKOFF_FACTOR"],
                max_timeout=app.config["CRTSH_MAX_TIMEOUT"],
            )
            database.insert_rows(
                "subdomains",
                ("scan_run_id", "project_id", "subdomain", "source", "created_at"),
                [
                    (scan_id, project_id, subdomain, "crt.sh", database.utc_now())
                    for subdomain in subdomains
                ],
            )
        except Exception as exc:
            failures += 1
            record_raw(project_id, scan_id, "crtsh_lookup_error", exc)

        hosts = [domain] + subdomains[: app.config["MAX_SUBDOMAINS_TO_PROBE"]]
        https_hosts = set()
        for host in hosts:
            try:
                results, errors = http_probe.probe_host(host, timeout, user_agent)
                database.insert_rows(
                    "http_results",
                    (
                        "scan_run_id",
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
                            scan_id,
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
                            "scan_run_id",
                            "project_id",
                            "url",
                            "header_name",
                            "header_value",
                            "present",
                            "created_at",
                        ),
                        [
                            (
                                scan_id,
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
                    record_raw(project_id, scan_id, f"http_probe:{host}", "\n".join(errors))
            except Exception as exc:
                failures += 1
                record_raw(project_id, scan_id, f"http_probe_error:{host}", exc)

        try:
            raw_whois = whois_lookup.lookup_whois(domain)
            database.insert_rows(
                "whois_results",
                ("scan_run_id", "project_id", "raw_text", "source", "created_at"),
                [(scan_id, project_id, raw_whois, "python-whois", database.utc_now())],
            )
        except Exception as exc:
            failures += 1
            record_raw(project_id, scan_id, "whois_lookup_error", exc)

        for host in sorted(https_hosts):
            try:
                certificate = tls_info.fetch_tls_certificate(host, app.config["TLS_TIMEOUT"])
                database.insert_rows(
                    "tls_certificates",
                    (
                        "scan_run_id",
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
                            scan_id,
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
                record_raw(project_id, scan_id, f"tls_info_error:{host}", exc)

        try:
            emails, source_url, errors = email_finder.find_homepage_emails(
                domain, timeout, user_agent
            )
            database.insert_rows(
                "emails",
                ("scan_run_id", "project_id", "email", "source", "created_at"),
                [
                    (scan_id, project_id, email, source_url or domain, database.utc_now())
                    for email in emails
                ],
            )
            if errors and not emails:
                record_raw(project_id, scan_id, "email_finder", "\n".join(errors))
        except Exception as exc:
            failures += 1
            record_raw(project_id, scan_id, "email_finder_error", exc)

        return failures

    def build_charts(data):
        return {
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

    def create_report_snapshot(project, scan, display_name):
        data = database.fetch_project_data(project["id"], scan["id"])
        summary = database.scan_summary(scan["id"])
        if not display_name:
            display_name = default_report_name(project, scan)

        filename = unique_report_filename(project["id"], scan)
        content = render_template(
            "report.html",
            project=project,
            data=data,
            summary=summary,
            latest_scan=scan,
            report_name=display_name,
            security_header_names=security_headers.SECURITY_HEADERS,
            security_header_matrix=build_security_header_matrix(data["security_headers"]),
        )
        report_path = Path(app.config["REPORTS_DIR"]) / filename
        report_path.write_text(content, encoding="utf-8")
        database.insert_report(project["id"], scan["id"], display_name, filename)
        return filename

    def default_report_name(project, scan):
        scan_time = scan["finished_at"] or scan["started_at"]
        return f"OSINT report - {project['root_domain']} - scan #{scan['scan_number']} - {scan_time}"

    def unique_report_filename(project_id, scan):
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        stem = f"project-{project_id}-scan-{scan['scan_number']}-{timestamp}"
        filename = f"{stem}.html"
        reports_dir = Path(app.config["REPORTS_DIR"])
        counter = 2
        while (reports_dir / filename).exists():
            filename = f"{stem}-{counter}.html"
            counter += 1
        return filename

    def delete_report_files(reports):
        reports_dir = Path(app.config["REPORTS_DIR"])
        for report in reports:
            (reports_dir / report["filename"]).unlink(missing_ok=True)

    return app


def migrate_legacy_report_files(app):
    reports_dir = Path(app.config["REPORTS_DIR"])
    with app.app_context():
        for path in reports_dir.glob("project-*-report.html"):
            match = LEGACY_REPORT_FILENAME_PATTERN.fullmatch(path.name)
            if not match or database.get_report_by_filename(path.name):
                continue
            project_id = int(match.group(1))
            project = database.get_project(project_id)
            if not project:
                continue
            latest_scan = database.get_latest_scan_run(project_id)
            database.insert_report(
                project_id,
                latest_scan["id"] if latest_scan else None,
                f"Legacy report - {project['root_domain']}",
                path.name,
            )


def row_to_dict(row):
    return {key: row[key] for key in row.keys()}


def parse_scan_ids(values):
    scan_ids = []
    for value in values:
        try:
            scan_ids.append(int(value))
        except (TypeError, ValueError):
            continue
    return scan_ids


def build_security_header_matrix(rows):
    matrix = {}
    for row in rows:
        url = row["url"]
        header_name = row["header_name"]
        matrix.setdefault(
            url,
            {
                header: {"present": False, "value": ""}
                for header in security_headers.SECURITY_HEADERS
            },
        )
        matrix[url][header_name] = {
            "present": bool(row["present"]),
            "value": row["header_value"] or "",
        }

    return [
        {"url": url, "headers": matrix[url]}
        for url in sorted(matrix)
    ]


def scan_source_warnings(data):
    warnings = []
    for row in data["raw_results"]:
        module_name = row["module_name"]
        if module_name == "crtsh_lookup_error":
            warnings.append(
                {
                    "source": "crt.sh",
                    "impact": "Subdomain discovery failed for this scan. Subdomain and downstream HTTP/TLS comparisons may be incomplete.",
                    "raw_output": row["raw_output"],
                }
            )
    return warnings


def compare_rows(before_rows, after_rows, key_fields, value_fields=None):
    def key_for(row):
        return tuple(str(row[field]) for field in key_fields)

    before = {key_for(row): row_to_dict(row) for row in before_rows}
    after = {key_for(row): row_to_dict(row) for row in after_rows}
    added_keys = sorted(set(after) - set(before))
    removed_keys = sorted(set(before) - set(after))
    changed = []

    if value_fields:
        for key in sorted(set(before) & set(after)):
            before_values = tuple(before[key].get(field) for field in value_fields)
            after_values = tuple(after[key].get(field) for field in value_fields)
            if before_values != after_values:
                changed.append(
                    {
                        "key": " | ".join(key),
                        "before": before[key],
                        "after": after[key],
                    }
                )

    return {
        "added": [after[key] for key in added_keys],
        "removed": [before[key] for key in removed_keys],
        "changed": changed,
    }


def compare_scan_data(before_data, after_data):
    rules = [
        {
            "label": "DNS records",
            "table": "dns_records",
            "key_fields": ("record_type", "name", "value"),
        },
        {"label": "Subdomains", "table": "subdomains", "key_fields": ("subdomain",)},
        {
            "label": "HTTP results",
            "table": "http_results",
            "key_fields": ("url",),
            "value_fields": (
                "status_code",
                "title",
                "server_header",
                "final_url",
                "https_available",
            ),
        },
        {
            "label": "Security headers",
            "table": "security_headers",
            "key_fields": ("url", "header_name"),
            "value_fields": ("present", "header_value"),
        },
        {
            "label": "WHOIS",
            "table": "whois_results",
            "key_fields": ("source",),
            "value_fields": ("raw_text",),
        },
        {
            "label": "TLS certificates",
            "table": "tls_certificates",
            "key_fields": ("hostname",),
            "value_fields": (
                "issuer",
                "subject",
                "not_before",
                "not_after",
                "san_names",
            ),
        },
        {"label": "Emails", "table": "emails", "key_fields": ("email",)},
        {
            "label": "Raw results",
            "table": "raw_results",
            "key_fields": ("module_name", "raw_output"),
        },
    ]
    sections = []
    for rule in rules:
        diff = compare_rows(
            before_data[rule["table"]],
            after_data[rule["table"]],
            rule["key_fields"],
            rule.get("value_fields"),
        )
        sections.append(
            {
                "label": rule["label"],
                "diff": diff,
                "total": len(diff["added"]) + len(diff["removed"]) + len(diff["changed"]),
            }
        )
    return sections


app = create_app()


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
