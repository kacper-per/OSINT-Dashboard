import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from flask import current_app, g


REPORT_SCAN_NUMBER_PATTERN = re.compile(r"project-\d+-scan-(\d+)-")


RESULT_TABLES = (
    "dns_records",
    "subdomains",
    "whois_results",
    "http_results",
    "security_headers",
    "emails",
    "tls_certificates",
    "raw_results",
)

RESULT_TABLE_COLUMNS = {
    "dns_records": (
        "id",
        "scan_run_id",
        "project_id",
        "record_type",
        "name",
        "value",
        "source",
        "created_at",
    ),
    "subdomains": ("id", "scan_run_id", "project_id", "subdomain", "source", "created_at"),
    "whois_results": ("id", "scan_run_id", "project_id", "raw_text", "source", "created_at"),
    "http_results": (
        "id",
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
    "security_headers": (
        "id",
        "scan_run_id",
        "project_id",
        "url",
        "header_name",
        "header_value",
        "present",
        "created_at",
    ),
    "emails": ("id", "scan_run_id", "project_id", "email", "source", "created_at"),
    "tls_certificates": (
        "id",
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
    "raw_results": ("id", "scan_run_id", "project_id", "module_name", "raw_output", "created_at"),
}

RESULT_TABLE_SCHEMAS = {
    "dns_records": """
CREATE TABLE IF NOT EXISTS dns_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER NOT NULL,
    project_id INTEGER NOT NULL,
    record_type TEXT NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(scan_run_id, record_type, name, value),
    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);
""",
    "subdomains": """
CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER NOT NULL,
    project_id INTEGER NOT NULL,
    subdomain TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(scan_run_id, subdomain),
    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);
""",
    "whois_results": """
CREATE TABLE IF NOT EXISTS whois_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER NOT NULL,
    project_id INTEGER NOT NULL,
    raw_text TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);
""",
    "http_results": """
CREATE TABLE IF NOT EXISTS http_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER NOT NULL,
    project_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    status_code INTEGER,
    title TEXT,
    server_header TEXT,
    final_url TEXT,
    https_available INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    UNIQUE(scan_run_id, url),
    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);
""",
    "security_headers": """
CREATE TABLE IF NOT EXISTS security_headers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER NOT NULL,
    project_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    header_name TEXT NOT NULL,
    header_value TEXT,
    present INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(scan_run_id, url, header_name),
    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);
""",
    "emails": """
CREATE TABLE IF NOT EXISTS emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER NOT NULL,
    project_id INTEGER NOT NULL,
    email TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(scan_run_id, email),
    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);
""",
    "tls_certificates": """
CREATE TABLE IF NOT EXISTS tls_certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER NOT NULL,
    project_id INTEGER NOT NULL,
    hostname TEXT NOT NULL,
    issuer TEXT,
    subject TEXT,
    not_before TEXT,
    not_after TEXT,
    san_names TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(scan_run_id, hostname),
    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);
""",
    "raw_results": """
CREATE TABLE IF NOT EXISTS raw_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER NOT NULL,
    project_id INTEGER NOT NULL,
    module_name TEXT NOT NULL,
    raw_output TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);
""",
}

SCHEMA = (
    """
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company_name TEXT NOT NULL,
    root_domain TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    next_scan_number INTEGER NOT NULL DEFAULT 1,
    next_report_number INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    scan_number INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    UNIQUE(project_id, scan_number),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    scan_run_id INTEGER,
    report_number INTEGER NOT NULL,
    display_name TEXT NOT NULL,
    filename TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    UNIQUE(project_id, report_number),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id) ON DELETE SET NULL
);
"""
    + "\n".join(RESULT_TABLE_SCHEMAS.values())
)

INDEXES = """
CREATE INDEX IF NOT EXISTS idx_scan_runs_project_id ON scan_runs(project_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_runs_project_scan_number ON scan_runs(project_id, scan_number);
CREATE INDEX IF NOT EXISTS idx_reports_project_id ON reports(project_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_reports_project_report_number ON reports(project_id, report_number);
CREATE INDEX IF NOT EXISTS idx_dns_records_scan_run_id ON dns_records(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_subdomains_scan_run_id ON subdomains(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_whois_results_scan_run_id ON whois_results(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_http_results_scan_run_id ON http_results(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_security_headers_scan_run_id ON security_headers(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_emails_scan_run_id ON emails(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_tls_certificates_scan_run_id ON tls_certificates(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_raw_results_scan_run_id ON raw_results(scan_run_id);
"""


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def get_db():
    if "db" not in g:
        database_path = current_app.config["DATABASE_PATH"]
        database_path.parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(database_path)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(SCHEMA)
    migrate_db(db)
    db.executescript(INDEXES)
    db.commit()


def migrate_db(db):
    migrate_project_counters(db)
    migrate_scan_run_numbers(db)
    migrate_report_numbers(db)
    for table in RESULT_TABLES:
        columns = table_columns(db, table)
        if "scan_run_id" not in columns:
            rebuild_result_table(db, table)
    refresh_project_counters(db)


def table_columns(db, table):
    return [row["name"] for row in db.execute(f"PRAGMA table_info({table})")]


def migrate_project_counters(db):
    columns = table_columns(db, "projects")
    if "next_scan_number" not in columns:
        db.execute("ALTER TABLE projects ADD COLUMN next_scan_number INTEGER DEFAULT 1")
    if "next_report_number" not in columns:
        db.execute("ALTER TABLE projects ADD COLUMN next_report_number INTEGER DEFAULT 1")


def migrate_scan_run_numbers(db):
    columns = table_columns(db, "scan_runs")
    if "scan_number" not in columns:
        db.execute("ALTER TABLE scan_runs ADD COLUMN scan_number INTEGER")

    project_ids = [
        row["project_id"]
        for row in db.execute("SELECT DISTINCT project_id FROM scan_runs ORDER BY project_id")
    ]
    for project_id in project_ids:
        scans = db.execute(
            """
            SELECT id, scan_number FROM scan_runs
            WHERE project_id = ?
            ORDER BY id
            """,
            (project_id,),
        ).fetchall()
        used_numbers = {scan["scan_number"] for scan in scans if scan["scan_number"] is not None}
        next_number = 1
        for scan in scans:
            if scan["scan_number"] is not None:
                continue
            while next_number in used_numbers:
                next_number += 1
            db.execute(
                "UPDATE scan_runs SET scan_number = ? WHERE id = ?",
                (next_number, scan["id"]),
            )
            used_numbers.add(next_number)
            next_number += 1
    repair_scan_numbers_from_report_filenames(db)


def repair_scan_numbers_from_report_filenames(db):
    rows = db.execute(
        """
        SELECT scan_runs.id AS scan_id,
               scan_runs.project_id,
               scan_runs.scan_number,
               reports.filename
        FROM scan_runs
        JOIN reports ON reports.scan_run_id = scan_runs.id
        ORDER BY scan_runs.project_id, scan_runs.id, reports.id
        """
    ).fetchall()
    proposed = {}
    for row in rows:
        match = REPORT_SCAN_NUMBER_PATTERN.search(row["filename"])
        if not match:
            continue
        parsed_number = int(match.group(1))
        if row["scan_number"] is None or parsed_number > row["scan_number"]:
            proposed[row["scan_id"]] = parsed_number

    for scan_id, scan_number in proposed.items():
        owner = db.execute(
            "SELECT project_id FROM scan_runs WHERE id = ?", (scan_id,)
        ).fetchone()
        if owner is None:
            continue
        conflict = db.execute(
            """
            SELECT id FROM scan_runs
            WHERE project_id = ? AND scan_number = ? AND id != ?
            """,
            (owner["project_id"], scan_number, scan_id),
        ).fetchone()
        if conflict is None:
            db.execute(
                "UPDATE scan_runs SET scan_number = ? WHERE id = ?",
                (scan_number, scan_id),
            )


def migrate_report_numbers(db):
    columns = table_columns(db, "reports")
    if "report_number" not in columns:
        db.execute("ALTER TABLE reports ADD COLUMN report_number INTEGER")

    project_ids = [
        row["project_id"]
        for row in db.execute("SELECT DISTINCT project_id FROM reports ORDER BY project_id")
    ]
    for project_id in project_ids:
        reports = db.execute(
            """
            SELECT id, report_number FROM reports
            WHERE project_id = ?
            ORDER BY id
            """,
            (project_id,),
        ).fetchall()
        used_numbers = {report["report_number"] for report in reports if report["report_number"] is not None}
        next_number = 1
        for report in reports:
            if report["report_number"] is not None:
                continue
            while next_number in used_numbers:
                next_number += 1
            db.execute(
                "UPDATE reports SET report_number = ? WHERE id = ?",
                (next_number, report["id"]),
            )
            used_numbers.add(next_number)
            next_number += 1


def refresh_project_counters(db):
    projects = db.execute("SELECT id FROM projects ORDER BY id").fetchall()
    for project in projects:
        project_id = project["id"]
        next_scan_number = db.execute(
            "SELECT COALESCE(MAX(scan_number), 0) + 1 FROM scan_runs WHERE project_id = ?",
            (project_id,),
        ).fetchone()[0]
        next_report_number = db.execute(
            "SELECT COALESCE(MAX(report_number), 0) + 1 FROM reports WHERE project_id = ?",
            (project_id,),
        ).fetchone()[0]
        db.execute(
            """
            UPDATE projects
            SET next_scan_number = CASE
                    WHEN next_scan_number IS NULL OR next_scan_number < ? THEN ?
                    ELSE next_scan_number
                END,
                next_report_number = CASE
                    WHEN next_report_number IS NULL OR next_report_number < ? THEN ?
                    ELSE next_report_number
                END
            WHERE id = ?
            """,
            (
                next_scan_number,
                next_scan_number,
                next_report_number,
                next_report_number,
                project_id,
            ),
        )


def rebuild_result_table(db, table):
    legacy_table = f"{table}_legacy_migration"
    db.execute(f"ALTER TABLE {table} RENAME TO {legacy_table}")
    db.execute(RESULT_TABLE_SCHEMAS[table])
    db.execute(
        f"""
        INSERT INTO scan_runs (project_id, scan_number, started_at, finished_at, status)
        SELECT source.project_id,
               1,
               COALESCE(MIN(source.created_at), ?),
               COALESCE(MAX(source.created_at), ?),
               'completed'
        FROM {legacy_table} source
        WHERE NOT EXISTS (
            SELECT 1 FROM scan_runs sr WHERE sr.project_id = source.project_id
        )
        GROUP BY source.project_id
        """,
        (utc_now(), utc_now()),
    )

    target_columns = [column for column in RESULT_TABLE_COLUMNS[table] if column != "id"]
    select_expressions = []
    for column in target_columns:
        if column == "scan_run_id":
            select_expressions.append(
                """
                (
                    SELECT sr.id
                    FROM scan_runs sr
                    WHERE sr.project_id = source.project_id
                    ORDER BY sr.id DESC
                    LIMIT 1
                )
                """
            )
        else:
            select_expressions.append(f"source.{column}")

    db.execute(
        f"""
        INSERT OR IGNORE INTO {table} ({", ".join(target_columns)})
        SELECT {", ".join(select_expressions)}
        FROM {legacy_table} source
        """
    )
    db.execute(f"DROP TABLE {legacy_table}")


@contextmanager
def transaction():
    db = get_db()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise


def insert_rows(table, columns, rows, replace=False):
    if not rows:
        return
    placeholders = ", ".join("?" for _ in columns)
    column_sql = ", ".join(columns)
    operation = "INSERT OR REPLACE" if replace else "INSERT OR IGNORE"
    sql = f"{operation} INTO {table} ({column_sql}) VALUES ({placeholders})"
    with transaction() as db:
        db.executemany(sql, rows)


def get_project(project_id):
    return get_db().execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()


def get_running_scan(project_id):
    return get_db().execute(
        """
        SELECT * FROM scan_runs
        WHERE project_id = ? AND status = ?
        ORDER BY scan_number DESC
        LIMIT 1
        """,
        (project_id, "running"),
    ).fetchone()


def create_scan_run(project_id):
    with transaction() as db:
        project = db.execute(
            "SELECT next_scan_number FROM projects WHERE id = ?",
            (project_id,),
        ).fetchone()
        if project is None:
            raise ValueError(f"Project {project_id} does not exist")
        next_scan_number = project["next_scan_number"] or 1
        cursor = db.execute(
            """
            INSERT INTO scan_runs (project_id, scan_number, started_at, status)
            VALUES (?, ?, ?, ?)
            """,
            (project_id, next_scan_number, utc_now(), "running"),
        )
        db.execute(
            "UPDATE projects SET next_scan_number = ? WHERE id = ?",
            (next_scan_number + 1, project_id),
        )
        return cursor.lastrowid


def get_latest_scan_run(project_id):
    return get_db().execute(
        """
        SELECT * FROM scan_runs
        WHERE project_id = ? AND status != 'running'
        ORDER BY scan_number DESC
        LIMIT 1
        """,
        (project_id,),
    ).fetchone()


def get_previous_scan_run(project_id, scan_id):
    return get_db().execute(
        """
        SELECT * FROM scan_runs
        WHERE project_id = ?
          AND scan_number < (
              SELECT scan_number FROM scan_runs WHERE project_id = ? AND id = ?
          )
          AND status != 'running'
        ORDER BY scan_number DESC
        LIMIT 1
        """,
        (project_id, project_id, scan_id),
    ).fetchone()


def get_scan_run(project_id, scan_id):
    return get_db().execute(
        "SELECT * FROM scan_runs WHERE project_id = ? AND id = ?",
        (project_id, scan_id),
    ).fetchone()


def get_scan_runs(project_id, scan_ids):
    if not scan_ids:
        return []
    placeholders = ", ".join("?" for _ in scan_ids)
    return get_db().execute(
        f"""
        SELECT * FROM scan_runs
        WHERE project_id = ? AND id IN ({placeholders})
        ORDER BY scan_number
        """,
        (project_id, *scan_ids),
    ).fetchall()


def list_scan_runs(project_id, limit=5):
    return get_db().execute(
        "SELECT * FROM scan_runs WHERE project_id = ? ORDER BY scan_number DESC LIMIT ?",
        (project_id, limit),
    ).fetchall()


def scan_summary(scan_run_id):
    db = get_db()
    if scan_run_id is None:
        return empty_summary()
    return {
        "subdomains": db.execute(
            "SELECT COUNT(*) FROM subdomains WHERE scan_run_id = ?", (scan_run_id,)
        ).fetchone()[0],
        "dns_records": db.execute(
            "SELECT COUNT(*) FROM dns_records WHERE scan_run_id = ?", (scan_run_id,)
        ).fetchone()[0],
        "http_results": db.execute(
            "SELECT COUNT(*) FROM http_results WHERE scan_run_id = ?", (scan_run_id,)
        ).fetchone()[0],
        "emails": db.execute(
            "SELECT COUNT(*) FROM emails WHERE scan_run_id = ?", (scan_run_id,)
        ).fetchone()[0],
        "missing_headers": db.execute(
            "SELECT COUNT(*) FROM security_headers WHERE scan_run_id = ? AND present = 0",
            (scan_run_id,),
        ).fetchone()[0],
    }


def empty_summary():
    return {
        "subdomains": 0,
        "dns_records": 0,
        "http_results": 0,
        "emails": 0,
        "missing_headers": 0,
    }


def list_scan_runs_with_summary(project_id, limit=5):
    return [
        {"scan": scan, "summary": scan_summary(scan["id"])}
        for scan in list_scan_runs(project_id, limit)
    ]


def project_summary(project_id, scan_run_id=None):
    scan = get_latest_scan_run(project_id) if scan_run_id is None else get_scan_run(project_id, scan_run_id)
    return scan_summary(scan["id"] if scan else None)


def fetch_project_data(project_id, scan_run_id=None):
    db = get_db()
    scan = get_latest_scan_run(project_id) if scan_run_id is None else get_scan_run(project_id, scan_run_id)
    data = {}
    if scan is None:
        for table in RESULT_TABLES:
            data[table] = []
        return data

    for table in RESULT_TABLES:
        data[table] = db.execute(
            f"""
            SELECT * FROM {table}
            WHERE project_id = ? AND scan_run_id = ?
            ORDER BY id DESC
            """,
            (project_id, scan["id"]),
        ).fetchall()
    return data


def prune_old_scan_runs(project_id, keep=5):
    with transaction() as db:
        db.execute(
            """
            DELETE FROM scan_runs
            WHERE project_id = ?
              AND id NOT IN (
                  SELECT id FROM scan_runs
                  WHERE project_id = ?
                  ORDER BY scan_number DESC
                  LIMIT ?
              )
            """,
            (project_id, project_id, keep),
        )


def delete_scan(project_id, scan_id):
    with transaction() as db:
        scan = db.execute(
            "SELECT * FROM scan_runs WHERE project_id = ? AND id = ?",
            (project_id, scan_id),
        ).fetchone()
        if scan is not None and scan["status"] != "running":
            db.execute("DELETE FROM scan_runs WHERE id = ?", (scan["id"],))
        return scan


def delete_scans(project_id, scan_ids):
    with transaction() as db:
        if not scan_ids:
            return []
        placeholders = ", ".join("?" for _ in scan_ids)
        scans = db.execute(
            f"""
            SELECT * FROM scan_runs
            WHERE project_id = ? AND id IN ({placeholders}) AND status != 'running'
            ORDER BY scan_number
            """,
            (project_id, *scan_ids),
        ).fetchall()
        if scans:
            delete_placeholders = ", ".join("?" for _ in scans)
            db.execute(
                f"DELETE FROM scan_runs WHERE id IN ({delete_placeholders})",
                tuple(scan["id"] for scan in scans),
            )
        return scans


def delete_all_scans(project_id):
    with transaction() as db:
        scans = db.execute(
            """
            SELECT * FROM scan_runs
            WHERE project_id = ? AND status != 'running'
            ORDER BY scan_number
            """,
            (project_id,),
        ).fetchall()
        db.execute(
            "DELETE FROM scan_runs WHERE project_id = ? AND status != 'running'",
            (project_id,),
        )
        return scans


def insert_report(project_id, scan_run_id, display_name, filename):
    with transaction() as db:
        project = db.execute(
            "SELECT next_report_number FROM projects WHERE id = ?",
            (project_id,),
        ).fetchone()
        if project is None:
            raise ValueError(f"Project {project_id} does not exist")
        next_report_number = project["next_report_number"] or 1
        cursor = db.execute(
            """
            INSERT INTO reports (
                project_id,
                scan_run_id,
                report_number,
                display_name,
                filename,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                project_id,
                scan_run_id,
                next_report_number,
                display_name,
                filename,
                utc_now(),
            ),
        )
        db.execute(
            "UPDATE projects SET next_report_number = ? WHERE id = ?",
            (next_report_number + 1, project_id),
        )
        return cursor.lastrowid


def count_reports(project_id):
    return get_db().execute(
        "SELECT COUNT(*) FROM reports WHERE project_id = ?", (project_id,)
    ).fetchone()[0]


def list_reports(project_id):
    return get_db().execute(
        """
        SELECT reports.*,
               scan_runs.scan_number AS scan_number,
               scan_runs.started_at AS scan_started_at,
               scan_runs.status AS scan_status
        FROM reports
        LEFT JOIN scan_runs ON scan_runs.id = reports.scan_run_id
        WHERE reports.project_id = ?
        ORDER BY reports.id DESC
        """,
        (project_id,),
    ).fetchall()


def get_report(project_id, report_id):
    return get_db().execute(
        "SELECT * FROM reports WHERE project_id = ? AND id = ?", (project_id, report_id)
    ).fetchone()


def get_report_by_filename(filename):
    return get_db().execute("SELECT * FROM reports WHERE filename = ?", (filename,)).fetchone()


def rename_report(project_id, report_id, display_name):
    with transaction() as db:
        db.execute(
            "UPDATE reports SET display_name = ? WHERE project_id = ? AND id = ?",
            (display_name, project_id, report_id),
        )


def delete_report(project_id, report_id):
    with transaction() as db:
        report = db.execute(
            "SELECT * FROM reports WHERE project_id = ? AND id = ?",
            (project_id, report_id),
        ).fetchone()
        if report is not None:
            db.execute("DELETE FROM reports WHERE id = ?", (report["id"],))
        return report


def delete_project(project_id):
    with transaction() as db:
        project = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        if project is not None:
            db.execute("DELETE FROM projects WHERE id = ?", (project_id,))
        return project


def prune_old_reports(project_id, keep=10):
    with transaction() as db:
        old_reports = db.execute(
            """
            SELECT * FROM reports
            WHERE project_id = ?
            ORDER BY id DESC
            LIMIT -1 OFFSET ?
            """,
            (project_id, keep),
        ).fetchall()
        db.executemany(
            "DELETE FROM reports WHERE id = ?",
            [(report["id"],) for report in old_reports],
        )
        return old_reports


def init_app(app):
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()
