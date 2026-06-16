import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from flask import current_app, g


SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company_name TEXT NOT NULL,
    root_domain TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS dns_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    record_type TEXT NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(project_id, record_type, name, value),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    subdomain TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(project_id, subdomain),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS whois_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    raw_text TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS http_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    status_code INTEGER,
    title TEXT,
    server_header TEXT,
    final_url TEXT,
    https_available INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    UNIQUE(project_id, url),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS security_headers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    header_name TEXT NOT NULL,
    header_value TEXT,
    present INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(project_id, url, header_name),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    email TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(project_id, email),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tls_certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    hostname TEXT NOT NULL,
    issuer TEXT,
    subject TEXT,
    not_before TEXT,
    not_after TEXT,
    san_names TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(project_id, hostname),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS raw_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    module_name TEXT NOT NULL,
    raw_output TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);
"""

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
    get_db().executescript(SCHEMA)
    get_db().commit()


@contextmanager
def transaction():
    db = get_db()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise


def clear_project_results(project_id):
    with transaction() as db:
        for table in RESULT_TABLES:
            db.execute(f"DELETE FROM {table} WHERE project_id = ?", (project_id,))


def insert_rows(table, columns, rows, replace=False):
    if not rows:
        return
    placeholders = ", ".join("?" for _ in columns)
    column_sql = ", ".join(columns)
    operation = "INSERT OR REPLACE" if replace else "INSERT OR IGNORE"
    sql = f"{operation} INTO {table} ({column_sql}) VALUES ({placeholders})"
    with transaction() as db:
        db.executemany(sql, rows)


def fetch_project_data(project_id):
    db = get_db()
    data = {}
    for table in RESULT_TABLES:
        data[table] = db.execute(
            f"SELECT * FROM {table} WHERE project_id = ? ORDER BY id DESC",
            (project_id,),
        ).fetchall()
    return data


def init_app(app):
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()
