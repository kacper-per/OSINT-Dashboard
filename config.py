import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-for-production")
    DATABASE_PATH = Path(os.environ.get("DATABASE_PATH", BASE_DIR / "data" / "osint.db"))
    REPORTS_DIR = Path(os.environ.get("REPORTS_DIR", BASE_DIR / "reports"))
    REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "8"))
    TLS_TIMEOUT = int(os.environ.get("TLS_TIMEOUT", "6"))
    MAX_SUBDOMAINS_TO_PROBE = int(os.environ.get("MAX_SUBDOMAINS_TO_PROBE", "50"))
    CRTSH_TIMEOUT = int(os.environ.get("CRTSH_TIMEOUT", "30"))
    SCAN_HISTORY_LIMIT = int(os.environ.get("SCAN_HISTORY_LIMIT", "5"))
    REPORT_LIMIT = int(os.environ.get("REPORT_LIMIT", "10"))
    CRTSH_RETRIES = int(os.environ.get("CRTSH_RETRIES", "2"))
    CRTSH_BACKOFF_FACTOR = float(os.environ.get("CRTSH_BACKOFF_FACTOR", "2"))
    CRTSH_MAX_TIMEOUT = int(os.environ.get("CRTSH_MAX_TIMEOUT", "120"))
    CRTSH_RETRY_DELAY = float(os.environ.get("CRTSH_RETRY_DELAY", "1"))
    USER_AGENT = os.environ.get(
        "USER_AGENT",
        "OSINT-Recon-Dashboard/1.0 (passive authorized reconnaissance)",
    )
