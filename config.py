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
    USER_AGENT = os.environ.get(
        "USER_AGENT",
        "OSINT-Recon-Dashboard/1.0 (passive authorized reconnaissance)",
    )
