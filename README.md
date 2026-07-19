# OSINT Recon Dashboard

A beginner-friendly local Flask application for the first, passive phase of an
authorized security assessment.

The working MVP uses only free public sources and free Python libraries. It
does not require API keys or paid services.

## What It Collects

- Public DNS records: A, AAAA, MX, NS, TXT, and CNAME
- Subdomains found in the free crt.sh certificate-transparency feed
- Basic HTTP/HTTPS availability, redirects, page titles, and Server headers
- Six common HTTP security headers (More in future...)
- Public WHOIS data
- Publicly presented TLS certificate details and SAN names
- Email addresses displayed on the root-domain homepage (and more on demand)
- Optional deep email search across in-scope HTML pages for a selected scan

Results are saved and stored locally in SQLite. A failed module
does not stop the rest of a scan; warnings are saved under **Raw Results** and
the scan is marked `completed_with_errors`.

## Ethical and Legal Note

This tool performs passive OSINT reconnaissance using public sources and basic
non-invasive HTTP checks. It does not exploit vulnerabilities, brute-force
credentials, attack systems, bypass authentication, or perform aggressive
scanning.

## Setup

The project targets Python 3 on Linux, WSL, Kali, or Ubuntu.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000` in a browser.

On Windows PowerShell, activate the environment with:

```powershell
.\.venv\Scripts\Activate.ps1
```

## First Run

1. Start the Flask application with `python app.py`.
2. Select **Create project** and enter an organization plus a root domain such
   as `example.com`.
3. Open the project and select **Run reconnaissance**.
4. Review normalized results in the dashboard.
5. Run additional scans to build the last-five-scan history and compare the
   latest scan with the previous one.
6. In the **Emails** tab, optionally select **DEEP SEARCH FOR EMAILS** to crawl
   in-scope HTML pages for additional public email addresses.
7. Select **Generate report** to create a timestamped HTML snapshot for a
   specific scan.

Scans and reports are numbered per project. The database still keeps internal
global IDs, but the UI and reports show project-local numbers starting at `#1`.
Those counters keep increasing even when old scan results or HTML reports are
pruned by the configured limits.

The database is initialized automatically at `data/osint.db`. To initialize it
without starting the development server:

```bash
python -c "from app import app; print('Database initialized:', app.config['DATABASE_PATH'])"
```

## Configuration

These optional environment variables control local behavior:

| Variable | Default | Purpose |
| --- | ---: | --- |
| `SECRET_KEY` | development value | Flask session signing key |
| `DATABASE_PATH` | `data/osint.db` | SQLite database location |
| `REPORTS_DIR` | `reports/` | Generated report location |
| `REQUEST_TIMEOUT` | `8` | Network timeout in seconds |
| `TLS_TIMEOUT` | `6` | TLS connection timeout in seconds |
| `MAX_SUBDOMAINS_TO_PROBE` | `50` | Limits basic HTTP/TLS checks per scan |
| `EMAIL_CRAWL_MAX_PAGES` | `100` | Max in-scope HTML pages for manual deep email search |
| `EMAIL_CRAWL_MAX_BYTES` | `1048576` | Max bytes read from one crawled HTML page |
| `CRTSH_TIMEOUT` | `30` | Timeout for crt.sh subdomain discovery |
| `SCAN_HISTORY_LIMIT` | `5` | Number of scan result snapshots kept per project |
| `REPORT_LIMIT` | `10` | Number of HTML report files kept per project |
| `CRTSH_RETRIES` | `2` | Retries for temporary crt.sh failures |
| `CRTSH_BACKOFF_FACTOR` | `2` | Multiplier for each crt.sh retry timeout |
| `CRTSH_MAX_TIMEOUT` | `120` | Maximum timeout for a single crt.sh attempt |
| `CRTSH_RETRY_DELAY` | `1` | Delay between crt.sh retries, in seconds |
| `USER_AGENT` | application identifier | HTTP User-Agent string |

The subdomain probe limit is intentional: it keeps checks basic and
non-aggressive. crt.sh may return more names than the app probes.

## Project Structure

```text
osint-recon-dashboard/
|-- app.py
|-- config.py
|-- database.py
|-- modules/
|   |-- dns_lookup.py
|   |-- crtsh_lookup.py
|   |-- http_probe.py
|   |-- security_headers.py
|   |-- whois_lookup.py
|   |-- tls_info.py
|   `-- email_finder.py
|-- templates/
|-- static/
|-- data/
|-- reports/
`-- tests/
```

## Run Tests

Tests use local fake module results and do not query external services.

```bash
pytest
```

## Design and Limitations

- Scans run synchronously in the Flask development process. The scan button is
  replaced by stop and pause buttons.
- Scans can be paused or stopped, but the action takes effect only after 
  the currently running module finishes.
- The application keeps the latest scan result snapshots per project according
  to `SCAN_HISTORY_LIMIT`; older scan results are pruned.
- HTML reports are independent snapshots and are kept according to
  `REPORT_LIMIT`; report records may outlive the scan data they were generated
  from.
- The standard reconnaissance email finder inspects only the homepage. The
  optional deep email search crawls in-scope HTML pages only when manually
  triggered from a scan dashboard.
- HTTP probing checks only HTTP and HTTPS. It is not a port scanner.
- WHOIS availability and format vary by registry.
- TLS collection requires a valid certificate trusted by the local system.
- Bootstrap and Chart.js are loaded from public CDNs. The application and its
  evidence tables still function if Chart.js is unavailable.

Future improvements could add selection of security headers by user, option to restart
only part of the scan (for example, only one module if it's failed) amd
authenticated user accounts.
