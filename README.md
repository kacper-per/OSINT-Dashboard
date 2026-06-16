# OSINT Recon Dashboard

A beginner-friendly local Flask application for the first, passive phase of an
authorized security assessment. Create a project for an organization and root
domain, run public-source reconnaissance, review normalized findings in a
dashboard, and export a standalone HTML report.

The working MVP uses only free public sources and free Python libraries. It
does not require API keys or paid services.

## What It Collects

- Public DNS records: A, AAAA, MX, NS, TXT, and CNAME
- Subdomains found in the free crt.sh certificate-transparency feed
- Basic HTTP/HTTPS availability, redirects, page titles, and Server headers
- Six common HTTP security headers
- Public WHOIS data
- Publicly presented TLS certificate details and SAN names
- Email addresses displayed on the root-domain homepage

Results are deduplicated and stored locally in SQLite. A failed module does not
stop the rest of a scan; warnings are saved under **Raw Results**.

## Ethical and Legal Note

This tool performs passive OSINT reconnaissance using public sources and basic
non-invasive HTTP checks. It does not exploit vulnerabilities, brute-force
credentials, attack systems, bypass authentication, or perform aggressive
scanning. It should only be used for educational purposes, authorized
assessments, or domains owned/approved by the user.

Public data may be stale, incomplete, redacted, or misleading. Treat the output
as assessment input, not proof of a vulnerability.

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
5. Select **Generate report** to create `reports/project-<id>-report.html`.

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

- Scans run synchronously in the Flask development process. Keep the browser
  tab open until the scan completes.
- Existing normalized findings are refreshed at the start of each scan; scan
  run history remains available.
- The email finder inspects only the homepage and does not crawl the site.
- HTTP probing checks only HTTP and HTTPS. It is not a port scanner.
- WHOIS availability and format vary by registry.
- TLS collection requires a valid certificate trusted by the local system.
- Bootstrap and Chart.js are loaded from public CDNs. The application and its
  evidence tables still function if Chart.js is unavailable.

Future improvements could add background jobs, scan snapshots, local vendored
UI assets, authenticated user accounts, or optional integrations. Paid APIs are
deliberately outside this MVP.
