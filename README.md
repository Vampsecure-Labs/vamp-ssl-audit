<h1 align="center">vamp-ssl-audit</h1>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white" alt="Python 3.9+"/>
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey" alt="Platform"/>
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License MIT"/>
  <img src="https://img.shields.io/badge/VampSecure-Labs-magenta" alt="VampSecure Labs"/>
</p>

## Overview

`vamp-ssl-audit` is a professional TLS/SSL configuration auditor with an SSLabs-inspired A+–F grading system. It tests protocol support (SSLv3 through TLS 1.3), cipher suite quality, certificate validity and key strength, and HTTP security headers. Each finding includes a concrete remediation recommendation. Reports export to JSON, HTML (dark-theme with grade badge), Markdown, and CSV — making it suitable for both interactive assessments and automated CI/CD pipelines.

## Features

- SSLabs-style letter grading from A+ (TLS 1.3 + complete HSTS + no legacy protocols) to F (null cipher, expired certificate, or connection failure)
- Protocol detection: SSLv3 (CRITICAL, grade cap C), TLS 1.0/1.1 (CRITICAL/HIGH, cap B), TLS 1.2 (info), TLS 1.3 (info)
- Cipher suite analysis: NULL/EXPORT/ADH/AECDH ciphers (CRITICAL, cap F); RC4/DES/MD5 (CRITICAL, cap C); 3DES (HIGH, cap B)
- Certificate inspection: expiry and days remaining, key type and size (RSA < 1024 CRITICAL/F; RSA < 2048 HIGH/B; EC < 224 HIGH/B; DSA HIGH/B), signature algorithm (MD5 CRITICAL/C; SHA-1 HIGH/B), self-signed detection (HIGH/T), hostname coverage via SAN and CN
- HTTP security header checks alongside TLS: HSTS (presence, `max-age`, `includeSubDomains`, `preload`), X-Frame-Options, X-Content-Type-Options
- Multi-host concurrent scanning with configurable thread pool (`--workers`, default 5)
- Custom port support (`--port`, default 443) and per-host `HOST:PORT` notation
- Export to Console (Rich), JSON, HTML (dark-theme standalone with grade badge), Markdown, and CSV

## Requirements

- Python 3.9 or later
- `cryptography >= 41.0.0`
- `rich >= 13.7.0`

## Installation

```bash
git clone https://github.com/belky-me/vamp-ssl-audit.git
cd vamp-ssl-audit
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```
python3 vamp_ssl_audit.py --help
```

```
usage: vamp_ssl_audit.py [-h] [-H HOST[:PORT]] [--file FILE]
                          [--port PORT] [--timeout TIMEOUT] [--workers WORKERS]
                          [--json FILE] [--html FILE]
                          [--markdown FILE] [--csv FILE]
                          [--client CLIENT] [--engagement ENGAGEMENT]
                          [--auditor AUDITOR] [--report-scope SCOPE]
                          [--report-html FILE] [--report-pdf FILE]

vamp-ssl-audit — TLS/SSL Professional Auditor (VampSecure Labs)
```

## Examples

```bash
# Audit a single host on default port 443
python3 vamp_ssl_audit.py -H example.com

# Audit with a non-standard port inline
python3 vamp_ssl_audit.py -H example.com:8443

# Audit multiple hosts in one command
python3 vamp_ssl_audit.py -H example.com -H api.example.com -H legacy.example.com

# Audit a list of hosts from file with 10 parallel workers
python3 vamp_ssl_audit.py --file hosts.txt --workers 10

# Export results to all formats
python3 vamp_ssl_audit.py -H example.com \
    --json results.json --html report.html --markdown report.md --csv report.csv

# Scan a non-HTTPS service on a custom default port
python3 vamp_ssl_audit.py --file smtp_hosts.txt --port 587

# Generate client-ready engagement report (HTML + PDF)
python3 vamp_ssl_audit.py --file hosts.txt \
    --client "Acme Corp" --engagement "TLS Configuration Review Q3 2026" \
    --auditor "J. Smith" --report-html client_report.html --report-pdf client_report.pdf
```

## CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `-H / --host HOST[:PORT]` | — | Target host, optionally with port (repeatable) |
| `--file FILE` | — | Text file with one host (or host:port) per line |
| `--port N` | 443 | Default port when not specified inline |
| `--timeout N` | 10 | Per-connection timeout in seconds |
| `--workers N` | 5 | Concurrent worker threads |
| `--json FILE` | — | Export results to JSON |
| `--html FILE` | — | Export dark-theme HTML report with grade badge |
| `--markdown FILE` | — | Export Markdown report |
| `--csv FILE` | — | Export CSV summary (+ `FILE.findings` detail file) |
| `--client TEXT` | — | Client name for VSL engagement report |
| `--engagement TEXT` | — | Engagement title for VSL engagement report |
| `--auditor TEXT` | — | Auditor name for VSL engagement report |
| `--report-scope TEXT` | — | Scope description for VSL engagement report |
| `--report-html FILE` | — | Export unified VSL client report (HTML) |
| `--report-pdf FILE` | — | Export unified VSL client report (PDF, requires fpdf2) |

## Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| Console | (default) | Rich-colored graded output with finding tables and remediations |
| JSON | `--json FILE` | Machine-readable full result set |
| HTML | `--html FILE` | Dark-theme standalone report with letter-grade badge |
| Markdown | `--markdown FILE` | Portable report for audit repositories |
| CSV | `--csv FILE` | Summary row per host + `FILE.findings` with one row per finding |
| Client HTML | `--report-html FILE` | Unified VampSecure Labs engagement report |
| Client PDF | `--report-pdf FILE` | PDF version of the VSL client report |

## Grading Scale

| Grade | Criteria |
|-------|----------|
| A+ | TLS 1.3 active, complete HSTS, no legacy protocols or weak ciphers |
| A | Good configuration; no significant issues |
| A- | Good configuration; HSTS incomplete or TLS 1.3 not offered |
| B | TLS 1.0/1.1 present, 3DES, SHA-1 signature, or RSA < 2048 |
| C | SSLv3 accepted, RC4, or MD5 signature algorithm |
| D | Very poor configuration |
| T | Certificate not trusted: self-signed or hostname mismatch |
| F | Critical failure: null cipher, expired certificate, or connection error |

## Exit Codes

| Code | Meaning | CI/CD Behavior |
|------|---------|----------------|
| `0` | No critical or high findings | Pipeline passes |
| `1` | High-severity findings detected | Pipeline fails — review required |
| `2` | Critical-severity findings detected | Pipeline fails — immediate action required |

## Legal Notice

Use exclusively on systems you own or for which you hold explicit written authorization from the system owner. VampSecure Studios assumes no liability for unauthorized use.

## Part of VampSecure Labs Toolkit

`vamp-ssl-audit` is one tool in the VampSecure Labs security research toolkit. For the full toolkit including the orchestrator that runs all tools in sequence and aggregates findings into a single engagement report, see:

- Portfolio: [github.com/belky-me](https://github.com/belky-me)
- Orchestrator: [github.com/belky-me/vamp-orchestrator](https://github.com/belky-me/vamp-orchestrator)

---

© VampSecure Studios — VampSecure Labs Security Research Division
