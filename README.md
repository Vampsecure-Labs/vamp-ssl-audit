<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->
<h1 align="center">vamp-ssl-audit</h1>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white" alt="Python 3.9+"/>
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey" alt="Platform"/>
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License MIT"/>
  <img src="https://img.shields.io/badge/VampSecure-Labs-magenta" alt="VampSecure Labs"/>
  <img src="https://github.com/Vampsecure-Labs/vamp-ssl-audit/actions/workflows/ci.yml/badge.svg" alt="CI"/>
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
pip install vamp-ssl-audit
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-ssl-audit
```

```bash
git clone https://github.com/Vampsecure-Labs/vamp-ssl-audit.git
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

## Try it now — public test targets

These hosts are publicly provided for testing TLS tools:

```bash
# Expired certificate → grade F
python3 vamp_ssl_audit.py -H expired.badssl.com

# Self-signed certificate → grade T
python3 vamp_ssl_audit.py -H self-signed.badssl.com

# TLS 1.0 still accepted → HIGH finding, grade cap B
python3 vamp_ssl_audit.py -H tls-v1.badssl.com

# SHA-1 signature → HIGH finding
python3 vamp_ssl_audit.py -H sha1-2016.badssl.com

# Clean A grade (standard well-configured host)
python3 vamp_ssl_audit.py -H badssl.com
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

# With Let's Encrypt auto-renewal active, 90d alerts are noise — use 30d instead
python3 vamp_ssl_audit.py --file hosts.txt --warn-days 30

# Scan a non-HTTPS service on a custom default port
python3 vamp_ssl_audit.py --file smtp_hosts.txt --port 587

# Generate client-ready engagement report (HTML + PDF)
python3 vamp_ssl_audit.py --file hosts.txt \
    --client "Acme Corp" --engagement "TLS Configuration Review Q3 2026" \
    --auditor "J. Smith" --report-html client_report.html --report-pdf client_report.pdf
```

## CI/CD Integration

Drop this into `.github/workflows/ssl-audit.yml` to gate your pipeline on TLS grade:

```yaml
name: TLS Audit
on:
  schedule:
    - cron: '0 6 * * 1'   # weekly on Monday
  workflow_dispatch:

jobs:
  ssl-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install vamp-ssl-audit
      - run: |
          vamp-ssl-audit \
            -H yourdomain.com \
            -H api.yourdomain.com \
            --warn-days 30 \
            --json ssl-results.json \
            --markdown ssl-report.md
        # Exit code 1 = HIGH findings, 2 = CRITICAL findings → pipeline fails
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: ssl-audit-report
          path: ssl-report.md
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
| `--warn-days N` | 90 | Days ahead to issue MEDIUM cert-expiry alert. With Let's Encrypt auto-renewal, `--warn-days 30` avoids noise (renewal runs at 30d, not 90d) |
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
| A+ | TLS 1.3 active, HSTS present and complete, no legacy protocols or weak ciphers |
| A | Good configuration; HSTS absent or TLS 1.3 not offered |
| A- | Good configuration; HSTS incomplete (short max-age, no includeSubDomains) |
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

## Sample Output

```
$ python3 vamp_ssl_audit.py -H expired.badssl.com -H self-signed.badssl.com -H badssl.com
vamp-ssl-audit v1.3.0 — TLS/SSL Professional Auditor · VampSecure Labs
──────────────────────────────────────────────────────────────────────
Auditing 3 hosts with 3 workers...

┌────────────────────────┬───────┬────────┬────────────────────────────────────┐
│ Host                   │ Grade │ Proto  │ Top Finding                        │
├────────────────────────┼───────┼────────┼────────────────────────────────────┤
│ expired.badssl.com     │  F    │ TLS1.2 │ [CRITICAL] Certificate expired     │
│ self-signed.badssl.com │  T    │ TLS1.2 │ [HIGH] Self-signed certificate     │
│ badssl.com             │  A    │ TLS1.3 │ No critical issues                 │
└────────────────────────┴───────┴────────┴────────────────────────────────────┘

── expired.badssl.com ──────────────────────────────────────────────────────
  [CRITICAL] Certificate expired 2015-04-09 (3829 days ago)
             Remediation: renew certificate immediately (e.g. certbot renew)
  Grade cap: F

── self-signed.badssl.com ──────────────────────────────────────────────────
  [HIGH] Self-signed certificate — not trusted by any public CA
         Remediation: replace with a certificate issued by a trusted CA
  Grade cap: T

── badssl.com ──────────────────────────────────────────────────────────────
  [INFO] TLS 1.3 supported                       ✓
  [INFO] HSTS present (max-age=31536000)          ✓
  [INFO] Certificate valid for 87 days            ✓
  Grade: A

3 hosts audited in 2.4s · 2 findings (1 CRITICAL, 1 HIGH)
Exit code: 2
```

## Why vamp-ssl-audit vs. testssl.sh · SSL Labs API · nmap ssl-enum-ciphers

| Capability | vamp-ssl-audit | testssl.sh | SSL Labs API | nmap ssl-enum-ciphers |
|------------|----------------|------------|--------------|----------------------|
| A+–F grading (SSLabs-style) | ✅ | ✅ | ✅ (authoritative) | ❌ |
| Runs fully local / offline | ✅ | ✅ | ❌ Cloud only | ✅ |
| Multi-host concurrent scan | ✅ `--workers N` | ❌ Sequential | ❌ | ❌ |
| HSTS / DANE / CT log checks | ✅ | ✅ | ✅ | ❌ |
| mTLS / client cert validation | ✅ | ✅ | ❌ | ❌ |
| OCSP stapling check | ✅ | ✅ | ✅ | ❌ |
| `--watch N` daemon mode | ✅ | ❌ | ❌ | ❌ |
| `--delta FILE` regression tracking | ✅ | ❌ | ❌ | ❌ |
| JSON + HTML + Markdown + CSV export | ✅ | ✅ JSON | ✅ JSON | ❌ |
| VSL engagement report (HTML / PDF) | ✅ `vampsec_report` | ❌ | ❌ | ❌ |
| CI/CD exit codes (0 / 1 / 2) | ✅ | ✅ | ❌ | ❌ |
| Python importable package | ✅ | ❌ Bash | ❌ | ❌ |

- **Concurrent scanning** — `--workers 10` audits a 50-host TLS inventory in under a minute; testssl.sh runs sequentially and SSL Labs throttles at ~3 requests/min per IP.
- **Continuous monitoring** — `--watch N` combined with `--delta FILE` surfaces only newly degraded hosts on each run, turning a one-shot tool into a change-alert system.
- **CI/CD native** — exit codes 0/1/2 gate pipelines directly; the bundled GitHub Actions snippet is ready to copy into `.github/workflows/`.
- **Self-hosted** — SSL Labs requires an internet-reachable target and may queue requests; `vamp-ssl-audit` runs on air-gapped networks and internal lab environments without sending host data to a third party.

## Check Coverage

| Check | Standard | Grade cap |
|-------|----------|-----------|
| SSLv3 accepted | NIST SP 800-52r2 §3.3.1 | C |
| TLS 1.0 / TLS 1.1 present | RFC 8996 / NIST SP 800-52r2 | B |
| NULL / EXPORT / ADH / AECDH cipher suites | NIST SP 800-52r2 §3.3.3 | F |
| RC4 / DES / 3DES cipher suites | CIS Control 3.10 / RFC 7465 | C–B |
| Certificate expiry (default 90-day warning) | CIS Control 3.10 | F (expired) / MEDIUM |
| RSA key < 1024 bits | NIST SP 800-131Ar2 | F |
| RSA key < 2048 bits | NIST SP 800-131Ar2 | B |
| EC key < 224 bits | NIST SP 800-186 | B |
| SHA-1 / MD5 signature algorithm | NIST SP 800-131Ar2 | B–C |
| Self-signed certificate | CIS Control 3.10 | T |
| Hostname mismatch (SAN / CN coverage) | RFC 6125 | T |
| HSTS absence or short max-age | OWASP HSTS / RFC 6797 | A– |
| OCSP stapling | RFC 6960 | INFO |
| DANE / TLSA record | RFC 6698 | INFO |
| Certificate Transparency log presence | RFC 9162 | INFO |
| mTLS mutual authentication | NIST SP 800-52r2 §3.2 | INFO |

## Legal Notice

Use exclusively on systems you own or for which you hold explicit written authorization from the system owner. VampSecure Studios assumes no liability for unauthorized use.

## Part of VampSecure Labs Toolkit

`vamp-ssl-audit` is one tool in the VampSecure Labs security research toolkit. For the full toolkit including the orchestrator that runs all tools in sequence and aggregates findings into a single engagement report, see:

- Portfolio: [github.com/Vampsecure-Labs](https://github.com/Vampsecure-Labs)
- Orchestrator: [github.com/Vampsecure-Labs/vamp-orchestrator](https://github.com/Vampsecure-Labs/vamp-orchestrator)

---

© VampSecure Studios — VampSecure Labs Security Research Division

## Historial de versiones

| Versión | Cambios principales |
|---------|---------------------|
| v1.7.0 | CLI unificado con subcomandos; paquete importable (S3 modularización) |
| v1.6.0 | `--delta FILE` — diff NEW/RECURRING/RESOLVED entre escaneos |
| v1.5.0 | `--watch N` daemon mode; `--warn-days` cert-expiry; `--report-pdf` fpdf2 |
| v1.4.0 | Markdown/CSV export; VSL engagement report (`--report-html/pdf`) |
| v1.3.0 | HTML dark-theme report; multi-host batch scanning |
| v1.0.0 | MVP TLS/SSL auditor — grading A+…F, protocol/cipher/cert checks |

---

© VampSecure Studios — VampSecure Labs Security Research Division
