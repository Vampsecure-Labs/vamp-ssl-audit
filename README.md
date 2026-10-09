<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->
<h1 align="center">vamp-ssl-audit</h1>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white" alt="Python 3.9+"/>
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey" alt="Platform"/>
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License MIT"/>
  <img src="https://img.shields.io/badge/VampSecure-Labs-magenta" alt="VampSecure Labs"/>
  <img src="https://github.com/Vampsecure-Labs/vamp-ssl-audit/actions/workflows/ci.yml/badge.svg" alt="CI"/>
</p>

> 🇬🇧 [English](#english) · 🇪🇸 [Español](#español)

---

<a name="english"></a>
## 🇬🇧 English

### Overview

`vamp-ssl-audit` is a professional TLS/SSL configuration auditor with an SSLabs-inspired A+–F grading system. It tests protocol support (SSLv3 through TLS 1.3), cipher suite quality, certificate validity and key strength, and HTTP security headers. Each finding includes a concrete remediation recommendation. Reports export to JSON, HTML (dark-theme with grade badge), Markdown, and CSV — making it suitable for both interactive assessments and automated CI/CD pipelines.

### Features

- SSLabs-style letter grading from A+ (TLS 1.3 + complete HSTS + no legacy protocols) to F (null cipher, expired certificate, or connection failure)
- Protocol detection: SSLv3 (CRITICAL, grade cap C), TLS 1.0/1.1 (CRITICAL/HIGH, cap B), TLS 1.2 (info), TLS 1.3 (info)
- Cipher suite analysis: NULL/EXPORT/ADH/AECDH ciphers (CRITICAL, cap F); RC4/DES/MD5 (CRITICAL, cap C); 3DES (HIGH, cap B)
- Certificate inspection: expiry and days remaining, key type and size (RSA < 1024 CRITICAL/F; RSA < 2048 HIGH/B; EC < 224 HIGH/B; DSA HIGH/B), signature algorithm (MD5 CRITICAL/C; SHA-1 HIGH/B), self-signed detection (HIGH/T), hostname coverage via SAN and CN
- HTTP security header checks alongside TLS: HSTS (presence, `max-age`, `includeSubDomains`, `preload`), X-Frame-Options, X-Content-Type-Options
- Multi-host concurrent scanning with configurable thread pool (`--workers`, default 5)
- Custom port support (`--port`, default 443) and per-host `HOST:PORT` notation
- Export to Console (Rich), JSON, HTML (dark-theme standalone with grade badge), Markdown, and CSV

### Requirements

- Python 3.9 or later
- `cryptography >= 41.0.0`
- `rich >= 13.7.0`

### Installation

```bash
pip install vamp-ssl-audit
# or with Homebrew:
brew install vampsecure-labs/labs/vamp-ssl-audit
```

```bash
git clone https://github.com/Vampsecure-Labs/vamp-ssl-audit.git
cd vamp-ssl-audit
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Usage

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

### Try it now — public test targets

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

### Examples

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

### CI/CD Integration

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

### CLI Reference

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

### Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| Console | (default) | Rich-colored graded output with finding tables and remediations |
| JSON | `--json FILE` | Machine-readable full result set |
| HTML | `--html FILE` | Dark-theme standalone report with letter-grade badge |
| Markdown | `--markdown FILE` | Portable report for audit repositories |
| CSV | `--csv FILE` | Summary row per host + `FILE.findings` with one row per finding |
| Client HTML | `--report-html FILE` | Unified VampSecure Labs engagement report |
| Client PDF | `--report-pdf FILE` | PDF version of the VSL client report |

### Grading Scale

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

### Exit Codes

| Code | Meaning | CI/CD Behavior |
|------|---------|----------------|
| `0` | No critical or high findings | Pipeline passes |
| `1` | High-severity findings detected | Pipeline fails — review required |
| `2` | Critical-severity findings detected | Pipeline fails — immediate action required |

### Sample Output

```
$ python3 vamp_ssl_audit.py -H expired.badssl.com -H self-signed.badssl.com -H badssl.com
vamp-ssl-audit v1.7.1 — TLS/SSL Professional Auditor · VampSecure Labs
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

### Why vamp-ssl-audit vs. testssl.sh · SSL Labs API · nmap ssl-enum-ciphers

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

### Check Coverage

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

### Legal Notice

Use exclusively on systems you own or for which you hold explicit written authorization from the system owner. VampSecure Studios assumes no liability for unauthorized use.

### Part of VampSecure Labs Toolkit

`vamp-ssl-audit` is one tool in the VampSecure Labs security research toolkit. For the full toolkit including the orchestrator that runs all tools in sequence and aggregates findings into a single engagement report, see:

- Portfolio: [github.com/Vampsecure-Labs](https://github.com/Vampsecure-Labs)
- Orchestrator: [github.com/Vampsecure-Labs/vamp-orchestrator](https://github.com/Vampsecure-Labs/vamp-orchestrator)

### Version History

| Version | Main changes |
|---------|-------------|
| v1.7.1 | Bilingual README (EN/ES) |
| v1.7.0 | Unified CLI with subcommands; importable package (S3 modularization) |
| v1.6.0 | `--delta FILE` — diff NEW/RECURRING/RESOLVED between scans |
| v1.5.0 | `--watch N` daemon mode; `--warn-days` cert-expiry; `--report-pdf` fpdf2 |
| v1.4.0 | Markdown/CSV export; VSL engagement report (`--report-html/pdf`) |
| v1.3.0 | HTML dark-theme report; multi-host batch scanning |
| v1.0.0 | MVP TLS/SSL auditor — grading A+…F, protocol/cipher/cert checks |

---

© VampSecure Studios — VampSecure Labs Security Research Division

---
---

<a name="español"></a>
## 🇪🇸 Español

### Descripción general

`vamp-ssl-audit` es un auditor profesional de configuración TLS/SSL con un sistema de calificación A+–F inspirado en SSLabs. Analiza el soporte de protocolos (de SSLv3 a TLS 1.3), la calidad de los cipher suites, la validez del certificado y la fortaleza de la clave, y las cabeceras de seguridad HTTP. Cada hallazgo incluye una recomendación de remediación concreta. Los informes se exportan a JSON, HTML (tema oscuro con badge de calificación), Markdown y CSV — lo que lo hace adecuado tanto para evaluaciones interactivas como para pipelines CI/CD automatizados.

### Características

- Calificación por letras estilo SSLabs de A+ (TLS 1.3 + HSTS completo + sin protocolos legacy) a F (cipher nulo, certificado caducado o fallo de conexión)
- Detección de protocolos: SSLv3 (CRITICAL, cap C), TLS 1.0/1.1 (CRITICAL/HIGH, cap B), TLS 1.2 (info), TLS 1.3 (info)
- Análisis de cipher suites: ciphers NULL/EXPORT/ADH/AECDH (CRITICAL, cap F); RC4/DES/MD5 (CRITICAL, cap C); 3DES (HIGH, cap B)
- Inspección de certificado: caducidad y días restantes, tipo y tamaño de clave (RSA < 1024 CRITICAL/F; RSA < 2048 HIGH/B; EC < 224 HIGH/B; DSA HIGH/B), algoritmo de firma (MD5 CRITICAL/C; SHA-1 HIGH/B), detección de autofirmado (HIGH/T), cobertura de hostname mediante SAN y CN
- Checks de cabeceras de seguridad HTTP junto con TLS: HSTS (presencia, `max-age`, `includeSubDomains`, `preload`), X-Frame-Options, X-Content-Type-Options
- Escaneo concurrente de múltiples hosts con pool de hilos configurable (`--workers`, por defecto 5)
- Soporte de puerto personalizado (`--port`, por defecto 443) y notación `HOST:PORT` por host
- Exportación a consola (Rich), JSON, HTML (dark-theme standalone con badge de calificación), Markdown y CSV

### Requisitos

- Python 3.9 o superior
- `cryptography >= 41.0.0`
- `rich >= 13.7.0`

### Instalación

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

### Uso

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

vamp-ssl-audit — Auditor Profesional TLS/SSL (VampSecure Labs)
```

### Pruébalo ahora — objetivos de test públicos

Estos hosts se ofrecen públicamente para probar herramientas TLS:

```bash
# Certificado caducado → calificación F
python3 vamp_ssl_audit.py -H expired.badssl.com

# Certificado autofirmado → calificación T
python3 vamp_ssl_audit.py -H self-signed.badssl.com

# TLS 1.0 aún aceptado → hallazgo HIGH, cap B
python3 vamp_ssl_audit.py -H tls-v1.badssl.com

# Firma SHA-1 → hallazgo HIGH
python3 vamp_ssl_audit.py -H sha1-2016.badssl.com

# Calificación A limpia (host bien configurado)
python3 vamp_ssl_audit.py -H badssl.com
```

### Ejemplos

```bash
# Auditar un host en el puerto 443 por defecto
python3 vamp_ssl_audit.py -H example.com

# Auditar con un puerto no estándar inline
python3 vamp_ssl_audit.py -H example.com:8443

# Auditar múltiples hosts en un solo comando
python3 vamp_ssl_audit.py -H example.com -H api.example.com -H legacy.example.com

# Auditar una lista de hosts desde un fichero con 10 workers en paralelo
python3 vamp_ssl_audit.py --file hosts.txt --workers 10

# Exportar resultados a todos los formatos
python3 vamp_ssl_audit.py -H example.com \
    --json results.json --html report.html --markdown report.md --csv report.csv

# Con renovación automática Let's Encrypt activa, las alertas de 90d son ruido — usar 30d
python3 vamp_ssl_audit.py --file hosts.txt --warn-days 30

# Escanear un servicio no-HTTPS en un puerto personalizado
python3 vamp_ssl_audit.py --file smtp_hosts.txt --port 587

# Generar informe de engagement listo para cliente (HTML + PDF)
python3 vamp_ssl_audit.py --file hosts.txt \
    --client "Acme Corp" --engagement "Revisión Configuración TLS T3 2026" \
    --auditor "J. Smith" --report-html informe_cliente.html --report-pdf informe_cliente.pdf
```

### Integración CI/CD

Añade esto a `.github/workflows/ssl-audit.yml` para condicionar tu pipeline a la calificación TLS:

```yaml
name: TLS Audit
on:
  schedule:
    - cron: '0 6 * * 1'   # semanal los lunes
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
            -H tudominio.com \
            -H api.tudominio.com \
            --warn-days 30 \
            --json ssl-results.json \
            --markdown ssl-report.md
        # Exit code 1 = hallazgos HIGH, 2 = CRITICAL → pipeline falla
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: ssl-audit-report
          path: ssl-report.md
```

### Referencia CLI

| Flag | Por defecto | Descripción |
|------|-------------|-------------|
| `-H / --host HOST[:PORT]` | — | Host objetivo, opcionalmente con puerto (repetible) |
| `--file FILE` | — | Fichero de texto con un host (o host:puerto) por línea |
| `--port N` | 443 | Puerto por defecto cuando no se especifica inline |
| `--timeout N` | 10 | Timeout de conexión en segundos |
| `--workers N` | 5 | Hilos worker concurrentes |
| `--json FILE` | — | Exportar resultados a JSON |
| `--html FILE` | — | Exportar informe HTML dark-theme con badge de calificación |
| `--markdown FILE` | — | Exportar informe Markdown |
| `--csv FILE` | — | Exportar resumen CSV (+ fichero `FILE.findings` con un hallazgo por fila) |
| `--warn-days N` | 90 | Días de antelación para alerta MEDIUM de caducidad. Con renovación Let's Encrypt, `--warn-days 30` evita ruido (la renovación ocurre a 30d, no 90d) |
| `--client TEXT` | — | Nombre del cliente para informe VSL |
| `--engagement TEXT` | — | Título del engagement para informe VSL |
| `--auditor TEXT` | — | Nombre del auditor para informe VSL |
| `--report-scope TEXT` | — | Descripción de alcance para informe VSL |
| `--report-html FILE` | — | Exportar informe VSL unificado para cliente (HTML) |
| `--report-pdf FILE` | — | Exportar informe VSL para cliente (PDF, requiere fpdf2) |

### Formatos de salida

| Formato | Flag | Descripción |
|---------|------|-------------|
| Consola | (por defecto) | Salida con color Rich con tablas de hallazgos y remediaciones |
| JSON | `--json FILE` | Conjunto completo de resultados legible por máquina |
| HTML | `--html FILE` | Informe dark-theme standalone con badge de calificación |
| Markdown | `--markdown FILE` | Informe portable para repositorios de auditoría |
| CSV | `--csv FILE` | Fila resumen por host + `FILE.findings` con una fila por hallazgo |
| HTML cliente | `--report-html FILE` | Informe unificado VampSecure Labs para cliente |
| PDF cliente | `--report-pdf FILE` | Versión PDF del informe VSL para cliente |

### Escala de calificación

| Calificación | Criterio |
|--------------|----------|
| A+ | TLS 1.3 activo, HSTS presente y completo, sin protocolos legacy ni ciphers débiles |
| A | Buena configuración; HSTS ausente o TLS 1.3 no ofrecido |
| A- | Buena configuración; HSTS incompleto (max-age corto, sin includeSubDomains) |
| B | TLS 1.0/1.1 presentes, 3DES, firma SHA-1 o RSA < 2048 |
| C | SSLv3 aceptado, RC4 o algoritmo de firma MD5 |
| D | Configuración muy deficiente |
| T | Certificado no confiable: autofirmado o mismatch de hostname |
| F | Fallo crítico: cipher nulo, certificado caducado o error de conexión |

### Exit codes

| Código | Significado | Comportamiento CI/CD |
|--------|-------------|----------------------|
| `0` | Sin hallazgos críticos o altos | Pipeline pasa |
| `1` | Hallazgos de severidad alta detectados | Pipeline falla — revisión requerida |
| `2` | Hallazgos de severidad crítica detectados | Pipeline falla — acción inmediata requerida |

### Salida de ejemplo

```
$ python3 vamp_ssl_audit.py -H expired.badssl.com -H self-signed.badssl.com -H badssl.com
vamp-ssl-audit v1.7.1 — Auditor Profesional TLS/SSL · VampSecure Labs
──────────────────────────────────────────────────────────────────────
Auditando 3 hosts con 3 workers...

┌────────────────────────┬───────────┬────────┬──────────────────────────────────────┐
│ Host                   │ Calific.  │ Proto  │ Hallazgo principal                   │
├────────────────────────┼───────────┼────────┼──────────────────────────────────────┤
│ expired.badssl.com     │  F        │ TLS1.2 │ [CRITICAL] Certificado caducado      │
│ self-signed.badssl.com │  T        │ TLS1.2 │ [HIGH] Certificado autofirmado       │
│ badssl.com             │  A        │ TLS1.3 │ Sin problemas críticos               │
└────────────────────────┴───────────┴────────┴──────────────────────────────────────┘

── expired.badssl.com ──────────────────────────────────────────────────────
  [CRITICAL] Certificado caducado el 2015-04-09 (hace 3829 días)
             Remediación: renovar el certificado inmediatamente (e.g. certbot renew)
  Cap de calificación: F

── self-signed.badssl.com ──────────────────────────────────────────────────
  [HIGH] Certificado autofirmado — no confiable por ninguna CA pública
         Remediación: sustituir por un certificado emitido por una CA de confianza
  Cap de calificación: T

── badssl.com ──────────────────────────────────────────────────────────────
  [INFO] TLS 1.3 soportado                       ✓
  [INFO] HSTS presente (max-age=31536000)         ✓
  [INFO] Certificado válido por 87 días           ✓
  Calificación: A

3 hosts auditados en 2.4s · 2 hallazgos (1 CRITICAL, 1 HIGH)
Exit code: 2
```

### Por qué vamp-ssl-audit vs. testssl.sh · SSL Labs API · nmap ssl-enum-ciphers

| Capacidad | vamp-ssl-audit | testssl.sh | SSL Labs API | nmap ssl-enum-ciphers |
|-----------|----------------|------------|--------------|----------------------|
| Calificación A+–F (estilo SSLabs) | ✅ | ✅ | ✅ (autoritativo) | ❌ |
| Ejecución local / offline | ✅ | ✅ | ❌ Solo cloud | ✅ |
| Escaneo concurrente multi-host | ✅ `--workers N` | ❌ Secuencial | ❌ | ❌ |
| Checks HSTS / DANE / CT log | ✅ | ✅ | ✅ | ❌ |
| Validación mTLS / certificado cliente | ✅ | ✅ | ❌ | ❌ |
| Check OCSP stapling | ✅ | ✅ | ✅ | ❌ |
| Modo daemon `--watch N` | ✅ | ❌ | ❌ | ❌ |
| Seguimiento de regresiones `--delta FILE` | ✅ | ❌ | ❌ | ❌ |
| Exportación JSON + HTML + Markdown + CSV | ✅ | ✅ JSON | ✅ JSON | ❌ |
| Informe VSL de engagement (HTML / PDF) | ✅ `vampsec_report` | ❌ | ❌ | ❌ |
| Exit codes CI/CD (0 / 1 / 2) | ✅ | ✅ | ❌ | ❌ |
| Paquete Python importable | ✅ | ❌ Bash | ❌ | ❌ |

- **Escaneo concurrente** — `--workers 10` audita un inventario de 50 hosts TLS en menos de un minuto; testssl.sh es secuencial y SSL Labs limita a ~3 peticiones/min por IP.
- **Monitorización continua** — `--watch N` combinado con `--delta FILE` muestra solo los hosts recién degradados en cada ejecución, convirtiendo una herramienta puntual en un sistema de alertas de cambio.
- **Nativo para CI/CD** — los exit codes 0/1/2 condicionan los pipelines directamente; el fragmento de GitHub Actions incluido está listo para copiar en `.github/workflows/`.
- **Self-hosted** — SSL Labs requiere un objetivo accesible desde internet y puede encolar peticiones; `vamp-ssl-audit` funciona en redes air-gapped y entornos de lab interno sin enviar datos de hosts a terceros.

### Cobertura de checks

| Check | Estándar | Cap de calificación |
|-------|----------|---------------------|
| SSLv3 aceptado | NIST SP 800-52r2 §3.3.1 | C |
| TLS 1.0 / TLS 1.1 presentes | RFC 8996 / NIST SP 800-52r2 | B |
| Cipher suites NULL / EXPORT / ADH / AECDH | NIST SP 800-52r2 §3.3.3 | F |
| Cipher suites RC4 / DES / 3DES | CIS Control 3.10 / RFC 7465 | C–B |
| Caducidad de certificado (aviso 90 días por defecto) | CIS Control 3.10 | F (caducado) / MEDIUM |
| Clave RSA < 1024 bits | NIST SP 800-131Ar2 | F |
| Clave RSA < 2048 bits | NIST SP 800-131Ar2 | B |
| Clave EC < 224 bits | NIST SP 800-186 | B |
| Algoritmo de firma SHA-1 / MD5 | NIST SP 800-131Ar2 | B–C |
| Certificado autofirmado | CIS Control 3.10 | T |
| Mismatch de hostname (cobertura SAN / CN) | RFC 6125 | T |
| Ausencia o max-age corto de HSTS | OWASP HSTS / RFC 6797 | A– |
| OCSP stapling | RFC 6960 | INFO |
| Registro DANE / TLSA | RFC 6698 | INFO |
| Presencia en logs Certificate Transparency | RFC 9162 | INFO |
| Autenticación mutua mTLS | NIST SP 800-52r2 §3.2 | INFO |

### Aviso legal

Uso exclusivo en sistemas de tu propiedad o sobre los que dispongas de autorización escrita explícita del propietario. VampSecure Studios no asume responsabilidad alguna por el uso no autorizado.

### Parte del toolkit de VampSecure Labs

`vamp-ssl-audit` es una herramienta del toolkit de investigación de seguridad de VampSecure Labs. Para el toolkit completo, incluido el orquestador que ejecuta todas las herramientas en secuencia y agrega los hallazgos en un único informe de engagement, consulta:

- Portfolio: [github.com/Vampsecure-Labs](https://github.com/Vampsecure-Labs)
- Orquestador: [github.com/Vampsecure-Labs/vamp-orchestrator](https://github.com/Vampsecure-Labs/vamp-orchestrator)

### Historial de versiones

| Versión | Cambios principales |
|---------|---------------------|
| v1.7.1 | README bilingüe (EN/ES) |
| v1.7.0 | CLI unificado con subcomandos; paquete importable (S3 modularización) |
| v1.6.0 | `--delta FILE` — diff NEW/RECURRING/RESOLVED entre escaneos |
| v1.5.0 | `--watch N` daemon mode; `--warn-days` cert-expiry; `--report-pdf` fpdf2 |
| v1.4.0 | Markdown/CSV export; VSL engagement report (`--report-html/pdf`) |
| v1.3.0 | HTML dark-theme report; multi-host batch scanning |
| v1.0.0 | MVP TLS/SSL auditor — grading A+…F, protocol/cipher/cert checks |

---

© VampSecure Studios — VampSecure Labs Security Research Division
