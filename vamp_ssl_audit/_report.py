# © VampSecure Studios — VampSecure Labs Security Research Division
"""
_report.py — Serialización JSON/HTML/Markdown/CSV de vamp-ssl-audit
"""

from __future__ import annotations

import csv as csv_module
import io
import json
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from ._models import (
    VERSION,
    TOOL_NAME,
    AuditResult,
    CertInfo,
    GRADE_DESCRIPTION,
    HTML_GRADE_COLOR,
)


def to_json(results: list[AuditResult]) -> str:
    """Serializa los resultados en JSON incluyendo nota y remediaciones."""

    def _cert_dict(c: CertInfo | None) -> dict | None:
        if c is None:
            return None
        return {
            "subject":        c.subject,
            "issuer":         c.issuer,
            "not_before":     c.not_before.isoformat() if c.not_before else None,
            "not_after":      c.not_after.isoformat()  if c.not_after  else None,
            "days_remaining": c.days_remaining,
            "key_type":       c.key_type,
            "key_bits":       c.key_bits,
            "sig_algorithm":  c.sig_algorithm,
            "san_entries":    c.san_entries,
            "is_self_signed": c.is_self_signed,
            "hostname_ok":    c.hostname_ok,
        }

    def _result_dict(r: AuditResult) -> dict:
        return {
            "host":                  r.host,
            "port":                  r.port,
            "timestamp":             r.timestamp,
            "error":                 r.error,
            "grade":                 r.grade,
            "grade_description":     GRADE_DESCRIPTION.get(r.grade, ""),
            "negotiated_protocol":   r.negotiated_protocol,
            "negotiated_cipher":     r.negotiated_cipher,
            "supported_protocols":   r.supported_protocols,
            "unsupported_protocols": r.unsupported_protocols,
            "cert":                  _cert_dict(r.cert),
            "hsts_header":           r.hsts_header,
            "x_frame_options":       r.x_frame_options,
            "x_content_type":        r.x_content_type,
            "max_severity":          r.max_severity,
            "findings": [
                {
                    "severity":    f.severity,
                    "category":    f.category,
                    "name":        f.name,
                    "detail":      f.detail,
                    "grade_cap":   f.grade_cap,
                    "remediation": f.remediation,
                }
                for f in r.findings
            ],
        }

    return json.dumps(
        {
            "tool":      TOOL_NAME,
            "version":   VERSION,
            "generated": datetime.now(timezone.utc).isoformat(),
            "results":   [_result_dict(r) for r in results],
        },
        indent=2, ensure_ascii=False,
    )


def to_html(results: list[AuditResult]) -> str:
    """Genera un informe HTML standalone dark-theme con insignia de nota SSLabs-style."""
    SEV_CSS = {
        "CRITICAL": "sev-crit",
        "HIGH":     "sev-high",
        "MEDIUM":   "sev-med",
        "LOW":      "sev-low",
        "INFO":     "sev-info",
    }

    rows_html: list[str] = []
    for r in results:
        if r.error:
            rows_html.append(
                f'<div class="result-block"><h2>{escape(r.target)}</h2>'
                f'<p class="sev-crit">ERROR: {escape(r.error)}</p></div>'
            )
            continue

        grade         = r.grade
        _, grade_hex  = HTML_GRADE_COLOR.get(grade, ("grade-f", "#ff2222"))
        grade_desc_h  = escape(GRADE_DESCRIPTION.get(grade, ""))

        cert_html = ""
        if r.cert:
            c = r.cert
            exp_cls = ("sev-crit" if c.days_remaining < 30
                       else "sev-high" if c.days_remaining < 90 else "good")
            san_str = escape(", ".join(c.san_entries[:8]))
            if len(c.san_entries) > 8:
                san_str += f" … (+{len(c.san_entries)-8})"
            cert_html = f"""
            <div class="cert-block">
              <h3>Certificado X.509</h3>
              <table class="info-table">
                <tr><td>Sujeto</td><td>{escape(c.subject)}</td></tr>
                <tr><td>Emisor</td><td>{escape(c.issuer)}</td></tr>
                <tr><td>Clave</td><td>{escape(c.key_type)} {c.key_bits} bits</td></tr>
                <tr><td>Firma</td><td>{escape(c.sig_algorithm)}</td></tr>
                <tr><td>Expira</td><td class="{exp_cls}">{c.not_after.date() if c.not_after else "?"} ({c.days_remaining}d)</td></tr>
                <tr><td>Autofirmado</td><td class="{'sev-high' if c.is_self_signed else 'good'}">{'SÍ' if c.is_self_signed else 'No'}</td></tr>
                <tr><td>SAN</td><td>{san_str or '—'}</td></tr>
              </table>
            </div>"""

        findings_html = ""
        if r.findings:
            rows_f = ""
            for f in r.findings:
                remed_html = ""
                if f.remediation:
                    remed_html = (
                        f'<details class="remed"><summary>Ver remediación</summary>'
                        f'<pre>{escape(f.remediation)}</pre></details>'
                    )
                rows_f += (
                    f'<tr><td class="{SEV_CSS.get(f.severity,"")}">{escape(f.severity)}</td>'
                    f'<td>{escape(f.category)}</td>'
                    f'<td>{escape(f.name)}</td>'
                    f'<td>{escape(f.detail)}{remed_html}</td></tr>'
                )
            findings_html = f"""
            <table class="findings-table">
              <thead><tr><th>Severidad</th><th>Categoría</th><th>Hallazgo</th><th>Detalle / Remediación</th></tr></thead>
              <tbody>{rows_f}</tbody>
            </table>"""
        else:
            findings_html = '<p class="good">✔ Sin hallazgos de seguridad</p>'

        hsts_s = escape(r.hsts_header) if r.hsts_header else '<span class="sev-high">AUSENTE</span>'

        rows_html.append(f"""
        <div class="result-block">
          <div class="host-header">
            <div class="grade-circle" style="background:{grade_hex}">{escape(grade)}</div>
            <div class="host-info">
              <h2>{escape(r.target)}</h2>
              <p class="grade-desc">{grade_desc_h}</p>
            </div>
          </div>
          <div class="meta-row">
            <span><b>Protocolo:</b> {escape(r.negotiated_protocol)}</span>
            <span><b>Cipher:</b> {escape(r.negotiated_cipher)}</span>
            <span><b>Legacy aceptados:</b> {escape(', '.join(r.supported_protocols)) or '—'}</span>
            <span><b>HSTS:</b> {hsts_s}</span>
          </div>
          {cert_html}
          <h3>Hallazgos ({len(r.findings)})</h3>
          {findings_html}
        </div>""")

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    all_rows  = "\n".join(rows_html)

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VampSecure Labs — SSL/TLS Audit Report</title>
<style>
:root {{
  --bg: #0d0d0d; --surface: #141414; --border: #1e1e1e;
  --text: #e0e0e0; --text-dim: #888; --accent: #9b59b6;
  --crit: #ff4444; --high: #ff8800; --med: #ffcc00; --low: #4488ff; --good: #44cc88;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ background: var(--bg); color: var(--text); font-family: 'Consolas','Courier New',monospace; font-size: 14px; padding: 24px; }}
header {{ border-bottom: 1px solid var(--accent); padding-bottom: 16px; margin-bottom: 24px; }}
header h1 {{ color: var(--accent); font-size: 22px; letter-spacing: .1em; }}
header p {{ color: var(--text-dim); font-size: 12px; margin-top: 4px; }}
.result-block {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 20px; margin-bottom: 20px; }}
.host-header {{ display: flex; align-items: center; gap: 16px; margin-bottom: 14px; }}
.grade-circle {{ width: 56px; height: 56px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 18px; font-weight: bold; color: #fff; flex-shrink: 0; }}
.host-info h2 {{ font-size: 16px; margin-bottom: 4px; }}
.grade-desc {{ color: var(--text-dim); font-size: 12px; }}
.result-block h3 {{ font-size: 13px; color: var(--text-dim); margin: 14px 0 6px; text-transform: uppercase; letter-spacing: .07em; }}
.meta-row {{ display: flex; flex-wrap: wrap; gap: 18px; font-size: 12px; color: var(--text-dim); margin-bottom: 14px; }}
.meta-row b {{ color: var(--text); }}
.sev-crit {{ color: var(--crit); }}
.sev-high {{ color: var(--high); }}
.sev-med  {{ color: var(--med); }}
.sev-low  {{ color: var(--low); }}
.sev-info {{ color: var(--text-dim); }}
.good     {{ color: var(--good); }}
.cert-block {{ background: var(--bg); border-left: 3px solid var(--accent); padding: 12px 16px; border-radius: 0 4px 4px 0; margin-bottom: 14px; }}
.info-table td {{ padding: 4px 12px 4px 0; vertical-align: top; }}
.info-table td:first-child {{ color: var(--text-dim); width: 120px; }}
.findings-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
.findings-table th {{ text-align: left; padding: 6px 10px; color: var(--text-dim); border-bottom: 1px solid var(--border); font-size: 11px; text-transform: uppercase; }}
.findings-table td {{ padding: 6px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }}
.findings-table tr:last-child td {{ border-bottom: none; }}
details.remed {{ margin-top: 6px; }}
details.remed summary {{ cursor: pointer; color: var(--accent); font-size: 11px; }}
details.remed pre {{ background: #0a0a0a; border: 1px solid var(--border); border-radius: 4px; padding: 10px; font-size: 11px; margin-top: 6px; overflow-x: auto; white-space: pre-wrap; }}
footer {{ margin-top: 32px; text-align: center; color: var(--text-dim); font-size: 11px; }}
</style>
</head>
<body>
<header>
  <h1>VampSecure Labs — SSL/TLS Audit Report</h1>
  <p>{TOOL_NAME} v{VERSION} · {generated} · VampSecure Studios · Uso exclusivo en auditorías autorizadas</p>
</header>
{all_rows}
<footer>© VampSecure Studios — VampSecure Labs Security Research Division</footer>
</body>
</html>"""


def to_markdown(results: list[AuditResult]) -> str:
    """
    Genera un informe en formato Markdown incluible directamente en
    documentación de auditoría o repositorios de informes.
    """
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = []

    lines.append("# VampSecure Labs — Informe de Auditoría SSL/TLS")
    lines.append("")
    lines.append(f"**Herramienta:** {TOOL_NAME} v{VERSION}  ")
    lines.append(f"**Generado:** {generated}  ")
    lines.append(f"**Hosts analizados:** {len(results)}  ")
    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## Resumen Ejecutivo")
    lines.append("")
    lines.append("| Host:Puerto | Nota | Protocolo | Cert Expira | HSTS | Hallazgos C/H | Severidad Máx. |")
    lines.append("|-------------|------|-----------|-------------|------|---------------|----------------|")
    for r in results:
        if r.error:
            lines.append(f"| `{r.target}` | **F** | ERROR | — | — | — | ERROR |")
            continue
        days  = f"{r.cert.days_remaining}d" if r.cert else "?"
        hsts  = "✔" if r.hsts_header else "✗"
        crhi  = sum(1 for f in r.findings if f.severity in ("CRITICAL", "HIGH"))
        lines.append(
            f"| `{r.target}` | **{r.grade}** | {r.negotiated_protocol} "
            f"| {days} | {hsts} | {crhi} | {r.max_severity} |"
        )
    lines.append("")
    lines.append("---")
    lines.append("")

    for r in results:
        lines.append(f"## Host: `{r.target}`")
        lines.append("")

        if r.error:
            lines.append(f"> ❌ **ERROR:** {r.error}")
            lines.append("")
            continue

        grade_desc = GRADE_DESCRIPTION.get(r.grade, "")
        lines.append(f"### 📊 Calificación: **{r.grade}** — {grade_desc}")
        lines.append("")

        lines.append("| Campo | Valor |")
        lines.append("|-------|-------|")
        lines.append(f"| Protocolo negociado | `{r.negotiated_protocol}` |")
        lines.append(f"| Cipher negociado | `{r.negotiated_cipher}` |")
        prots = ", ".join(r.supported_protocols) if r.supported_protocols else "—"
        lines.append(f"| Protocolos legacy aceptados | {prots} |")
        hsts_val = f"`{r.hsts_header}`" if r.hsts_header else "**AUSENTE**"
        lines.append(f"| HSTS | {hsts_val} |")
        lines.append("")

        if r.cert:
            c = r.cert
            lines.append("### Certificado X.509")
            lines.append("")
            lines.append("| Campo | Valor |")
            lines.append("|-------|-------|")
            lines.append(f"| Sujeto | `{c.subject}` |")
            lines.append(f"| Emisor | `{c.issuer}` |")
            lines.append(f"| Clave | {c.key_type} {c.key_bits} bits |")
            lines.append(f"| Firma | {c.sig_algorithm} |")
            not_after_s = c.not_after.date() if c.not_after else "?"
            lines.append(f"| Expira | {not_after_s} ({c.days_remaining} días) |")
            lines.append(f"| Autofirmado | {'⚠️ SÍ' if c.is_self_signed else '✔ No'} |")
            if c.san_entries:
                san_md = ", ".join(f"`{s}`" for s in c.san_entries[:8])
                if len(c.san_entries) > 8:
                    san_md += f" … (+{len(c.san_entries)-8})"
                lines.append(f"| SAN | {san_md} |")
            lines.append("")

        if r.findings:
            lines.append("### 🔍 Hallazgos")
            lines.append("")

            severity_groups = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            for sev in severity_groups:
                group = [f for f in r.findings if f.severity == sev]
                if not group:
                    continue
                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}.get(sev, "")
                lines.append(f"#### {icon} {sev}")
                lines.append("")
                for f in group:
                    lines.append(f"**{f.name}**")
                    lines.append(f"> {f.detail}")
                    if f.remediation:
                        lines.append("> ")
                        lines.append("> **Remediación:**")
                        lines.append("> ")
                        lines.append("> ```")
                        for rline in f.remediation.splitlines():
                            lines.append(f"> {rline}")
                        lines.append("> ```")
                    lines.append("")

            priorizados = [f for f in r.findings if f.severity in ("CRITICAL", "HIGH") and f.remediation]
            if priorizados:
                lines.append("### ✅ Pasos de remediación priorizados")
                lines.append("")
                for i, f in enumerate(priorizados, 1):
                    lines.append(f"{i}. **[{f.severity}]** {f.name}")
                lines.append("")
        else:
            lines.append("### ✅ Sin hallazgos de seguridad")
            lines.append("")

        lines.append("---")
        lines.append("")

    lines.append(f"*Generado por {TOOL_NAME} v{VERSION} · VampSecure Studios · VampSecure Labs Security Research Division*  ")
    lines.append("*Uso exclusivo en entornos autorizados. El uso no autorizado es ilegal.*")
    lines.append("")

    return "\n".join(lines)


def to_csv(results: list[AuditResult], base_path: str) -> tuple[str, str]:
    """
    Genera dos ficheros CSV:
      - <base_path>          : resumen por host (una fila por host)
      - <base_path>.findings : detalle de hallazgos (una fila por hallazgo)

    Devuelve los dos paths como tupla.
    """
    buf_hosts = io.StringIO()
    writer_h = csv_module.writer(buf_hosts)
    writer_h.writerow([
        "host", "puerto", "nota", "descripcion_nota",
        "protocolo", "cipher", "protocolos_legacy",
        "cert_sujeto", "cert_emisor", "cert_clave", "cert_firma",
        "cert_expira", "cert_dias_restantes", "cert_autofirmado",
        "hsts", "hsts_valor",
        "num_hallazgos", "hallazgos_critical", "hallazgos_high",
        "hallazgos_medium", "hallazgos_low",
        "severidad_maxima", "error", "timestamp",
    ])
    for r in results:
        cert = r.cert
        writer_h.writerow([
            r.host, r.port,
            r.grade, GRADE_DESCRIPTION.get(r.grade, ""),
            r.negotiated_protocol, r.negotiated_cipher,
            "|".join(r.supported_protocols),
            cert.subject        if cert else "",
            cert.issuer         if cert else "",
            f"{cert.key_type} {cert.key_bits}b" if cert else "",
            cert.sig_algorithm  if cert else "",
            cert.not_after.date() if (cert and cert.not_after) else "",
            cert.days_remaining if cert else "",
            "SI" if (cert and cert.is_self_signed) else "NO" if cert else "",
            "SI" if r.hsts_header else "NO",
            r.hsts_header or "",
            len(r.findings),
            sum(1 for f in r.findings if f.severity == "CRITICAL"),
            sum(1 for f in r.findings if f.severity == "HIGH"),
            sum(1 for f in r.findings if f.severity == "MEDIUM"),
            sum(1 for f in r.findings if f.severity == "LOW"),
            r.max_severity,
            r.error or "",
            r.timestamp,
        ])

    buf_findings = io.StringIO()
    writer_f = csv_module.writer(buf_findings)
    writer_f.writerow([
        "host", "puerto", "nota_host",
        "severidad", "categoria", "hallazgo", "detalle",
        "cap_nota", "remediacion",
    ])
    for r in results:
        for f in r.findings:
            writer_f.writerow([
                r.host, r.port, r.grade,
                f.severity, f.category, f.name, f.detail,
                f.grade_cap,
                f.remediation.replace("\n", " | "),
            ])

    path_hosts    = base_path
    path_findings = base_path + ".findings"

    Path(path_hosts).write_text(buf_hosts.getvalue(), encoding="utf-8")
    Path(path_findings).write_text(buf_findings.getvalue(), encoding="utf-8")

    return path_hosts, path_findings


def _findings_vsl(results: list) -> list:
    """
    Convierte los hallazgos TLS/SSL al formato Finding unificado de VampSecure Labs.

    Incluye todos los hallazgos de severidad MEDIUM, HIGH o CRITICAL.
    Los hallazgos INFO se omiten para mantener el informe de cliente enfocado.
    """
    from vampsec_report import Finding as VSLFinding

    SEVERIDADES_INCLUIDAS = {"CRITICAL", "HIGH", "MEDIUM"}
    hallazgos: list = []
    n = 0

    for r in results:
        objetivo = f"{r.host}:{r.port}"
        for f in r.findings:
            if f.severity not in SEVERIDADES_INCLUIDAS:
                continue
            n += 1

            partes_evidencia = [
                f"Categoría: {f.category}",
                f"Detalle: {f.detail}",
            ]
            if f.grade_cap:
                partes_evidencia.append(f"Nota SSL máxima con este hallazgo: {f.grade_cap}")

            hallazgos.append(VSLFinding(
                id          = f"SSL-{n:03d}",
                title       = f.name,
                severity    = f.severity,
                description = f.detail,
                evidence    = " | ".join(partes_evidencia),
                affected    = objetivo,
                remediation = f.remediation or "Consultar la guía de buenas prácticas TLS de BSI/NIST.",
                tags        = ["ssl", "tls", f.category.lower(), f.severity.lower()],
            ))

    return hallazgos
