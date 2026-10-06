# © VampSecure Studios — VampSecure Labs Security Research Division
"""
cli.py — Interfaz de línea de comandos de vamp-ssl-audit
"""

from __future__ import annotations

import argparse
import concurrent.futures
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ._models import (
    VERSION,
    TOOL_NAME,
    AuditResult,
    Finding,
    SEVERITY_ORDER,
    GRADE_ORDER_LIST,
    GRADE_COLOR,
    GRADE_DESCRIPTION,
)
from ._core import SSLAuditor, _apply_cap, compute_grade, apply_delta_scan
from ._report import to_json, to_html, to_markdown, to_csv, _findings_vsl

console = Console()

BANNER = r"""
__   ___   __  __ ___  ___ ___ ___ _   _ ___ ___ _      _   ___ ___
\ \ / /_\ |  \/  | _ \/ __| __/ __| | | | _ \ __| |    /_\ | _ ) __|
 \ V / _ \| |\/| |  _/\__ \ _| (__| |_| |   / _|| |__ / _ \| _ \__ \
  \_/_/ \_\_|  |_|_|  |___/___\___|\___/|_|_\___|____/_/ \_\___/___/
  by Antonio Hernandez "Belky" — VampSecure Studios
  vamp-ssl-audit v1.7.0 · TLS/SSL Professional Auditor con mTLS Testing
  ────────────────────────────────────────────────────────────────────────
  USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""

SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "bold magenta",
    "LOW":      "cyan",
    "INFO":     "green",
}


# ---------------------------------------------------------------------------
# Funciones de presentación en consola
# ---------------------------------------------------------------------------

def print_result(result: AuditResult) -> None:
    """Muestra el resultado de un host en la consola con su nota prominente."""
    if result.error:
        console.print(
            f"[bold red]✗[/] [bold]{result.target}[/] — {result.error}"
        )
        return

    sev        = result.max_severity
    sev_color  = SEVERITY_COLOR.get(sev, "white")
    grade      = result.grade
    grade_col  = GRADE_COLOR.get(grade, "white")
    grade_desc = GRADE_DESCRIPTION.get(grade, "")

    console.print(f"\n[bold cyan]{'─'*60}[/]")
    console.print(
        f"  Nota: [{grade_col}]{grade:>2}[/{grade_col}]  "
        f"[bold]{result.target}[/]  "
        f"[{sev_color}]{sev}[/{sev_color}]"
    )
    console.print(f"  [dim]{grade_desc}[/]")
    console.print(f"[bold cyan]{'─'*60}[/]")

    console.print(f"  [bold]Protocolo negociado:[/] {result.negotiated_protocol or 'N/A'}")
    console.print(f"  [bold]Cipher negociado:[/]    {result.negotiated_cipher or 'N/A'}")

    if result.supported_protocols:
        console.print(
            "  [bold red]Protocolos inseguros aceptados:[/] "
            + ", ".join(result.supported_protocols)
        )

    if result.cert:
        c = result.cert
        exp_color = "red" if c.days_remaining < 30 else ("yellow" if c.days_remaining < 90 else "green")
        console.print("\n  [bold]Certificado[/]")
        console.print(f"    Sujeto:        {c.subject}")
        console.print(f"    Emisor:        {c.issuer}")
        console.print(f"    Clave:         {c.key_type} {c.key_bits} bits")
        console.print(f"    Firma:         {c.sig_algorithm}")
        console.print(
            f"    Expira:        [{exp_color}]"
            f"{c.not_after.date() if c.not_after else 'N/A'} ({c.days_remaining}d)"
            f"[/{exp_color}]"
        )
        console.print(f"    Autofirmado:   {'[red]SÍ[/red]' if c.is_self_signed else '[green]No[/green]'}")
        if c.san_entries:
            console.print(
                f"    SAN ({len(c.san_entries)}):     "
                + ", ".join(c.san_entries[:5])
                + (" …" if len(c.san_entries) > 5 else "")
            )

    if result.hsts_header:
        console.print(f"\n  [bold]HSTS:[/] [green]{result.hsts_header}[/]")
    else:
        console.print("\n  [bold]HSTS:[/] [red]AUSENTE[/]")

    if result.findings:
        console.print()
        tbl = Table(show_header=True, header_style="bold cyan", box=None, padding=(0, 1))
        tbl.add_column("SEV",       width=10)
        tbl.add_column("Categoría", width=18)
        tbl.add_column("Hallazgo",  min_width=32)
        tbl.add_column("Detalle",   min_width=38)
        for f in result.findings:
            color = SEVERITY_COLOR.get(f.severity, "white")
            tbl.add_row(
                Text(f.severity, style=color),
                Text(f.category),
                Text(f.name),
                Text(f.detail),
            )
        console.print(tbl)

        criticos = [f for f in result.findings if f.severity in ("CRITICAL", "HIGH") and f.remediation]
        if criticos:
            console.print("\n  [bold cyan]Pasos de remediación prioritarios:[/]")
            for f in criticos:
                console.print(
                    Panel(
                        f.remediation,
                        title=f"[{SEVERITY_COLOR[f.severity]}]{f.severity}[/] — {f.name}",
                        border_style="cyan",
                        expand=False,
                    )
                )
    else:
        console.print("\n  [bold green]✔ Sin hallazgos de seguridad[/]")


def print_summary(results: list[AuditResult]) -> None:
    """Tabla resumen de todos los hosts auditados."""
    console.print("\n")
    tbl = Table(title="Resumen de auditoría TLS/SSL",
                header_style="bold cyan", show_lines=True)
    tbl.add_column("Host:puerto",    min_width=24)
    tbl.add_column("Nota",           width=6)
    tbl.add_column("Protocolo",      width=10)
    tbl.add_column("Cert expira",    width=14)
    tbl.add_column("HSTS",           width=6)
    tbl.add_column("Hallazgos C/H",  width=12)
    tbl.add_column("Severidad máx.", width=12)

    for r in results:
        if r.error:
            tbl.add_row(
                r.target, "[red]F[/]", "[red]ERROR[/]",
                "-", "-", "-", "[red]ERROR[/]",
            )
            continue
        sev_col   = SEVERITY_COLOR.get(r.max_severity, "white")
        grade_col = GRADE_COLOR.get(r.grade, "white")
        days      = r.cert.days_remaining if r.cert else "?"
        if isinstance(days, int):
            days_s = (f"[red]{days}d[/]"    if days < 30
                      else f"[yellow]{days}d[/]" if days < 90
                      else f"[green]{days}d[/]")
        else:
            days_s = "?"
        hsts_s   = "[green]✔[/]" if r.hsts_header else "[red]✗[/]"
        crit_hi  = sum(1 for f in r.findings if f.severity in ("CRITICAL", "HIGH"))
        tbl.add_row(
            f"[bold]{r.target}[/]",
            f"[{grade_col}]{r.grade}[/{grade_col}]",
            r.negotiated_protocol,
            days_s,
            hsts_s,
            str(crit_hi),
            f"[{sev_col}]{r.max_severity}[/{sev_col}]",
        )
    console.print(tbl)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    """Parsea los argumentos de la línea de comandos."""
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=f"VampSecure Labs SSL Audit v{VERSION} — Auditor TLS/SSL con calificación SSLabs-style",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Ejemplos:
  vamp-ssl-audit -H ejemplo.com
  vamp-ssl-audit -H ejemplo.com:8443 -H otro.com
  vamp-ssl-audit -H ejemplo.com --json salida.json --html informe.html
  vamp-ssl-audit --file lista_hosts.txt --workers 10 --markdown informe.md --csv resultados.csv
        """,
    )
    p.add_argument("-H", "--host", dest="hosts", metavar="HOST[:PUERTO]",
                   action="append", default=[],
                   help="Host a auditar (se puede repetir). Puerto por defecto: 443")
    p.add_argument("--file", metavar="FILE",
                   help="Fichero con hosts, uno por línea (HOST o HOST:PUERTO)")
    p.add_argument("--port", type=int, default=443,
                   help="Puerto por defecto cuando no se especifica en --host (default: 443)")
    p.add_argument("--timeout", type=int, default=10,
                   help="Timeout de conexión en segundos (default: 10)")
    p.add_argument("--workers", type=int, default=5,
                   help="Hilos paralelos para múltiples hosts (default: 5)")
    p.add_argument("--json", metavar="FILE",
                   help="Guardar resultado completo en JSON (incluye remediaciones)")
    p.add_argument("--html", metavar="FILE",
                   help="Guardar informe en HTML dark-theme (incluye remediaciones colapsables)")
    p.add_argument("--markdown", metavar="FILE",
                   help="Guardar informe en Markdown (apto para repositorios de auditoría)")
    p.add_argument("--csv", metavar="FILE",
                   help="Guardar resumen en CSV (genera además FILE.findings con detalle de hallazgos)")
    p.add_argument("--warn-days", type=int, default=90, metavar="N",
                   help="Días de antelación para alerta MEDIUM de caducidad (default: 90). "
                        "Con Let's Encrypt y renovación automática activa, usa --warn-days 30")
    p.add_argument("--strict-tls13", action="store_true", default=False,
                   help="Modo estricto TLS 1.3: si el servidor soporta TLS 1.2 o inferior, "
                        "la nota máxima es B. Útil para entornos que exigen TLS 1.3 exclusivo.")

    mtls_group = p.add_argument_group(
        "mTLS testing",
        "Prueba de autenticación mutua TLS. Sin --mtls-cert/--mtls-key detecta si el "
        "servidor REQUIERE certificado cliente. Con ambas opciones, conecta usando el "
        "certificado proporcionado e informa si es aceptado o rechazado.",
    )
    mtls_group.add_argument(
        "--mtls-cert", metavar="CERT.pem",
        help="Ruta al certificado cliente PEM para la prueba de mTLS.",
    )
    mtls_group.add_argument(
        "--mtls-key", metavar="KEY.pem",
        help="Ruta a la clave privada PEM del certificado cliente (par de --mtls-cert).",
    )

    p.add_argument(
        "--watch", type=int, metavar="SECONDS",
        help="Daemon mode: re-auditar cada N segundos, mostrar solo hallazgos NEW/RESOLVED",
    )
    p.add_argument(
        "--delta", metavar="FILE",
        help="Delta scan: comparar con un informe JSON previo (--json). "
             "Muestra hallazgos como NEW/RECURRING y lista los RESOLVED.",
    )

    from vampsec_report import add_report_args
    add_report_args(p)

    return p.parse_args()


def _resolve_targets(args: argparse.Namespace) -> list[tuple[str, int]]:
    """Construye la lista de (host, puerto) a auditar."""
    raw: list[str] = list(args.hosts)

    if args.file:
        path = Path(args.file)
        if not path.is_file():
            console.print(f"[bold red]ERROR:[/] Fichero no encontrado: {args.file}")
            sys.exit(1)
        raw.extend(
            line.strip() for line in path.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        )

    if not raw:
        console.print("[bold red]ERROR:[/] Indica al menos un host con -H o --file")
        sys.exit(1)

    targets: list[tuple[str, int]] = []
    for entry in raw:
        if ":" in entry:
            host, port_str = entry.rsplit(":", 1)
            try:
                targets.append((host.strip(), int(port_str)))
            except ValueError:
                console.print(f"[yellow]Aviso:[/] Puerto inválido en '{entry}', usando {args.port}")
                targets.append((entry, args.port))
        else:
            targets.append((entry.strip(), args.port))

    return targets


def _daemon_loop(args: argparse.Namespace, interval: int) -> None:
    """Re-audit every `interval` seconds; print only NEW / RESOLVED findings."""
    import signal

    prev_keys: set = set()
    iteration = 0

    def _stop(sig, frame):
        print("\n[!] Daemon detenido.", file=sys.stderr)
        sys.exit(0)

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    targets = _resolve_targets(args)
    target_str = ", ".join(f"{h}:{p}" for h, p in targets)
    auditor = SSLAuditor(
        timeout=args.timeout,
        warn_days=args.warn_days,
        strict_tls13=getattr(args, "strict_tls13", False),
        mtls_cert=getattr(args, "mtls_cert", None),
        mtls_key=getattr(args, "mtls_key", None),
    )

    print(
        f"[*] Daemon mode — {target_str} — cada {interval}s — Ctrl+C para detener",
        file=sys.stderr,
    )

    from datetime import datetime, timezone

    while True:
        iteration += 1
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"\n── [{ts}] iter #{iteration} ──", file=sys.stderr)

        current_keys: set = set()
        try:
            for host, port in targets:
                result = auditor.audit(host, port)
                for f in result.findings:
                    current_keys.add(f"{host}:{port}:{f.category}:{f.name}")
        except Exception as exc:
            print(f"  [!] Error en auditoría: {exc}", file=sys.stderr)
            time.sleep(interval)
            continue

        new_keys = current_keys - prev_keys
        resolved_keys = prev_keys - current_keys

        if not new_keys and not resolved_keys:
            print("[=] Sin cambios", file=sys.stderr)
        else:
            for k in sorted(new_keys):
                print(f"  [+NEW     ] {k}", file=sys.stderr)
            for k in sorted(resolved_keys):
                print(f"  [-RESOLVED] {k}", file=sys.stderr)

        prev_keys = current_keys
        time.sleep(interval)


def main() -> None:
    """Punto de entrada principal."""
    console.print(BANNER, style="bold magenta")

    args = _parse_args()

    if getattr(args, "watch", None) is not None:
        _daemon_loop(args, args.watch)
        return

    targets  = _resolve_targets(args)
    auditor  = SSLAuditor(
        timeout=args.timeout,
        warn_days=args.warn_days,
        strict_tls13=getattr(args, "strict_tls13", False),
        mtls_cert=getattr(args, "mtls_cert", None),
        mtls_key=getattr(args, "mtls_key", None),
    )

    console.print(f"[bold cyan]Auditando {len(targets)} host(s)…[/]\n")

    results: list[AuditResult] = []

    if len(targets) == 1:
        host, port = targets[0]
        with console.status(f"[cyan]Auditando {host}:{port}…[/]", spinner="dots"):
            results.append(auditor.audit(host, port))
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(auditor.audit, h, p): (h, p) for h, p in targets}
            with console.status("[cyan]Auditando hosts en paralelo…[/]", spinner="dots"):
                for future in concurrent.futures.as_completed(futures):
                    results.append(future.result())

    results.sort(key=lambda r: (r.host, r.port))

    delta_resolved: list[str] = []
    if getattr(args, "delta", None):
        try:
            results, delta_resolved = apply_delta_scan(results, args.delta)
            n_new = sum(1 for r in results for f in r.findings if f.delta_state == "new")
            n_rec = sum(1 for r in results for f in r.findings if f.delta_state == "recurring")
            console.print(
                f"[bold cyan]  DELTA vs {args.delta}:[/] "
                f"[bold green]{n_new} NEW[/] · [yellow]{n_rec} RECURRING[/] · "
                f"[dim]{len(delta_resolved)} RESOLVED[/]\n"
            )
        except ValueError as exc:
            console.print(f"[bold red]  [!] Delta error: {exc}[/]")

    for r in results:
        print_result(r)

    print_summary(results)

    if delta_resolved:
        console.print("\n[bold green]  ✅ RESUELTOS desde el baseline:[/]")
        for k in delta_resolved:
            console.print(f"[dim]    [-RESOLVED] {k}[/]")

    if args.json:
        Path(args.json).write_text(to_json(results), encoding="utf-8")
        console.print(f"\n[green]✔[/] JSON guardado en [bold]{args.json}[/]")

    if args.html:
        Path(args.html).write_text(to_html(results), encoding="utf-8")
        console.print(f"[green]✔[/] HTML guardado en [bold]{args.html}[/]")

    if args.markdown:
        Path(args.markdown).write_text(to_markdown(results), encoding="utf-8")
        console.print(f"[green]✔[/] Markdown guardado en [bold]{args.markdown}[/]")

    if args.csv:
        p_hosts, p_findings = to_csv(results, args.csv)
        console.print(f"[green]✔[/] CSV resumen guardado en [bold]{p_hosts}[/]")
        console.print(f"[green]✔[/] CSV hallazgos guardado en [bold]{p_findings}[/]")

    if getattr(args, "report_html", None) or getattr(args, "report_pdf", None):
        from vampsec_report import VampSecReport, meta_from_args
        meta   = meta_from_args(args, tool="vamp-ssl-audit", version=VERSION)
        report = VampSecReport(meta=meta, findings=_findings_vsl(results))
        if args.report_html:
            report.to_html_client(args.report_html)
            console.print(f"[green]✔[/] Informe cliente HTML guardado en [bold]{args.report_html}[/]")
        if args.report_pdf:
            report.to_pdf(args.report_pdf)
            console.print(f"[green]✔[/] Informe cliente PDF guardado en [bold]{args.report_pdf}[/]")

    max_sev = "INFO"
    for r in results:
        if SEVERITY_ORDER.get(r.max_severity, 99) < SEVERITY_ORDER.get(max_sev, 99):
            max_sev = r.max_severity

    sys.exit(2 if max_sev == "CRITICAL" else 1 if max_sev == "HIGH" else 0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Interrumpido por el usuario.[/]")
        sys.exit(0)
