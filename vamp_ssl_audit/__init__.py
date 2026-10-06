# © VampSecure Studios — VampSecure Labs Security Research Division
"""
vamp_ssl_audit — Auditor TLS/SSL profesional con calificación SSLabs-style

Paquete público que re-exporta toda la API pública para uso como librería:

  from vamp_ssl_audit import audit_host, AuditResult, compute_grade, VERSION

Módulos internos:
  _models  — constantes, estructuras de datos (Finding, CertInfo, AuditResult)
  _core    — lógica pura de auditoría (SSLAuditor, compute_grade, _apply_cap)
  _report  — serialización JSON/HTML/Markdown/CSV y conversión VSL
  cli      — interfaz de línea de comandos (main, _parse_args, _daemon_loop)
"""

from ._models import (
    VERSION,
    TOOL_NAME,
    PROTOCOL_RISK,
    PROTOCOL_GRADE_CAP,
    WEAK_CIPHER_PATTERNS,
    CIPHER_GRADE_CAP,
    SIG_ALG_RISK,
    SEVERITY_ORDER,
    GRADE_ORDER_LIST,
    GRADE_COLOR,
    GRADE_DESCRIPTION,
    HTML_GRADE_COLOR,
    Finding,
    CertInfo,
    AuditResult,
)

from ._core import (
    _apply_cap,
    compute_grade,
    SSLAuditor,
    apply_delta_scan,
)

from ._report import (
    to_json,
    to_html,
    to_markdown,
    to_csv,
    _findings_vsl,
)

from .cli import (
    main,
    _parse_args,
    _daemon_loop,
    _resolve_targets,
    BANNER,
    SEVERITY_COLOR,
    console,
    print_result,
    print_summary,
)

__all__ = [
    # Versión
    "VERSION",
    "TOOL_NAME",
    # Constantes
    "PROTOCOL_RISK",
    "PROTOCOL_GRADE_CAP",
    "WEAK_CIPHER_PATTERNS",
    "CIPHER_GRADE_CAP",
    "SIG_ALG_RISK",
    "SEVERITY_ORDER",
    "SEVERITY_COLOR",
    "GRADE_ORDER_LIST",
    "GRADE_COLOR",
    "GRADE_DESCRIPTION",
    "HTML_GRADE_COLOR",
    # Estructuras de datos
    "Finding",
    "CertInfo",
    "AuditResult",
    # Core
    "_apply_cap",
    "compute_grade",
    "SSLAuditor",
    "apply_delta_scan",
    # Report
    "to_json",
    "to_html",
    "to_markdown",
    "to_csv",
    "_findings_vsl",
    # CLI
    "main",
    "_parse_args",
    "_daemon_loop",
    "_resolve_targets",
    "BANNER",
    "console",
    "print_result",
    "print_summary",
]
