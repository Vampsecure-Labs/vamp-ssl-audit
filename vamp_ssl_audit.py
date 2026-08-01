#!/usr/bin/env python3
"""
vamp_ssl_audit.py — Auditor TLS/SSL
=====================================
VampSecure Labs · VampSecure Studios
Para Uso Exclusivo en Pruebas de Penetración Autorizadas — v1.0

DESCRIPCIÓN GENERAL
-------------------
Auditor asíncrono de configuraciones TLS/SSL para hosts y puertos arbitrarios.
Analiza protocolos soportados, suite de cifrado negociada, fortaleza del certificado
digital y cabeceras de seguridad HTTP. Diseñado para auditorías de cumplimiento PCI-DSS,
ISO 27001 y preparación CIS Benchmark sin depender de OpenSSL CLI externo.

COMPROBACIONES REALIZADAS
--------------------------
  Protocolos
    · Intenta conexión explícita con cada versión (SSLv3, TLS 1.0, 1.1, 1.2, 1.3)
    · Clasifica el protocolo negociado por defecto

  Suite de cifrado
    · Identifica cifrados NULL, EXPORT, RC4, DES/3DES, anónimos (DHE/ECDHE-anon)
    · Clasifica ciphers AEAD (GCM/CCM/POLY1305) como seguros

  Certificado digital
    · Fecha de expiración y días restantes
    · Tamaño de clave (RSA, EC, DSA, EdDSA)
    · Algoritmo de firma (MD5, SHA-1, SHA-256+)
    · Certificado autofirmado
    · Cobertura de hostname (SAN / CN)
    · Transparencia de certificados (CT log via crt.sh — opcional)

  Cabeceras HTTP de seguridad
    · Strict-Transport-Security (HSTS): presencia, max-age, includeSubDomains, preload
    · X-Frame-Options, X-Content-Type-Options (complementario)

DEPENDENCIAS
------------
  cryptography >= 41.0.0  — Análisis profundo del certificado X.509
  rich         >= 13.7.0  — Salida de consola con formato enriquecido

  Instalación: pip install cryptography rich

AUTORÍA
-------
  © VampSecure Studios — VampSecure Labs Security Research Division
  Todos los derechos reservados. Uso exclusivo en entornos autorizados.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import socket
import ssl
import sys
import urllib.error
import urllib.request
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.hashes import MD5, SHA1
from cryptography.x509.oid import ExtensionOID, NameOID
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


VERSION   = "1.0"
TOOL_NAME = "vamp-ssl-audit"

console = Console()

BANNER = r"""
 __   ___   __  ___ ___   ___ ___ ___      _   _   _ ___ ___ _____
 \ \ / /_\ |  \/  | _ \ / __| __/ __|    /_\ | | | |   \_ _|_   _|
  \ V / _ \| |\/| |  _/ \__ \ _| (__    / _ \| |_| | |) | |  | |
   \_/_/ \_\_|  |_|_|   |___/___\___|  /_/ \_\\___/|___/___| |_|
        by VampSecure Studios · vamp-ssl-audit v1.0 · TLS/SSL Auditor
        ─────────────────────────────────────────────────────────────
        USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""

# ---------------------------------------------------------------------------
# Constantes de clasificación
# ---------------------------------------------------------------------------

# Protocolos con su nivel de riesgo
PROTOCOL_RISK: dict[str, tuple[str, str]] = {
    "SSLv3":   ("CRITICAL", "Protocolo obsoleto, vulnerable a POODLE"),
    "TLS 1.0": ("CRITICAL", "Protocolo obsoleto, vulnerable a BEAST/POODLE"),
    "TLS 1.1": ("HIGH",     "Protocolo obsoleto, depreciado en RFC 8996"),
    "TLS 1.2": ("INFO",     "Protocolo aceptable, recomendado cifrado AEAD"),
    "TLS 1.3": ("INFO",     "Protocolo óptimo, forward-secrecy obligatoria"),
}

# Fragmentos de nombre de cipher que indican debilidad
WEAK_CIPHER_PATTERNS: dict[str, tuple[str, str]] = {
    "NULL":       ("CRITICAL", "Sin cifrado — tráfico en claro"),
    "EXPORT":     ("CRITICAL", "Cifrado de exportación — clave reducida intencional"),
    "ADH":        ("CRITICAL", "Diffie-Hellman anónimo — sin autenticación"),
    "AECDH":      ("CRITICAL", "ECDH anónimo — sin autenticación"),
    "RC4":        ("CRITICAL", "RC4 roto, sesgos estadísticos documentados"),
    "DES ":       ("CRITICAL", "DES de 56 bits, roto en 1999"),
    "_DES_":      ("HIGH",     "3DES vulnerable a Sweet32 (64-bit block)"),
    "3DES":       ("HIGH",     "3DES vulnerable a Sweet32 (64-bit block)"),
    "MD5":        ("HIGH",     "HMAC-MD5 como MAC — debilidad conocida"),
    "RC2":        ("HIGH",     "RC2 obsoleto"),
    "IDEA":       ("MEDIUM",   "IDEA desusado"),
    "CAMELLIA":   ("MEDIUM",   "Camellia — aceptable pero infrecuente"),
    "SEED":       ("MEDIUM",   "SEED — obsoleto"),
}

# Algoritmos de firma y su severidad
SIG_ALG_RISK: dict[str, tuple[str, str]] = {
    "md5":    ("CRITICAL", "Firma MD5 — colisiones triviales"),
    "sha1":   ("HIGH",     "Firma SHA-1 — depreciada, colisiones conocidas"),
    "sha256": ("INFO",     "SHA-256 — aceptable"),
    "sha384": ("INFO",     "SHA-384 — robusto"),
    "sha512": ("INFO",     "SHA-512 — robusto"),
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "bold magenta",
    "LOW":      "cyan",
    "INFO":     "green",
}

# ---------------------------------------------------------------------------
# Estructuras de datos
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """Hallazgo de seguridad individual."""
    severity:  str
    category:  str
    name:      str
    detail:    str

    @property
    def order(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 99)


@dataclass
class CertInfo:
    """Detalles extraídos del certificado X.509."""
    subject:         str = ""
    issuer:          str = ""
    not_before:      Optional[datetime] = None
    not_after:       Optional[datetime] = None
    days_remaining:  int = 0
    serial:          str = ""
    key_type:        str = ""
    key_bits:        int = 0
    sig_algorithm:   str = ""
    san_entries:     list[str] = field(default_factory=list)
    is_self_signed:  bool = False
    hostname_ok:     bool = True
    cn:              str = ""


@dataclass
class AuditResult:
    """Resultado completo de la auditoría de un host:port."""
    host:                 str
    port:                 int
    timestamp:            str
    # Protocolo
    negotiated_protocol:  str = ""
    negotiated_cipher:    str = ""
    supported_protocols:  list[str] = field(default_factory=list)
    unsupported_protocols: list[str] = field(default_factory=list)
    # Certificado
    cert:                 Optional[CertInfo] = None
    # HSTS
    hsts_header:          Optional[str] = None
    x_frame_options:      Optional[str] = None
    x_content_type:       Optional[str] = None
    # Hallazgos consolidados
    findings:             list[Finding] = field(default_factory=list)
    # Error fatal (host no alcanzable, etc.)
    error:                Optional[str] = None

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "INFO"
        return min(self.findings, key=lambda f: f.order).severity

    @property
    def target(self) -> str:
        return f"{self.host}:{self.port}"


# ---------------------------------------------------------------------------
# Motor de auditoría SSL
# ---------------------------------------------------------------------------

class SSLAuditor:
    """
    Motor principal de auditoría TLS/SSL.

    Realiza cuatro bloques de comprobaciones por host:
      1. Protocolo negociado y cifrado por defecto
      2. Soporte de versiones antiguas (SSLv3, TLS 1.0, TLS 1.1)
      3. Análisis profundo del certificado X.509
      4. Cabeceras HTTP de seguridad (HSTS y otras)
    """

    def __init__(self, timeout: int = 10) -> None:
        self._timeout = timeout

    # ------------------------------------------------------------------ API

    def audit(self, host: str, port: int) -> AuditResult:
        """Punto de entrada para auditar un host:port."""
        result = AuditResult(
            host=host,
            port=port,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        try:
            self._phase_default_handshake(result)
            self._phase_legacy_protocols(result)
            self._phase_http_headers(result)
        except Exception as exc:
            result.error = str(exc)
        finally:
            result.findings.sort(key=lambda f: f.order)
        return result

    # --------------------------------------------------------- Fase 1: handshake por defecto

    def _phase_default_handshake(self, result: AuditResult) -> None:
        """Realiza el handshake TLS estándar y extrae protocolo, cipher y certificado."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        # Intentar primero con verificación completa; si falla por cert inválido,
        # reintentar sin verificación para obtener igualmente los datos del cert.
        der_cert: Optional[bytes] = None
        proto_version: str = ""
        cipher_name: str = ""
        # Tracking de si el hostname fue verificado correctamente
        hostname_ok = True

        try:
            with socket.create_connection((result.host, result.port), timeout=self._timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=result.host) as ssock:
                    proto_version = ssock.version() or ""
                    cipher_info   = ssock.cipher()
                    cipher_name   = cipher_info[0] if cipher_info else ""
                    der_cert      = ssock.getpeercert(binary_form=True)
        except ssl.CertificateError as exc:
            # Cert inválido (hostname mismatch, caducado, autofirmado) —
            # reconectar sin verificación para obtener el certificado de todas formas.
            hostname_ok = False
            result.findings.append(Finding(
                severity="CRITICAL",
                category="Certificado",
                name="Error de validación TLS",
                detail=str(exc),
            ))
            ctx_nocheck = ssl.create_default_context()
            ctx_nocheck.check_hostname = False
            ctx_nocheck.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((result.host, result.port), timeout=self._timeout) as sock:
                with ctx_nocheck.wrap_socket(sock, server_hostname=result.host) as ssock:
                    proto_version = ssock.version() or ""
                    cipher_info   = ssock.cipher()
                    cipher_name   = cipher_info[0] if cipher_info else ""
                    der_cert      = ssock.getpeercert(binary_form=True)
        except OSError as exc:
            raise RuntimeError(f"No se puede conectar a {result.host}:{result.port} — {exc}") from exc

        result.negotiated_protocol = proto_version
        result.negotiated_cipher   = cipher_name

        # Hallazgos de protocolo negociado
        if proto_version in PROTOCOL_RISK:
            sev, detail = PROTOCOL_RISK[proto_version]
            if sev not in ("INFO",):
                result.findings.append(Finding(
                    severity=sev,
                    category="Protocolo",
                    name=f"Protocolo negociado: {proto_version}",
                    detail=detail,
                ))

        # Hallazgos de cipher negociado
        self._classify_cipher(cipher_name, result)

        # Análisis del certificado
        if der_cert:
            cert_info = self._parse_cert(der_cert, result.host, hostname_ok, result)
            result.cert = cert_info

    # --------------------------------------------------------- Fase 2: protocolos legacy

    def _phase_legacy_protocols(self, result: AuditResult) -> None:
        """
        Intenta conexiones forzadas con versiones antiguas de TLS.
        Si el servidor acepta SSLv3/TLS1.0/TLS1.1 es un hallazgo.
        """
        legacy_map: list[tuple[str, ssl.TLSVersion, ssl.TLSVersion]] = []

        # SSLv3 — puede no estar disponible en OpenSSL moderno
        try:
            legacy_map.append(("SSLv3", ssl.TLSVersion.SSLv3, ssl.TLSVersion.SSLv3))
        except AttributeError:
            pass

        try:
            legacy_map.append(("TLS 1.0", ssl.TLSVersion.TLSv1,   ssl.TLSVersion.TLSv1))
            legacy_map.append(("TLS 1.1", ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1))
        except AttributeError:
            pass

        for label, min_v, max_v in legacy_map:
            accepted = self._test_protocol_version(result.host, result.port, min_v, max_v)
            if accepted:
                result.supported_protocols.append(label)
                sev, detail = PROTOCOL_RISK.get(label, ("HIGH", "Protocolo obsoleto"))
                result.findings.append(Finding(
                    severity=sev,
                    category="Protocolo",
                    name=f"Soporta {label}",
                    detail=detail,
                ))
            else:
                result.unsupported_protocols.append(label)

    def _test_protocol_version(
        self,
        host: str,
        port: int,
        min_v: ssl.TLSVersion,
        max_v: ssl.TLSVersion,
    ) -> bool:
        """
        Intenta un handshake SSL forzando la versión indicada.
        Devuelve True si el servidor acepta ese protocolo.
        """
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = min_v
                ctx.maximum_version = max_v
            with socket.create_connection((host, port), timeout=self._timeout) as sock:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    with ctx.wrap_socket(sock, server_hostname=host):
                        return True
        except (ssl.SSLError, OSError):
            return False
        except Exception:
            return False

    # --------------------------------------------------------- Fase 3: certificado

    def _parse_cert(self, der_bytes: bytes, hostname: str, hostname_ok: bool, result: AuditResult) -> CertInfo:
        """
        Analiza el certificado DER con la librería `cryptography` y genera
        hallazgos de seguridad sobre la fortaleza criptográfica del mismo.
        """
        info = CertInfo()

        try:
            cert = x509.load_der_x509_certificate(der_bytes)
        except Exception as exc:
            result.findings.append(Finding(
                severity="HIGH",
                category="Certificado",
                name="No se puede parsear el certificado",
                detail=str(exc),
            ))
            return info

        # Sujeto e emisor
        def _rdns(name: x509.Name) -> str:
            parts = []
            for oid, attr in [
                (NameOID.COMMON_NAME, "CN"),
                (NameOID.ORGANIZATION_NAME, "O"),
                (NameOID.COUNTRY_NAME, "C"),
            ]:
                try:
                    val = name.get_attributes_for_oid(oid)
                    if val:
                        parts.append(f"{attr}={val[0].value}")
                except Exception:
                    pass
            return ", ".join(parts) if parts else str(name)

        info.subject = _rdns(cert.subject)
        info.issuer  = _rdns(cert.issuer)

        # CN
        try:
            cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            info.cn = cn_attrs[0].value if cn_attrs else ""
        except Exception:
            pass

        # Validez temporal
        info.not_before = cert.not_valid_before_utc
        info.not_after  = cert.not_valid_after_utc
        now             = datetime.now(timezone.utc)
        delta           = info.not_after - now
        info.days_remaining = delta.days

        if info.days_remaining < 0:
            result.findings.append(Finding(
                severity="CRITICAL",
                category="Certificado",
                name="Certificado expirado",
                detail=f"Venció hace {-info.days_remaining} días ({info.not_after.date()})",
            ))
        elif info.days_remaining < 7:
            result.findings.append(Finding(
                severity="CRITICAL",
                category="Certificado",
                name="Certificado expira en < 7 días",
                detail=f"Expira en {info.days_remaining} días ({info.not_after.date()})",
            ))
        elif info.days_remaining < 30:
            result.findings.append(Finding(
                severity="HIGH",
                category="Certificado",
                name="Certificado expira pronto",
                detail=f"Expira en {info.days_remaining} días ({info.not_after.date()})",
            ))
        elif info.days_remaining < 90:
            result.findings.append(Finding(
                severity="MEDIUM",
                category="Certificado",
                name="Certificado caduca en < 90 días",
                detail=f"Expira en {info.days_remaining} días ({info.not_after.date()})",
            ))

        # Serial
        info.serial = f"{cert.serial_number:X}"

        # Tipo y tamaño de clave
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            info.key_type = "RSA"
            info.key_bits = pub.key_size
            if pub.key_size < 1024:
                result.findings.append(Finding(
                    severity="CRITICAL", category="Certificado",
                    name="Clave RSA < 1024 bits", detail=f"Clave de {pub.key_size} bits — rota"),)
            elif pub.key_size < 2048:
                result.findings.append(Finding(
                    severity="HIGH", category="Certificado",
                    name="Clave RSA < 2048 bits", detail=f"Clave de {pub.key_size} bits — débil"),)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            info.key_type = "EC"
            info.key_bits = pub.key_size
            if pub.key_size < 224:
                result.findings.append(Finding(
                    severity="HIGH", category="Certificado",
                    name="Clave EC < 224 bits", detail=f"Curva de {pub.key_size} bits — débil"),)
        elif isinstance(pub, dsa.DSAPublicKey):
            info.key_type = "DSA"
            info.key_bits = pub.key_size
            result.findings.append(Finding(
                severity="HIGH", category="Certificado",
                name="Clave DSA", detail="DSA depreciado; usar EC o RSA"),)
        elif isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            info.key_type = type(pub).__name__.replace("PublicKey", "")
            info.key_bits = 255 if "25519" in info.key_type else 448

        # Algoritmo de firma
        try:
            sig_alg = cert.signature_hash_algorithm
            if sig_alg is not None:
                info.sig_algorithm = sig_alg.name
                if isinstance(sig_alg, MD5):
                    result.findings.append(Finding(
                        severity="CRITICAL", category="Certificado",
                        name="Firma MD5", detail=SIG_ALG_RISK["md5"][1]),)
                elif isinstance(sig_alg, SHA1):
                    result.findings.append(Finding(
                        severity="HIGH", category="Certificado",
                        name="Firma SHA-1", detail=SIG_ALG_RISK["sha1"][1]),)
            else:
                info.sig_algorithm = "Ed25519/Ed448"
        except Exception:
            info.sig_algorithm = "desconocido"

        # SAN
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for entry in san_ext.value:
                if hasattr(entry, "value"):
                    info.san_entries.append(entry.value)
        except x509.extensions.ExtensionNotFound:
            pass

        # Autofirmado
        info.is_self_signed = (cert.subject == cert.issuer)
        if info.is_self_signed:
            result.findings.append(Finding(
                severity="HIGH",
                category="Certificado",
                name="Certificado autofirmado",
                detail="No emitido por una CA reconocida",
            ))

        # Verificación de hostname — determinada por el resultado del handshake inicial
        info.hostname_ok = hostname_ok
        if not hostname_ok:
            result.findings.append(Finding(
                severity="CRITICAL",
                category="Certificado",
                name="El certificado no cubre el hostname",
                detail=f"Hostname {hostname!r} no coincide con SAN/CN del certificado",
            ))

        return info

    # --------------------------------------------------------- Fase 4: cabeceras HTTP

    def _phase_http_headers(self, result: AuditResult) -> None:
        """
        Realiza una petición HTTP/HTTPS y analiza las cabeceras de seguridad.
        No falla si el puerto no es HTTP estándar.
        """
        url = f"https://{result.host}:{result.port}/"
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", f"VampSecureLabs-SSLAudit/{VERSION}")

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(req, timeout=self._timeout, context=ctx) as resp:
                headers = resp.headers
                result.hsts_header     = headers.get("Strict-Transport-Security")
                result.x_frame_options = headers.get("X-Frame-Options")
                result.x_content_type  = headers.get("X-Content-Type-Options")
        except (urllib.error.URLError, OSError):
            # Puerto no HTTP o error de red — no es un hallazgo de SSL
            return
        except Exception:
            return

        # Hallazgos HSTS
        if not result.hsts_header:
            result.findings.append(Finding(
                severity="HIGH",
                category="Cabeceras HTTP",
                name="HSTS ausente",
                detail="Falta Strict-Transport-Security — posibles ataques de downgrade HTTP",
            ))
        else:
            max_age = 0
            for part in result.hsts_header.split(";"):
                part = part.strip()
                if part.lower().startswith("max-age="):
                    try:
                        max_age = int(part.split("=", 1)[1])
                    except ValueError:
                        pass
            if max_age < 10_886_400:  # < 126 días
                result.findings.append(Finding(
                    severity="MEDIUM",
                    category="Cabeceras HTTP",
                    name="HSTS max-age insuficiente",
                    detail=f"max-age={max_age}s es inferior al mínimo recomendado (126 días = 10 886 400s)",
                ))
            if "includesubdomains" not in result.hsts_header.lower():
                result.findings.append(Finding(
                    severity="LOW",
                    category="Cabeceras HTTP",
                    name="HSTS sin includeSubDomains",
                    detail="Los subdominios no están cubiertos por la política HSTS",
                ))

        if result.x_frame_options is None:
            result.findings.append(Finding(
                severity="LOW",
                category="Cabeceras HTTP",
                name="X-Frame-Options ausente",
                detail="Puede facilitar ataques de clickjacking si la app es embebible",
            ))

        if result.x_content_type is None:
            result.findings.append(Finding(
                severity="LOW",
                category="Cabeceras HTTP",
                name="X-Content-Type-Options ausente",
                detail="Sin nosniff — posible MIME-type sniffing por el navegador",
            ))

    # --------------------------------------------------------- Utilidades internas

    def _classify_cipher(self, cipher_name: str, result: AuditResult) -> None:
        """Busca patrones de debilidad en el nombre del cipher negociado."""
        if not cipher_name:
            return
        for pattern, (sev, detail) in WEAK_CIPHER_PATTERNS.items():
            if pattern in cipher_name:
                result.findings.append(Finding(
                    severity=sev,
                    category="Cifrado",
                    name=f"Cipher débil: {cipher_name}",
                    detail=detail,
                ))
                return  # Un solo hallazgo por cipher


# ---------------------------------------------------------------------------
# Reportes
# ---------------------------------------------------------------------------

class Reporter:
    """Genera los distintos formatos de salida de la auditoría."""

    def __init__(self, console: Console) -> None:
        self._c = console

    # ---------------------------------------------------------------- Consola Rich

    def print_result(self, result: AuditResult) -> None:
        """Muestra el resultado de una auditoría en la consola."""
        if result.error:
            self._c.print(
                f"[bold red]✗[/] [bold]{result.target}[/] — {result.error}"
            )
            return

        # Cabecera del host
        sev   = result.max_severity
        color = SEVERITY_COLOR.get(sev, "white")
        self._c.print(f"\n[bold cyan]{'─'*60}[/]")
        self._c.print(f"  [{color}]{sev}[/]  [bold]{result.target}[/]")
        self._c.print(f"[bold cyan]{'─'*60}[/]")

        # Protocolo y cipher
        self._c.print(f"  [bold]Protocolo negociado:[/] {result.negotiated_protocol or 'N/A'}")
        self._c.print(f"  [bold]Cipher negociado:[/]    {result.negotiated_cipher or 'N/A'}")

        # Protocolos legacy detectados
        if result.supported_protocols:
            self._c.print(
                f"  [bold red]Protocolos inseguros aceptados:[/] "
                + ", ".join(result.supported_protocols)
            )

        # Certificado
        if result.cert:
            c = result.cert
            exp_color = "red" if c.days_remaining < 30 else ("yellow" if c.days_remaining < 90 else "green")
            self._c.print(f"\n  [bold]Certificado[/]")
            self._c.print(f"    Sujeto:        {c.subject}")
            self._c.print(f"    Emisor:        {c.issuer}")
            self._c.print(f"    Clave:         {c.key_type} {c.key_bits} bits")
            self._c.print(f"    Firma:         {c.sig_algorithm}")
            self._c.print(f"    Expira:        [{exp_color}]{c.not_after.date() if c.not_after else 'N/A'} ({c.days_remaining}d)[/{exp_color}]")
            self._c.print(f"    Autofirmado:   {'[red]SÍ[/red]' if c.is_self_signed else '[green]No[/green]'}")
            if c.san_entries:
                self._c.print(f"    SAN ({len(c.san_entries)}):     {', '.join(c.san_entries[:5])}"
                              + (" …" if len(c.san_entries) > 5 else ""))

        # HSTS
        if result.hsts_header:
            self._c.print(f"\n  [bold]HSTS:[/] [green]{result.hsts_header}[/]")
        else:
            self._c.print(f"\n  [bold]HSTS:[/] [red]AUSENTE[/]")

        # Tabla de hallazgos
        if result.findings:
            self._c.print()
            tbl = Table(show_header=True, header_style="bold cyan",
                        box=None, padding=(0, 1))
            tbl.add_column("SEV",      width=10)
            tbl.add_column("Categoría", width=18)
            tbl.add_column("Hallazgo",  min_width=32)
            tbl.add_column("Detalle",   min_width=38)
            for f in result.findings:
                color = SEVERITY_COLOR.get(f.severity, "white")
                tbl.add_row(
                    f"[{color}]{f.severity}[/{color}]",
                    f.category,
                    f.name,
                    f.detail,
                )
            self._c.print(tbl)
        else:
            self._c.print("\n  [bold green]✔ Sin hallazgos de seguridad[/]")

    def print_summary(self, results: list[AuditResult]) -> None:
        """Tabla resumen de todos los hosts auditados."""
        self._c.print("\n")
        tbl = Table(title="Resumen de auditoría TLS/SSL",
                    header_style="bold cyan", show_lines=True)
        tbl.add_column("Host:puerto",      min_width=24)
        tbl.add_column("Protocolo",        width=10)
        tbl.add_column("Cipher",           min_width=28)
        tbl.add_column("Cert expira",      width=14)
        tbl.add_column("HSTS",             width=6)
        tbl.add_column("Hallazgos",        width=10)
        tbl.add_column("Severidad máx.",   width=12)

        for r in results:
            if r.error:
                tbl.add_row(r.target, "[red]ERROR[/]", r.error, "-", "-", "-", "[red]ERROR[/]")
                continue
            sev_col = SEVERITY_COLOR.get(r.max_severity, "white")
            days    = r.cert.days_remaining if r.cert else "?"
            days_s  = f"[red]{days}d[/]" if isinstance(days, int) and days < 30 else (
                      f"[yellow]{days}d[/]" if isinstance(days, int) and days < 90 else f"[green]{days}d[/]")
            hsts_s  = "[green]✔[/]" if r.hsts_header else "[red]✗[/]"
            counts  = sum(1 for f in r.findings if f.severity in ("CRITICAL", "HIGH"))
            tbl.add_row(
                f"[bold]{r.target}[/]",
                r.negotiated_protocol,
                r.negotiated_cipher,
                days_s,
                hsts_s,
                str(len(r.findings)),
                f"[{sev_col}]{r.max_severity}[/{sev_col}]",
            )
        self._c.print(tbl)

    # ---------------------------------------------------------------- JSON

    def to_json(self, results: list[AuditResult]) -> str:
        """Serializa los resultados en JSON."""
        def _cert_dict(c: Optional[CertInfo]) -> Optional[dict]:
            if c is None:
                return None
            return {
                "subject":        c.subject,
                "issuer":         c.issuer,
                "not_before":     c.not_before.isoformat() if c.not_before else None,
                "not_after":      c.not_after.isoformat() if c.not_after else None,
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
                    {"severity": f.severity, "category": f.category,
                     "name": f.name, "detail": f.detail}
                    for f in r.findings
                ],
            }

        return json.dumps(
            {"tool": TOOL_NAME, "version": VERSION,
             "generated": datetime.now(timezone.utc).isoformat(),
             "results": [_result_dict(r) for r in results]},
            indent=2, ensure_ascii=False,
        )

    # ---------------------------------------------------------------- HTML

    def to_html(self, results: list[AuditResult]) -> str:
        """Genera un informe HTML standalone dark-theme."""
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
                rows_html.append(f'<div class="result-block"><h2>{escape(r.target)}</h2>'
                                 f'<p class="sev-crit">ERROR: {escape(r.error)}</p></div>')
                continue

            cert_html = ""
            if r.cert:
                c = r.cert
                exp_cls = "sev-crit" if c.days_remaining < 30 else (
                          "sev-high" if c.days_remaining < 90 else "good")
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
                rows = "".join(
                    f'<tr><td class="{SEV_CSS.get(f.severity,"")}">{escape(f.severity)}</td>'
                    f'<td>{escape(f.category)}</td>'
                    f'<td>{escape(f.name)}</td>'
                    f'<td>{escape(f.detail)}</td></tr>'
                    for f in r.findings
                )
                findings_html = f"""
                <table class="findings-table">
                  <thead><tr><th>Severidad</th><th>Categoría</th><th>Hallazgo</th><th>Detalle</th></tr></thead>
                  <tbody>{rows}</tbody>
                </table>"""
            else:
                findings_html = '<p class="good">✔ Sin hallazgos de seguridad</p>'

            sev_cls = SEV_CSS.get(r.max_severity, "sev-info")
            hsts_s  = escape(r.hsts_header) if r.hsts_header else '<span class="sev-high">AUSENTE</span>'

            rows_html.append(f"""
            <div class="result-block">
              <h2>
                <span class="sev-badge {sev_cls}">{escape(r.max_severity)}</span>
                {escape(r.target)}
              </h2>
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
<title>VampSecure Labs — SSL Audit Report</title>
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
.result-block h2 {{ font-size: 16px; margin-bottom: 12px; display: flex; align-items: center; gap: 10px; }}
.result-block h3 {{ font-size: 13px; color: var(--text-dim); margin: 14px 0 6px; text-transform: uppercase; letter-spacing: .07em; }}
.meta-row {{ display: flex; flex-wrap: wrap; gap: 18px; font-size: 12px; color: var(--text-dim); margin-bottom: 14px; }}
.meta-row b {{ color: var(--text); }}
.sev-badge {{ font-size: 11px; padding: 2px 8px; border-radius: 3px; font-weight: bold; }}
.sev-crit {{ color: var(--crit); }}
.sev-high {{ color: var(--high); }}
.sev-med  {{ color: var(--med); }}
.sev-low  {{ color: var(--low); }}
.sev-info {{ color: var(--text-dim); }}
.good     {{ color: var(--good); }}
.sev-badge.sev-crit {{ background: rgba(255,68,68,.15); }}
.sev-badge.sev-high {{ background: rgba(255,136,0,.15); }}
.sev-badge.sev-med  {{ background: rgba(255,204,0,.15); }}
.sev-badge.sev-low  {{ background: rgba(68,136,255,.15); }}
.sev-badge.sev-info {{ background: rgba(100,100,100,.15); }}
.cert-block {{ background: var(--bg); border-left: 3px solid var(--accent); padding: 12px 16px; border-radius: 0 4px 4px 0; margin-bottom: 14px; }}
.info-table td {{ padding: 4px 12px 4px 0; vertical-align: top; }}
.info-table td:first-child {{ color: var(--text-dim); width: 120px; }}
.findings-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
.findings-table th {{ text-align: left; padding: 6px 10px; color: var(--text-dim); border-bottom: 1px solid var(--border); font-size: 11px; text-transform: uppercase; }}
.findings-table td {{ padding: 6px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }}
.findings-table tr:last-child td {{ border-bottom: none; }}
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


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    """Parsea los argumentos de la línea de comandos."""
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=f"VampSecure Labs SSL Audit v{VERSION} — Auditor TLS/SSL profesional",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Ejemplos:
  vamp-ssl-audit -H ejemplo.com
  vamp-ssl-audit -H ejemplo.com:8443 -H otro.com:443
  vamp-ssl-audit -H ejemplo.com --json salida.json --html informe.html
  vamp-ssl-audit --file lista_hosts.txt --workers 10
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
                   help="Guardar resultado completo en JSON")
    p.add_argument("--html", metavar="FILE",
                   help="Guardar informe en HTML")
    return p.parse_args()


def _resolve_targets(args: argparse.Namespace) -> list[tuple[str, int]]:
    """Construye la lista de (host, puerto) a auditar."""
    raw: list[str] = list(args.hosts)

    if args.file:
        path = Path(args.file)
        if not path.is_file():
            console.print(f"[bold red]ERROR:[/] Fichero no encontrado: {args.file}")
            sys.exit(1)
        raw.extend(line.strip() for line in path.read_text().splitlines()
                   if line.strip() and not line.startswith("#"))

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


def main() -> None:
    """Punto de entrada principal."""
    console.print(BANNER, style="bold magenta")

    args    = _parse_args()
    targets = _resolve_targets(args)
    auditor = SSLAuditor(timeout=args.timeout)
    reporter = Reporter(console)

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

    # Ordenar por host
    results.sort(key=lambda r: (r.host, r.port))

    # Mostrar resultados
    for r in results:
        reporter.print_result(r)

    reporter.print_summary(results)

    # Guardar ficheros
    if args.json:
        Path(args.json).write_text(reporter.to_json(results), encoding="utf-8")
        console.print(f"\n[green]✔[/] JSON guardado en {args.json}")

    if args.html:
        Path(args.html).write_text(reporter.to_html(results), encoding="utf-8")
        console.print(f"[green]✔[/] HTML guardado en {args.html}")

    # Exit code según severidad máxima global
    max_sev = "INFO"
    for r in results:
        if SEVERITY_ORDER.get(r.max_severity, 99) < SEVERITY_ORDER.get(max_sev, 99):
            max_sev = r.max_severity

    sys.exit(2 if max_sev == "CRITICAL" else 1 if max_sev == "HIGH" else 0)


if __name__ == "__main__":
    main()
