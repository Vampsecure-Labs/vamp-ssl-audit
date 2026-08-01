#!/usr/bin/env python3
"""
vamp_ssl_audit.py — Auditor TLS/SSL con calificación SSLabs-style
===================================================================
VampSecure Labs · VampSecure Studios
Para Uso Exclusivo en Pruebas de Penetración Autorizadas — v2.0

DESCRIPCIÓN GENERAL
-------------------
Auditor profesional de configuraciones TLS/SSL con sistema de calificación
inspirado en SSLabs (notas A+/A/A-/B/C/D/T/F). Analiza protocolos soportados,
suite de cifrado negociada, fortaleza del certificado digital y cabeceras de
seguridad HTTP. Genera remediaciones concretas para cada hallazgo y puede
exportar informes en JSON, HTML, Markdown y CSV.

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
    · Certificado autofirmado y cobertura de hostname (SAN / CN)

  Cabeceras HTTP de seguridad
    · Strict-Transport-Security (HSTS): presencia, max-age, includeSubDomains, preload
    · X-Frame-Options, X-Content-Type-Options

SISTEMA DE CALIFICACIÓN (SSLabs-style)
---------------------------------------
  A+ · Configuración excepcional: TLS 1.3 + HSTS completo + sin legacies
  A  · Buena configuración: sin problemas significativos
  A- · Buena configuración: HSTS incompleto o TLS 1.3 no disponible
  B  · Aceptable: TLS 1.0/1.1, 3DES, SHA-1 o RSA < 2048 presentes
  C  · Deficiente: SSLv3, RC4 o firma MD5 aceptados
  D  · Muy deficiente
  T  · Certificado no confiable: autofirmado o sin cobertura del hostname
  F  · Fallo crítico: cifrado nulo, cert expirado o error de conexión

FORMATOS DE SALIDA
------------------
  Consola  · Rich con color y tablas
  JSON     · --json FILE   (estructura completa con hallazgos y remediaciones)
  HTML     · --html FILE   (informe dark-theme standalone con insignia de nota)
  Markdown · --markdown FILE (incluible en informes de auditoría)
  CSV      · --csv FILE    (fila por host + fila por hallazgo en segundo fichero)

DEPENDENCIAS
------------
  cryptography >= 41.0.0
  rich         >= 13.7.0

AUTORÍA
-------
  © VampSecure Studios — VampSecure Labs Security Research Division
  Todos los derechos reservados. Uso exclusivo en entornos autorizados.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv as csv_module
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

VERSION   = "2.0"
TOOL_NAME = "vamp-ssl-audit"

console = Console()

BANNER = r"""
  ____   ____    _    __  __ ____  _____ ____ _   _ ____  _____   _        _    ____ ____
 \ \ / / _  |  / \  |  \/  |  _ \/ ____/ ___| | | |  _ \| ____| | |      / \  | __ ) ___|
  \ V / (_| | / _ \ | |\/| | |_) \___ \| |___| | | | |_) |  _|   | |     / _ \ |  _ \___ \
   | |  \__, |/ ___ \| |  | |  __/ ___) |___  | |_| |  _ <| |___  | |___ / ___ \| |_) |__) |
   |_|     /_/_/   \_|_|  |_|_|   |____/\____|\___/|_| \_|_____| |_____/_/   \_|____/____/
     by VampSecure Studios · vamp-ssl-audit v2.0 · TLS/SSL Professional Auditor
     ────────────────────────────────────────────────────────────────────────────
     USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""

# ---------------------------------------------------------------------------
# Constantes de clasificación de protocolos y cifrados
# ---------------------------------------------------------------------------

PROTOCOL_RISK: dict[str, tuple[str, str]] = {
    "SSLv3":   ("CRITICAL", "Protocolo obsoleto, vulnerable a POODLE (RFC 7568)"),
    "TLS 1.0": ("CRITICAL", "Protocolo obsoleto, vulnerable a BEAST/POODLE (RFC 8996)"),
    "TLS 1.1": ("HIGH",     "Protocolo obsoleto, depreciado en RFC 8996"),
    "TLS 1.2": ("INFO",     "Protocolo aceptable, recomendado cifrado AEAD"),
    "TLS 1.3": ("INFO",     "Protocolo óptimo, forward-secrecy obligatoria"),
}

# Cap de nota SSLabs por protocolo legacy detectado
PROTOCOL_GRADE_CAP: dict[str, str] = {
    "SSLv3":   "C",
    "TLS 1.0": "B",
    "TLS 1.1": "B",
}

# Fragmentos de nombre de cipher que indican debilidad
WEAK_CIPHER_PATTERNS: dict[str, tuple[str, str]] = {
    "NULL":    ("CRITICAL", "Sin cifrado — tráfico en claro"),
    "EXPORT":  ("CRITICAL", "Cifrado de exportación — clave reducida intencional"),
    "ADH":     ("CRITICAL", "Diffie-Hellman anónimo — sin autenticación del servidor"),
    "AECDH":   ("CRITICAL", "ECDH anónimo — sin autenticación del servidor"),
    "RC4":     ("CRITICAL", "RC4 roto, sesgos estadísticos documentados (RFC 7465)"),
    "DES ":    ("CRITICAL", "DES de 56 bits, roto en 1999"),
    "_DES_":   ("HIGH",     "3DES vulnerable a Sweet32 (bloque de 64 bits)"),
    "3DES":    ("HIGH",     "3DES vulnerable a Sweet32 (bloque de 64 bits)"),
    "MD5":     ("HIGH",     "HMAC-MD5 como MAC — debilidad conocida"),
    "RC2":     ("HIGH",     "RC2 obsoleto y sin soporte activo"),
    "IDEA":    ("MEDIUM",   "IDEA desusado"),
    "CAMELLIA":("MEDIUM",   "Camellia — aceptable pero poco habitual"),
    "SEED":    ("MEDIUM",   "SEED — estándar coreano obsoleto"),
}

# Cap de nota SSLabs por patrón de cipher débil
CIPHER_GRADE_CAP: dict[str, str] = {
    "NULL":    "F",
    "EXPORT":  "F",
    "ADH":     "F",
    "AECDH":   "F",
    "RC4":     "C",
    "DES ":    "C",
    "_DES_":   "B",
    "3DES":    "B",
    "MD5":     "C",
    "RC2":     "B",
}

# Algoritmos de firma y su severidad
SIG_ALG_RISK: dict[str, tuple[str, str]] = {
    "md5":    ("CRITICAL", "Firma MD5 — colisiones triviales demostrables"),
    "sha1":   ("HIGH",     "Firma SHA-1 — depreciada, colisiones conocidas (SHAttered)"),
    "sha256": ("INFO",     "SHA-256 — estándar mínimo recomendado"),
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
# Sistema de calificación SSLabs-style
# ---------------------------------------------------------------------------

# Lista de notas de mejor a peor
GRADE_ORDER_LIST = ["A+", "A", "A-", "B", "C", "D", "T", "F"]

GRADE_COLOR: dict[str, str] = {
    "A+": "bold bright_green",
    "A":  "bold green",
    "A-": "bold yellow",
    "B":  "bold yellow",
    "C":  "bold dark_orange",
    "D":  "bold red3",
    "T":  "bold magenta",
    "F":  "bold red",
}

GRADE_DESCRIPTION: dict[str, str] = {
    "A+": "Configuración excepcional — todas las mejores prácticas cumplidas",
    "A":  "Buena configuración — sin problemas significativos",
    "A-": "Buena configuración — HSTS o soporte de TLS 1.3 mejorable",
    "B":  "Configuración aceptable — protocolos legacy o cifrados débiles presentes",
    "C":  "Configuración deficiente — SSLv3, RC4 o firma MD5 aceptada",
    "D":  "Configuración muy deficiente",
    "T":  "Certificado no confiable — autofirmado o sin cobertura del hostname",
    "F":  "Fallo crítico — cifrado nulo, certificado expirado o conexión imposible",
}

# Color HTML de cada nota (clase CSS, color hex)
HTML_GRADE_COLOR: dict[str, tuple[str, str]] = {
    "A+": ("grade-aplus",  "#00cc55"),
    "A":  ("grade-a",      "#22aa44"),
    "A-": ("grade-aminus", "#aacc00"),
    "B":  ("grade-b",      "#ffcc00"),
    "C":  ("grade-c",      "#ff8800"),
    "D":  ("grade-d",      "#ff5500"),
    "T":  ("grade-t",      "#cc44cc"),
    "F":  ("grade-f",      "#ff2222"),
}


def _apply_cap(current: str, cap: str) -> str:
    """
    Aplica un cap de nota: devuelve la nota más restrictiva entre las dos.
    Una nota más a la derecha en GRADE_ORDER_LIST es más restrictiva.
    """
    ci = GRADE_ORDER_LIST.index(current) if current in GRADE_ORDER_LIST else 0
    ca = GRADE_ORDER_LIST.index(cap)     if cap     in GRADE_ORDER_LIST else 0
    return GRADE_ORDER_LIST[max(ci, ca)]


def compute_grade(result: "AuditResult") -> str:
    """
    Calcula la calificación SSLabs-style del resultado de la auditoría.

    Reglas de cap en orden de prioridad (más restrictivo gana):
      F : Cifrado NULL/EXPORT/anónimo · cert expirado · clave RSA<512 · error de conexión
      T : Cert autofirmado o sin cobertura del hostname (sin F previo)
      C : SSLv3 aceptado · RC4 · DES puro · firma MD5
      B : TLS 1.0/1.1 aceptados · 3DES · firma SHA-1 · RSA<2048 · EC<224 · DSA
      A : HSTS ausente o TLS 1.3 no negociado por defecto
      A-: HSTS max-age<180d · sin includeSubDomains · sin preload
      A+: Todo correcto
    """
    if result.error:
        return "F"

    grade = "A+"

    # Aplica todos los caps de cada hallazgo individual
    for f in result.findings:
        if f.grade_cap:
            grade = _apply_cap(grade, f.grade_cap)

    # Lógica adicional que no genera hallazgo individual pero sí afecta la nota
    if grade in ("A+", "A", "A-"):
        # TLS 1.3 requerido para A+
        if grade == "A+" and result.negotiated_protocol != "TLSv1.3":
            grade = _apply_cap(grade, "A")

        # HSTS: analizar si es completo para decidir entre A+ / A / A-
        if result.hsts_header:
            has_subs    = "includesubdomains" in result.hsts_header.lower()
            has_preload = "preload"            in result.hsts_header.lower()
            max_age     = 0
            for part in result.hsts_header.split(";"):
                p = part.strip()
                if p.lower().startswith("max-age="):
                    try:
                        max_age = int(p.split("=", 1)[1].strip())
                    except ValueError:
                        pass
            # max-age ≥ 180 días + includeSubDomains + sin preload → A (no A+)
            if max_age >= 15_552_000 and has_subs and not has_preload:
                grade = _apply_cap(grade, "A")

    return grade


# ---------------------------------------------------------------------------
# Textos de remediación por tipo de hallazgo
# ---------------------------------------------------------------------------

_REMED_TLS_LEGACY = (
    "Eliminar el protocolo de la lista permitida:\n"
    "  nginx:   ssl_protocols TLSv1.2 TLSv1.3;\n"
    "  apache:  SSLProtocol -all +TLSv1.2 +TLSv1.3\n"
    "  haproxy: bind *:443 ssl-min-ver TLSv1.2\n"
    "Ref: RFC 8996, PCI-DSS 4.0 §4.2.1"
)

_REMED_NULL_CIPHER = (
    "Eliminar cifrados NULL de la configuración:\n"
    "  nginx:   ssl_ciphers ECDH+AESGCM:ECDH+CHACHA20:!NULL:!EXPORT;\n"
    "  apache:  SSLCipherSuite HIGH:!NULL:!EXPORT:!MD5:!3DES\n"
    "  haproxy: ssl-default-bind-ciphers ECDH+AESGCM:ECDH+CHACHA20\n"
    "Urgencia: CRÍTICA — el tráfico circula en claro."
)

_REMED_EXPORT_CIPHER = (
    "Eliminar cifrados EXPORT (diseñados para ser débiles intencionalmente):\n"
    "  nginx:   ssl_ciphers '!EXPORT:HIGH:ECDH+AESGCM:ECDH+CHACHA20';\n"
    "  apache:  SSLCipherSuite HIGH:!EXPORT:!NULL\n"
    "Urgencia: CRÍTICA — clave de sesión reducible a ≤40 bits."
)

_REMED_ANON_CIPHER = (
    "Eliminar cifrados anónimos (sin autenticación del servidor):\n"
    "  nginx:   ssl_ciphers '!ADH:!AECDH:HIGH:ECDH+AESGCM';\n"
    "  apache:  SSLCipherSuite HIGH:!ADH:!AECDH:!EXPORT\n"
    "Urgencia: CRÍTICA — cualquiera puede hacerse pasar por el servidor."
)

_REMED_RC4 = (
    "Eliminar RC4 (sesgos estadísticos permiten recuperar texto claro):\n"
    "  nginx:   ssl_ciphers '!RC4:ECDH+AESGCM:ECDH+CHACHA20';\n"
    "  apache:  SSLCipherSuite HIGH:!RC4:!EXPORT\n"
    "Ref: RFC 7465"
)

_REMED_DES = (
    "Eliminar DES (clave de 56 bits, roto desde 1998):\n"
    "  nginx:   ssl_ciphers 'HIGH:!DES:!3DES:ECDH+AESGCM';\n"
    "  apache:  SSLCipherSuite HIGH:!DES:!3DES"
)

_REMED_3DES = (
    "Eliminar 3DES (vulnerable a Sweet32, bloque de 64 bits):\n"
    "  nginx:   ssl_ciphers 'HIGH:!3DES:ECDH+AESGCM:ECDH+CHACHA20';\n"
    "  apache:  SSLCipherSuite HIGH:!3DES:!DES:!RC4\n"
    "Ref: CVE-2016-2183 (Sweet32)"
)

_REMED_CERT_EXPIRED = (
    "Renovar el certificado de inmediato:\n"
    "  Let's Encrypt:  certbot renew --force-renewal\n"
    "  Comercial:      generar nueva CSR y renovar en la CA\n"
    "Urgencia: CRÍTICA — los navegadores rechazan la conexión."
)

_REMED_CERT_EXPIRING = (
    "Renovar el certificado antes de su vencimiento:\n"
    "  Let's Encrypt:  certbot renew  (se puede ejecutar ya)\n"
    "  Comercial:      iniciar proceso de renovación en la CA\n"
    "Recomendado: renovar con ≥30 días de antelación."
)

_REMED_SELF_SIGNED = (
    "Obtener un certificado firmado por una CA de confianza:\n"
    "  Gratuito:  certbot --nginx -d ejemplo.com  (Let's Encrypt)\n"
    "  Interno:   configurar la CA raíz corporativa en los clientes\n"
    "Urgencia: ALTA — los navegadores muestran advertencia de seguridad."
)

_REMED_RSA_SMALL = (
    "Generar una clave RSA de mínimo 2048 bits (recomendado 4096):\n"
    "  openssl genrsa -out clave.key 4096\n"
    "  openssl req -new -key clave.key -out solicitud.csr\n"
    "Ref: NIST SP 800-131Ar2"
)

_REMED_RSA_WEAK = (
    "Generar una clave RSA de al menos 2048 bits (recomendado 4096):\n"
    "  openssl genrsa -out clave.key 4096\n"
    "  openssl req -new -key clave.key -out solicitud.csr\n"
    "Ref: NIST SP 800-131Ar2"
)

_REMED_SHA1 = (
    "Renovar el certificado con algoritmo de firma SHA-256 o superior:\n"
    "  openssl req -new -sha256 -key clave.key -out solicitud.csr\n"
    "Los navegadores modernos muestran advertencia con SHA-1 desde 2017."
)

_REMED_MD5 = (
    "Renovar el certificado con algoritmo de firma SHA-256 o superior:\n"
    "  openssl req -new -sha256 -key clave.key -out solicitud.csr\n"
    "Urgencia: CRÍTICA — colisiones MD5 son triviales (Flame, 2012)."
)

_REMED_HSTS_ABSENT = (
    "Añadir cabecera HSTS a la respuesta del servidor:\n"
    "  nginx:   add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload';\n"
    "  apache:  Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload'\n"
    "  haproxy: http-response set-header Strict-Transport-Security max-age=31536000;includeSubDomains;preload\n"
    "Ref: RFC 6797 · Registrar en https://hstspreload.org para preload"
)

_REMED_HSTS_SHORT = (
    "Aumentar max-age a mínimo 180 días (15 552 000 s), recomendado 1 año:\n"
    "  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n"
    "El valor actual es insuficiente para el preload de navegadores."
)

_REMED_HSTS_NO_SUBS = (
    "Añadir includeSubDomains a la cabecera HSTS:\n"
    "  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n"
    "Sin includeSubDomains los subdominios quedan desprotegidos."
)

_REMED_XFO = (
    "Añadir cabecera X-Frame-Options para prevenir clickjacking:\n"
    "  nginx:   add_header X-Frame-Options DENY;\n"
    "  apache:  Header always set X-Frame-Options DENY\n"
    "Usar SAMEORIGIN si la app legítimamente embebe su propio contenido."
)

_REMED_XCTO = (
    "Añadir cabecera X-Content-Type-Options para prevenir MIME sniffing:\n"
    "  nginx:   add_header X-Content-Type-Options nosniff;\n"
    "  apache:  Header always set X-Content-Type-Options nosniff"
)

_REMED_HOSTNAME = (
    "El certificado instalado no cubre este hostname.\n"
    "Soluciones:\n"
    "  a) Obtener un certificado que incluya este hostname en su SAN\n"
    "  b) Añadir el hostname como SAN adicional al renovar\n"
    "Ref: RFC 2818 §3.1 — el CN es ignorado si existen SAN"
)

_REMED_DSA = (
    "Migrar a clave RSA (≥2048 bits) o EC (P-256/P-384):\n"
    "  openssl ecparam -name prime256v1 -genkey -noout -out clave-ec.key\n"
    "  openssl req -new -sha256 -key clave-ec.key -out solicitud.csr\n"
    "DSA está depreciado en la mayoría de CAs desde 2015."
)

# ---------------------------------------------------------------------------
# Estructuras de datos
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """Hallazgo de seguridad individual con remediación y cap de nota."""
    severity:    str
    category:    str
    name:        str
    detail:      str
    remediation: str = ""   # Texto de remediación con pasos concretos
    grade_cap:   str = ""   # Cap de nota SSLabs que aplica este hallazgo

    @property
    def order(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 99)


@dataclass
class CertInfo:
    """Detalles extraídos del certificado X.509."""
    subject:        str = ""
    issuer:         str = ""
    not_before:     Optional[datetime] = None
    not_after:      Optional[datetime] = None
    days_remaining: int = 0
    serial:         str = ""
    key_type:       str = ""
    key_bits:       int = 0
    sig_algorithm:  str = ""
    san_entries:    list[str] = field(default_factory=list)
    is_self_signed: bool = False
    hostname_ok:    bool = True
    cn:             str = ""


@dataclass
class AuditResult:
    """Resultado completo de la auditoría de un host:port."""
    host:                  str
    port:                  int
    timestamp:             str
    # Protocolo
    negotiated_protocol:   str = ""
    negotiated_cipher:     str = ""
    supported_protocols:   list[str] = field(default_factory=list)
    unsupported_protocols: list[str] = field(default_factory=list)
    # Certificado
    cert:                  Optional[CertInfo] = None
    # Cabeceras HTTP
    hsts_header:           Optional[str] = None
    x_frame_options:       Optional[str] = None
    x_content_type:        Optional[str] = None
    # Hallazgos consolidados
    findings:              list[Finding] = field(default_factory=list)
    # Calificación SSLabs-style (calculada al finalizar la auditoría)
    grade:                 str = ""
    # Error fatal (host no alcanzable, etc.)
    error:                 Optional[str] = None

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

    Fases de comprobación:
      1. Protocolo negociado y cifrado por defecto
      2. Soporte de versiones antiguas (SSLv3, TLS 1.0, TLS 1.1)
      3. Análisis profundo del certificado X.509
      4. Cabeceras HTTP de seguridad (HSTS y otras)
      5. Cálculo de nota SSLabs-style
    """

    def __init__(self, timeout: int = 10) -> None:
        self._timeout = timeout

    # ------------------------------------------------------------------ API pública

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
            result.grade = compute_grade(result)
        return result

    # --------------------------------------------------------- Fase 1: handshake por defecto

    def _phase_default_handshake(self, result: AuditResult) -> None:
        """Realiza el handshake TLS estándar y extrae protocolo, cipher y certificado."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode    = ssl.CERT_REQUIRED

        der_cert:    Optional[bytes] = None
        proto_version: str = ""
        cipher_name:   str = ""
        hostname_ok:   bool = True

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
                grade_cap="T",
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

        # Hallazgos del protocolo negociado por defecto
        if proto_version in PROTOCOL_RISK:
            sev, detail = PROTOCOL_RISK[proto_version]
            if sev not in ("INFO",):
                cap = PROTOCOL_GRADE_CAP.get(proto_version, "B")
                result.findings.append(Finding(
                    severity=sev,
                    category="Protocolo",
                    name=f"Protocolo negociado: {proto_version}",
                    detail=detail,
                    remediation=_REMED_TLS_LEGACY,
                    grade_cap=cap,
                ))

        # Hallazgos del cipher negociado
        self._classify_cipher(cipher_name, result)

        # Análisis del certificado
        if der_cert:
            cert_info = self._parse_cert(der_cert, result.host, hostname_ok, result)
            result.cert = cert_info

    # --------------------------------------------------------- Fase 2: protocolos legacy

    def _phase_legacy_protocols(self, result: AuditResult) -> None:
        """
        Intenta conexiones forzadas con versiones antiguas de TLS.
        Si el servidor acepta SSLv3/TLS1.0/TLS1.1, genera un hallazgo.
        """
        legacy_map: list[tuple[str, ssl.TLSVersion, ssl.TLSVersion]] = []

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
                cap = PROTOCOL_GRADE_CAP.get(label, "B")
                result.findings.append(Finding(
                    severity=sev,
                    category="Protocolo",
                    name=f"Soporta {label}",
                    detail=detail,
                    remediation=_REMED_TLS_LEGACY,
                    grade_cap=cap,
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
                grade_cap="F",
            ))
            return info

        # Sujeto e emisor
        def _rdns(name: x509.Name) -> str:
            parts = []
            for oid, attr in [
                (NameOID.COMMON_NAME,        "CN"),
                (NameOID.ORGANIZATION_NAME,  "O"),
                (NameOID.COUNTRY_NAME,       "C"),
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

        try:
            cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            info.cn = cn_attrs[0].value if cn_attrs else ""
        except Exception:
            pass

        # Validez temporal
        info.not_before = cert.not_valid_before_utc
        info.not_after  = cert.not_valid_after_utc
        now             = datetime.now(timezone.utc)
        info.days_remaining = (info.not_after - now).days

        if info.days_remaining < 0:
            result.findings.append(Finding(
                severity="CRITICAL",
                category="Certificado",
                name="Certificado expirado",
                detail=f"Venció hace {-info.days_remaining} días ({info.not_after.date()})",
                remediation=_REMED_CERT_EXPIRED,
                grade_cap="F",
            ))
        elif info.days_remaining < 7:
            result.findings.append(Finding(
                severity="CRITICAL",
                category="Certificado",
                name="Certificado expira en < 7 días",
                detail=f"Expira en {info.days_remaining} días ({info.not_after.date()})",
                remediation=_REMED_CERT_EXPIRED,
                grade_cap="F",
            ))
        elif info.days_remaining < 30:
            result.findings.append(Finding(
                severity="HIGH",
                category="Certificado",
                name="Certificado expira en < 30 días",
                detail=f"Expira en {info.days_remaining} días ({info.not_after.date()})",
                remediation=_REMED_CERT_EXPIRING,
                grade_cap="B",
            ))
        elif info.days_remaining < 90:
            result.findings.append(Finding(
                severity="MEDIUM",
                category="Certificado",
                name="Certificado caduca en < 90 días",
                detail=f"Expira en {info.days_remaining} días ({info.not_after.date()})",
                remediation=_REMED_CERT_EXPIRING,
            ))

        # Serial
        info.serial = f"{cert.serial_number:X}"

        # Tipo y tamaño de clave pública
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            info.key_type = "RSA"
            info.key_bits = pub.key_size
            if pub.key_size < 1024:
                result.findings.append(Finding(
                    severity="CRITICAL", category="Certificado",
                    name="Clave RSA < 1024 bits",
                    detail=f"Clave de {pub.key_size} bits — rota criptográficamente",
                    remediation=_REMED_RSA_SMALL,
                    grade_cap="F",
                ))
            elif pub.key_size < 2048:
                result.findings.append(Finding(
                    severity="HIGH", category="Certificado",
                    name="Clave RSA < 2048 bits",
                    detail=f"Clave de {pub.key_size} bits — por debajo del mínimo recomendado",
                    remediation=_REMED_RSA_WEAK,
                    grade_cap="B",
                ))
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            info.key_type = "EC"
            info.key_bits = pub.key_size
            if pub.key_size < 224:
                result.findings.append(Finding(
                    severity="HIGH", category="Certificado",
                    name="Clave EC < 224 bits",
                    detail=f"Curva de {pub.key_size} bits — por debajo del mínimo seguro",
                    remediation=_REMED_RSA_SMALL,
                    grade_cap="B",
                ))
        elif isinstance(pub, dsa.DSAPublicKey):
            info.key_type = "DSA"
            info.key_bits = pub.key_size
            result.findings.append(Finding(
                severity="HIGH", category="Certificado",
                name="Clave DSA",
                detail="DSA depreciado; migrar a RSA ≥ 2048 bits o EC P-256/P-384",
                remediation=_REMED_DSA,
                grade_cap="B",
            ))
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
                        name="Firma MD5",
                        detail=SIG_ALG_RISK["md5"][1],
                        remediation=_REMED_MD5,
                        grade_cap="C",
                    ))
                elif isinstance(sig_alg, SHA1):
                    result.findings.append(Finding(
                        severity="HIGH", category="Certificado",
                        name="Firma SHA-1",
                        detail=SIG_ALG_RISK["sha1"][1],
                        remediation=_REMED_SHA1,
                        grade_cap="B",
                    ))
            else:
                info.sig_algorithm = "Ed25519/Ed448"
        except Exception:
            info.sig_algorithm = "desconocido"

        # Subject Alternative Names
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for entry in san_ext.value:
                if hasattr(entry, "value"):
                    info.san_entries.append(entry.value)
        except x509.extensions.ExtensionNotFound:
            pass

        # Certificado autofirmado
        info.is_self_signed = (cert.subject == cert.issuer)
        if info.is_self_signed:
            result.findings.append(Finding(
                severity="HIGH",
                category="Certificado",
                name="Certificado autofirmado",
                detail="No emitido por una CA reconocida — los navegadores muestran advertencia",
                remediation=_REMED_SELF_SIGNED,
                grade_cap="T",
            ))

        # Cobertura del hostname (determinada por el resultado del handshake inicial)
        info.hostname_ok = hostname_ok
        if not hostname_ok and not info.is_self_signed:
            result.findings.append(Finding(
                severity="CRITICAL",
                category="Certificado",
                name="El certificado no cubre el hostname",
                detail=f"Hostname {hostname!r} no coincide con SAN/CN del certificado",
                remediation=_REMED_HOSTNAME,
                grade_cap="T",
            ))

        return info

    # --------------------------------------------------------- Fase 4: cabeceras HTTP

    def _phase_http_headers(self, result: AuditResult) -> None:
        """
        Realiza una petición HTTPS y analiza las cabeceras de seguridad.
        No falla si el puerto no responde a HTTP.
        """
        url = f"https://{result.host}:{result.port}/"
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", f"VampSecureLabs-SSLAudit/{VERSION}")

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(req, timeout=self._timeout, context=ctx) as resp:
                headers             = resp.headers
                result.hsts_header     = headers.get("Strict-Transport-Security")
                result.x_frame_options = headers.get("X-Frame-Options")
                result.x_content_type  = headers.get("X-Content-Type-Options")
        except (urllib.error.URLError, OSError):
            return  # Puerto no HTTP o error de red — no es un hallazgo TLS
        except Exception:
            return

        # HSTS
        if not result.hsts_header:
            result.findings.append(Finding(
                severity="HIGH",
                category="Cabeceras HTTP",
                name="HSTS ausente",
                detail="Falta Strict-Transport-Security — posibles ataques de downgrade HTTP→HTTPS",
                remediation=_REMED_HSTS_ABSENT,
                grade_cap="A",
            ))
        else:
            max_age = 0
            for part in result.hsts_header.split(";"):
                p = part.strip()
                if p.lower().startswith("max-age="):
                    try:
                        max_age = int(p.split("=", 1)[1].strip())
                    except ValueError:
                        pass

            if max_age < 10_886_400:  # < 126 días
                result.findings.append(Finding(
                    severity="MEDIUM",
                    category="Cabeceras HTTP",
                    name="HSTS max-age insuficiente",
                    detail=f"max-age={max_age}s es inferior al mínimo recomendado (180 días = 15 552 000s)",
                    remediation=_REMED_HSTS_SHORT,
                    grade_cap="A-",
                ))
            if "includesubdomains" not in result.hsts_header.lower():
                result.findings.append(Finding(
                    severity="LOW",
                    category="Cabeceras HTTP",
                    name="HSTS sin includeSubDomains",
                    detail="Los subdominios no están cubiertos por la política HSTS",
                    remediation=_REMED_HSTS_NO_SUBS,
                    grade_cap="A-",
                ))

        # X-Frame-Options
        if result.x_frame_options is None:
            result.findings.append(Finding(
                severity="LOW",
                category="Cabeceras HTTP",
                name="X-Frame-Options ausente",
                detail="Puede facilitar ataques de clickjacking si la app es embebible en iframe",
                remediation=_REMED_XFO,
            ))

        # X-Content-Type-Options
        if result.x_content_type is None:
            result.findings.append(Finding(
                severity="LOW",
                category="Cabeceras HTTP",
                name="X-Content-Type-Options ausente",
                detail="Sin nosniff — posible MIME-type sniffing por el navegador",
                remediation=_REMED_XCTO,
            ))

    # --------------------------------------------------------- Utilidades internas

    def _classify_cipher(self, cipher_name: str, result: AuditResult) -> None:
        """Busca patrones de debilidad en el nombre del cipher negociado."""
        if not cipher_name:
            return

        remed_map = {
            "NULL": _REMED_NULL_CIPHER,
            "EXPORT": _REMED_EXPORT_CIPHER,
            "ADH": _REMED_ANON_CIPHER,
            "AECDH": _REMED_ANON_CIPHER,
            "RC4": _REMED_RC4,
            "DES ": _REMED_DES,
            "_DES_": _REMED_3DES,
            "3DES": _REMED_3DES,
        }

        for pattern, (sev, detail) in WEAK_CIPHER_PATTERNS.items():
            if pattern in cipher_name:
                cap   = CIPHER_GRADE_CAP.get(pattern, "")
                remed = remed_map.get(pattern, "")
                result.findings.append(Finding(
                    severity=sev,
                    category="Cifrado",
                    name=f"Cipher débil: {cipher_name}",
                    detail=detail,
                    remediation=remed,
                    grade_cap=cap,
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
        """Muestra el resultado de un host en la consola con su nota prominente."""
        if result.error:
            self._c.print(
                f"[bold red]✗[/] [bold]{result.target}[/] — {result.error}"
            )
            return

        sev        = result.max_severity
        sev_color  = SEVERITY_COLOR.get(sev, "white")
        grade      = result.grade
        grade_col  = GRADE_COLOR.get(grade, "white")
        grade_desc = GRADE_DESCRIPTION.get(grade, "")

        self._c.print(f"\n[bold cyan]{'─'*60}[/]")
        # Nota prominente al estilo SSLabs
        self._c.print(
            f"  Nota: [{grade_col}]{grade:>2}[/{grade_col}]  "
            f"[bold]{result.target}[/]  "
            f"[{sev_color}]{sev}[/{sev_color}]"
        )
        self._c.print(f"  [dim]{grade_desc}[/]")
        self._c.print(f"[bold cyan]{'─'*60}[/]")

        self._c.print(f"  [bold]Protocolo negociado:[/] {result.negotiated_protocol or 'N/A'}")
        self._c.print(f"  [bold]Cipher negociado:[/]    {result.negotiated_cipher or 'N/A'}")

        if result.supported_protocols:
            self._c.print(
                "  [bold red]Protocolos inseguros aceptados:[/] "
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
            self._c.print(
                f"    Expira:        [{exp_color}]"
                f"{c.not_after.date() if c.not_after else 'N/A'} ({c.days_remaining}d)"
                f"[/{exp_color}]"
            )
            self._c.print(f"    Autofirmado:   {'[red]SÍ[/red]' if c.is_self_signed else '[green]No[/green]'}")
            if c.san_entries:
                self._c.print(
                    f"    SAN ({len(c.san_entries)}):     "
                    + ", ".join(c.san_entries[:5])
                    + (" …" if len(c.san_entries) > 5 else "")
                )

        # HSTS
        if result.hsts_header:
            self._c.print(f"\n  [bold]HSTS:[/] [green]{result.hsts_header}[/]")
        else:
            self._c.print(f"\n  [bold]HSTS:[/] [red]AUSENTE[/]")

        # Tabla de hallazgos con remediación
        if result.findings:
            self._c.print()
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
            self._c.print(tbl)

            # Mostrar remediaciones sólo para hallazgos CRITICAL y HIGH
            criticos = [f for f in result.findings if f.severity in ("CRITICAL", "HIGH") and f.remediation]
            if criticos:
                self._c.print(f"\n  [bold cyan]Pasos de remediación prioritarios:[/]")
                for f in criticos:
                    self._c.print(
                        Panel(
                            f.remediation,
                            title=f"[{SEVERITY_COLOR[f.severity]}]{f.severity}[/] — {f.name}",
                            border_style="cyan",
                            expand=False,
                        )
                    )
        else:
            self._c.print("\n  [bold green]✔ Sin hallazgos de seguridad[/]")

    def print_summary(self, results: list[AuditResult]) -> None:
        """Tabla resumen de todos los hosts auditados."""
        self._c.print("\n")
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
        self._c.print(tbl)

    # ---------------------------------------------------------------- JSON

    def to_json(self, results: list[AuditResult]) -> str:
        """Serializa los resultados en JSON incluyendo nota y remediaciones."""
        def _cert_dict(c: Optional[CertInfo]) -> Optional[dict]:
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

    # ---------------------------------------------------------------- HTML

    def to_html(self, results: list[AuditResult]) -> str:
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

    # ---------------------------------------------------------------- Markdown

    def to_markdown(self, results: list[AuditResult]) -> str:
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

        # Tabla resumen
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

        # Detalle por host
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

            # Info técnica
            lines.append("| Campo | Valor |")
            lines.append("|-------|-------|")
            lines.append(f"| Protocolo negociado | `{r.negotiated_protocol}` |")
            lines.append(f"| Cipher negociado | `{r.negotiated_cipher}` |")
            prots = ", ".join(r.supported_protocols) if r.supported_protocols else "—"
            lines.append(f"| Protocolos legacy aceptados | {prots} |")
            hsts_val = f"`{r.hsts_header}`" if r.hsts_header else "**AUSENTE**"
            lines.append(f"| HSTS | {hsts_val} |")
            lines.append("")

            # Certificado
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

            # Hallazgos
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

                # Lista de pasos priorizados
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

    # ---------------------------------------------------------------- CSV

    def to_csv(self, results: list[AuditResult], base_path: str) -> tuple[str, str]:
        """
        Genera dos ficheros CSV:
          - <base_path>          : resumen por host (una fila por host)
          - <base_path>.findings : detalle de hallazgos (una fila por hallazgo)

        Devuelve los dos paths como tupla.
        """
        import io

        # Fichero 1: resumen por host
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

        # Fichero 2: hallazgos detallados
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

    # Argumentos de informe unificado VSL (--client, --engagement, --auditor,
    # --report-scope, --report-html, --report-pdf)
    from vampsec_report import add_report_args
    add_report_args(p)

    return p.parse_args()


# =============================================================================
# CONVERSOR A FORMATO DE INFORME UNIFICADO VSL
# =============================================================================

def _findings_vsl(results: list) -> list:
    """
    Convierte los hallazgos TLS/SSL al formato Finding unificado de VampSecure Labs.

    Incluye todos los hallazgos de severidad MEDIUM, HIGH o CRITICAL.
    Los hallazgos INFO se omiten para mantener el informe de cliente enfocado.

    Parámetros
    ----------
    results : list[AuditResult]  — Lista de resultados de la auditoría SSL

    Retorna
    -------
    List[Finding]  — Lista de hallazgos en formato VSL con prefijo SSL-NNN
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

            # Evidencia: categoría + detalle técnico + nota SSL afectada
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


def main() -> None:
    """Punto de entrada principal."""
    console.print(BANNER, style="bold magenta")

    args     = _parse_args()
    targets  = _resolve_targets(args)
    auditor  = SSLAuditor(timeout=args.timeout)
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

    results.sort(key=lambda r: (r.host, r.port))

    for r in results:
        reporter.print_result(r)

    reporter.print_summary(results)

    # Exportar ficheros solicitados
    if args.json:
        Path(args.json).write_text(reporter.to_json(results), encoding="utf-8")
        console.print(f"\n[green]✔[/] JSON guardado en [bold]{args.json}[/]")

    if args.html:
        Path(args.html).write_text(reporter.to_html(results), encoding="utf-8")
        console.print(f"[green]✔[/] HTML guardado en [bold]{args.html}[/]")

    if args.markdown:
        Path(args.markdown).write_text(reporter.to_markdown(results), encoding="utf-8")
        console.print(f"[green]✔[/] Markdown guardado en [bold]{args.markdown}[/]")

    if args.csv:
        p_hosts, p_findings = reporter.to_csv(results, args.csv)
        console.print(f"[green]✔[/] CSV resumen guardado en [bold]{p_hosts}[/]")
        console.print(f"[green]✔[/] CSV hallazgos guardado en [bold]{p_findings}[/]")

    # ── Informe unificado VSL (cliente) ───────────────────────────────────────
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

    # Exit code según severidad máxima global
    max_sev = "INFO"
    for r in results:
        if SEVERITY_ORDER.get(r.max_severity, 99) < SEVERITY_ORDER.get(max_sev, 99):
            max_sev = r.max_severity

    sys.exit(2 if max_sev == "CRITICAL" else 1 if max_sev == "HIGH" else 0)


if __name__ == "__main__":
    main()
