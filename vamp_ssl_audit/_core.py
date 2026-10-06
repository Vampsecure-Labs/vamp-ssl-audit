# © VampSecure Studios — VampSecure Labs Security Research Division
"""
_core.py — Lógica pura de auditoría TLS/SSL de vamp-ssl-audit
"""

from __future__ import annotations

import json
import socket
import ssl
import subprocess
import urllib.error
import urllib.request
import warnings
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.hashes import MD5, SHA1
from cryptography.x509.oid import ExtensionOID, NameOID

try:
    import dns.exception
    import dns.resolver
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False

from ._models import (
    VERSION,
    TOOL_NAME,
    PROTOCOL_RISK,
    PROTOCOL_GRADE_CAP,
    WEAK_CIPHER_PATTERNS,
    CIPHER_GRADE_CAP,
    SIG_ALG_RISK,
    GRADE_ORDER_LIST,
    AuditResult,
    Finding,
    CertInfo,
    _REMED_TLS_LEGACY,
    _REMED_NULL_CIPHER,
    _REMED_EXPORT_CIPHER,
    _REMED_ANON_CIPHER,
    _REMED_RC4,
    _REMED_DES,
    _REMED_3DES,
    _REMED_CERT_EXPIRED,
    _REMED_CERT_EXPIRING,
    _REMED_SELF_SIGNED,
    _REMED_RSA_SMALL,
    _REMED_RSA_WEAK,
    _REMED_SHA1,
    _REMED_MD5,
    _REMED_HSTS_ABSENT,
    _REMED_HSTS_SHORT,
    _REMED_HSTS_NO_SUBS,
    _REMED_XFO,
    _REMED_XCTO,
    _REMED_HOSTNAME,
    _REMED_DSA,
    _REMED_OCSP_NO_URL,
    _REMED_OCSP_NO_STAPLING,
    _REMED_CT_NO_LOG,
    _REMED_NO_SCT,
    _REMED_SC081V3,
    _REMED_LOG4J_TLS,
    _REMED_SESSION_TICKETS,
)

# ---------------------------------------------------------------------------
# Sistema de calificación SSLabs-style
# ---------------------------------------------------------------------------


def _apply_cap(current: str, cap: str) -> str:
    """
    Aplica un cap de nota: devuelve la nota más restrictiva entre las dos.
    Una nota más a la derecha en GRADE_ORDER_LIST es más restrictiva.
    """
    ci = GRADE_ORDER_LIST.index(current) if current in GRADE_ORDER_LIST else 0
    ca = GRADE_ORDER_LIST.index(cap)     if cap     in GRADE_ORDER_LIST else 0
    return GRADE_ORDER_LIST[max(ci, ca)]


def compute_grade(result: AuditResult) -> str:
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

    for f in result.findings:
        if f.grade_cap:
            grade = _apply_cap(grade, f.grade_cap)

    if result.strict_tls13:
        proto_debajo_tls13 = (
            set(result.supported_protocols)
            | ({"default:" + result.negotiated_protocol}
               if result.negotiated_protocol not in ("TLSv1.3", "")
               else set())
        )
        if proto_debajo_tls13:
            grade = _apply_cap(grade, "B")

    if grade in ("A+", "A", "A-"):
        if grade == "A+" and result.negotiated_protocol != "TLSv1.3":
            grade = _apply_cap(grade, "A")

        if grade == "A+" and result.hsts_header is None:
            grade = _apply_cap(grade, "A")

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
            if max_age >= 15_552_000 and has_subs and not has_preload:
                grade = _apply_cap(grade, "A")

    return grade


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

    def __init__(
        self,
        timeout: int = 10,
        warn_days: int = 90,
        strict_tls13: bool = False,
        mtls_cert: str | None = None,
        mtls_key: str | None = None,
    ) -> None:
        self._timeout      = timeout
        self._warn_days    = warn_days
        self._strict_tls13 = strict_tls13
        self._mtls_cert    = mtls_cert
        self._mtls_key     = mtls_key

    def audit(self, host: str, port: int) -> AuditResult:
        """Punto de entrada para auditar un host:port."""
        result = AuditResult(
            host=host,
            port=port,
            timestamp=datetime.now(timezone.utc).isoformat(),
            strict_tls13=self._strict_tls13,
        )
        try:
            self._phase_default_handshake(result)
            self._phase_legacy_protocols(result)
            self._phase_ocsp_stapling(result)
            self._phase_ct_logs(result)
            self._phase_sc081v3(result)
            self._phase_log4j_tls_bypass(result)
            self._phase_session_resumption(result)
            self._phase_mtls(result)
            self._phase_http_headers(result)
            self._audit_dane(result.host, result.port, result.findings)
            self._check_ct_logs(result.host, result.findings)
        except Exception as exc:
            result.error = str(exc)
        finally:
            result.findings.sort(key=lambda f: f.order)
            result.grade = compute_grade(result)
        return result

    def _phase_default_handshake(self, result: AuditResult) -> None:
        """Realiza el handshake TLS estándar y extrae protocolo, cipher y certificado."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode    = ssl.CERT_REQUIRED

        der_cert:    bytes | None = None
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

        self._classify_cipher(cipher_name, result)

        if der_cert:
            cert_info = self._parse_cert(der_cert, result.host, hostname_ok, result)
            result.cert = cert_info

    def _phase_legacy_protocols(self, result: AuditResult) -> None:
        """
        Intenta conexiones forzadas con versiones antiguas de TLS.
        Si el servidor acepta SSLv3/TLS1.0/TLS1.1, genera un hallazgo.
        En modo --strict-tls13 también comprueba TLS 1.2.
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

        if self._strict_tls13:
            try:
                legacy_map.append(("TLS 1.2", ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2))
            except AttributeError:
                pass

        for label, min_v, max_v in legacy_map:
            accepted = self._test_protocol_version(result.host, result.port, min_v, max_v)
            if accepted:
                result.supported_protocols.append(label)
                if label == "TLS 1.2" and self._strict_tls13:
                    result.findings.append(Finding(
                        severity="MEDIUM",
                        category="Protocolo",
                        name="Soporta TLS 1.2 (modo --strict-tls13 activo)",
                        detail=(
                            "El servidor acepta TLS 1.2 además de TLS 1.3. "
                            "En entornos que exigen exclusividad TLS 1.3, esto reduce la nota máxima a B."
                        ),
                        remediation=(
                            "Configurar el servidor para aceptar únicamente TLS 1.3:\n"
                            "  nginx:   ssl_protocols TLSv1.3;\n"
                            "  apache:  SSLProtocol -all +TLSv1.3\n"
                            "  haproxy: bind *:443 ssl-min-ver TLSv1.3"
                        ),
                        grade_cap="B",
                    ))
                else:
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

        try:
            info.not_before = cert.not_valid_before_utc
            info.not_after  = cert.not_valid_after_utc
        except AttributeError:
            from datetime import timezone as _tz
            info.not_before = cert.not_valid_before.replace(tzinfo=_tz.utc)
            info.not_after  = cert.not_valid_after.replace(tzinfo=_tz.utc)
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
        elif self._warn_days > 30 and info.days_remaining < self._warn_days:
            result.findings.append(Finding(
                severity="MEDIUM",
                category="Certificado",
                name=f"Certificado caduca en < {self._warn_days} días",
                detail=f"Expira en {info.days_remaining} días ({info.not_after.date()})",
                remediation=_REMED_CERT_EXPIRING,
            ))

        info.serial = f"{cert.serial_number:X}"

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

        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for entry in san_ext.value:
                if hasattr(entry, "value"):
                    info.san_entries.append(entry.value)
        except x509.extensions.ExtensionNotFound:
            pass

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

    def _phase_mtls(self, result: AuditResult) -> None:
        """
        Comprueba el comportamiento del servidor respecto a mTLS (autenticación mutua TLS).
        """
        if result.error:
            return

        host = result.host
        port = result.port

        ctx_sin_cert = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx_sin_cert.check_hostname = False
        ctx_sin_cert.verify_mode    = ssl.CERT_NONE

        sin_cert_ok    = False
        error_ssl_sin  = ""

        try:
            with socket.create_connection((host, port), timeout=self._timeout) as sock:
                with ctx_sin_cert.wrap_socket(sock, server_hostname=host):
                    sin_cert_ok = True
        except ssl.SSLError as exc:
            error_ssl_sin = str(exc)
            msg_lower = error_ssl_sin.lower()
            if (
                "certificate_required" in msg_lower
                or "alert certificate required" in msg_lower
                or "certificate required" in msg_lower
                or "1040" in error_ssl_sin
            ):
                result.mtls_required = True
        except OSError:
            return

        if sin_cert_ok:
            result.findings.append(Finding(
                severity="INFO",
                category="mTLS",
                name="SSL-MTLS-001: mTLS_NOT_ENFORCED — servidor acepta conexión sin cert cliente",
                detail=(
                    "El servidor TLS no requiere autenticación mutua (mTLS): acepta conexiones "
                    "sin presentar un certificado cliente. Para servicios de alta criticidad "
                    "(APIs internas, microservicios, admin endpoints) considerar requerir "
                    "certificado cliente mediante ClientAuth=require."
                ),
            ))
        elif result.mtls_required:
            result.findings.append(Finding(
                severity="INFO",
                category="mTLS",
                name="SSL-MTLS-002: mTLS REQUERIDO — el servidor exige certificado cliente",
                detail=(
                    "El servidor requiere autenticación mutua TLS (mTLS): rechazó el handshake "
                    f"con CERTIFICATE_REQUIRED ({error_ssl_sin[:80]}). "
                    "Use --mtls-cert y --mtls-key para conectar con un certificado cliente válido."
                ),
            ))

        if not self._mtls_cert or not self._mtls_key:
            return

        try:
            ctx_con_cert = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_con_cert.check_hostname = False
            ctx_con_cert.verify_mode    = ssl.CERT_NONE
            ctx_con_cert.load_cert_chain(certfile=self._mtls_cert, keyfile=self._mtls_key)

            with socket.create_connection((host, port), timeout=self._timeout) as sock:
                with ctx_con_cert.wrap_socket(sock, server_hostname=host):
                    result.findings.append(Finding(
                        severity="INFO",
                        category="mTLS",
                        name="SSL-MTLS-003: mTLS_CLIENT_CERT_ACCEPTED — certificado cliente aceptado",
                        detail=(
                            f"El servidor aceptó el certificado cliente proporcionado "
                            f"(cert: {self._mtls_cert}). La autenticación mutua TLS (mTLS) "
                            "completó el handshake correctamente."
                        ),
                    ))
        except ssl.SSLError as exc:
            error_con = str(exc)
            msg_lower = error_con.lower()
            if any(s in msg_lower for s in ("unknown ca", "bad certificate", "certificate unknown", "handshake failure")):
                result.findings.append(Finding(
                    severity="INFO",
                    category="mTLS",
                    name="SSL-MTLS-004: mTLS_CLIENT_CERT_REJECTED — certificado cliente rechazado",
                    detail=(
                        "El servidor rechazó el certificado cliente proporcionado. "
                        f"Error TLS: {error_con[:120]}. "
                        "El certificado debe estar firmado por la CA de confianza del servidor "
                        "(consultar la política de ClientAuth configurada)."
                    ),
                ))
            else:
                result.findings.append(Finding(
                    severity="INFO",
                    category="mTLS",
                    name="SSL-MTLS-004: mTLS error al presentar certificado cliente",
                    detail=f"Error al intentar mTLS con certificado cliente: {error_con[:120]}",
                ))
        except (FileNotFoundError, ssl.SSLError) as exc:
            result.findings.append(Finding(
                severity="INFO",
                category="mTLS",
                name="SSL-MTLS-004: Error al cargar certificado/clave cliente",
                detail=(
                    f"No se pudo cargar el certificado ({self._mtls_cert}) o la clave "
                    f"({self._mtls_key}): {str(exc)[:100]}. "
                    "Verificar que los ficheros existen, tienen el formato PEM correcto "
                    "y que la clave corresponde al certificado."
                ),
            ))

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
                headers                = resp.headers
                result.hsts_header     = headers.get("Strict-Transport-Security")
                result.x_frame_options = headers.get("X-Frame-Options")
                result.x_content_type  = headers.get("X-Content-Type-Options")
        except (urllib.error.URLError, OSError):
            return
        except Exception:
            return

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

            if max_age < 10_886_400:
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

        if result.x_frame_options is None:
            result.findings.append(Finding(
                severity="LOW",
                category="Cabeceras HTTP",
                name="X-Frame-Options ausente",
                detail="Puede facilitar ataques de clickjacking si la app es embebible en iframe",
                remediation=_REMED_XFO,
            ))

        if result.x_content_type is None:
            result.findings.append(Finding(
                severity="LOW",
                category="Cabeceras HTTP",
                name="X-Content-Type-Options ausente",
                detail="Sin nosniff — posible MIME-type sniffing por el navegador",
                remediation=_REMED_XCTO,
            ))

    def _classify_cipher(self, cipher_name: str, result: AuditResult) -> None:
        """Busca patrones de debilidad en el nombre del cipher negociado."""
        if not cipher_name:
            return

        remed_map = {
            "NULL":  _REMED_NULL_CIPHER,
            "EXPORT": _REMED_EXPORT_CIPHER,
            "ADH":   _REMED_ANON_CIPHER,
            "AECDH": _REMED_ANON_CIPHER,
            "RC4":   _REMED_RC4,
            "DES ":  _REMED_DES,
            "_DES_": _REMED_3DES,
            "3DES":  _REMED_3DES,
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
                return

    def _phase_sc081v3(self, result: AuditResult) -> None:
        """
        Verifica conformidad con CA/B Forum Ballot SC081v3 (vigente desde marzo 2026):
        validez máxima de certificados TLS públicos limitada a 200 días.
        """
        if not result.cert or result.error:
            return

        cert_info = result.cert

        if cert_info.is_self_signed:
            return

        if not cert_info.not_before or not cert_info.not_after:
            return

        total_dias = (cert_info.not_after - cert_info.not_before).days

        if total_dias > 398:
            result.findings.append(Finding(
                severity="CRITICAL",
                category="Certificado SC081v3",
                name="SSL-SC081-001: Certificado muy largo (> 398 días, no conforme SC081v3)",
                detail=(
                    f"Validez total: {total_dias} días "
                    f"(emisión: {cert_info.not_before.date()}, expiración: {cert_info.not_after.date()}). "
                    "Excede el límite anterior del CA/B Forum (398 días) y el nuevo límite SC081v3 (200 días, "
                    "vigente desde marzo 2026). Certificado probablemente emitido antes de SC081v3 "
                    "o por una CA no conforme."
                ),
                remediation=_REMED_SC081V3,
                grade_cap="B",
            ))
        elif total_dias > 200:
            result.findings.append(Finding(
                severity="HIGH",
                category="Certificado SC081v3",
                name="SSL-SC081-001: Certificado excede 200 días (CA/B Forum SC081v3)",
                detail=(
                    f"Validez total: {total_dias} días "
                    f"(emisión: {cert_info.not_before.date()}, expiración: {cert_info.not_after.date()}). "
                    "CA/B Forum Ballot SC081v3 (vigente desde marzo 2026) limita los certificados TLS "
                    "públicos a un máximo de 200 días. "
                    "Reducción gradual: 90 días en 2027, 47 días en 2029."
                ),
                remediation=_REMED_SC081V3,
            ))

        existing_expiry = any(
            "expira" in f.name.lower() and f.category == "Certificado"
            for f in result.findings
        )
        if not existing_expiry and 0 <= cert_info.days_remaining < 30:
            result.findings.append(Finding(
                severity="MEDIUM",
                category="Certificado SC081v3",
                name="SSL-SC081-002: Certificado expira en < 30 días (SC081v3)",
                detail=(
                    f"El certificado expira en {cert_info.days_remaining} días "
                    f"({cert_info.not_after.date()}). "
                    "Con los ciclos cortos de SC081v3, la renovación frecuente y automatizada es obligatoria. "
                    "Se recomienda automatizar con ACME/certbot."
                ),
                remediation=_REMED_CERT_EXPIRING,
            ))

    def _phase_log4j_tls_bypass(self, result: AuditResult) -> None:
        """
        Detección indirecta de CVE-2026-34477 — Log4j TLS bypass via JMSAppender.
        """
        if result.error:
            return

        host = result.host
        port = result.port

        java_stack_detectado = False
        server_identificado  = ""

        try:
            url = f"https://{host}:{port}/"
            req = urllib.request.Request(url, method="HEAD")
            req.add_header("User-Agent", f"VampSecureLabs-SSLAudit/{VERSION}")

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

            with urllib.request.urlopen(req, timeout=self._timeout, context=ctx) as resp:
                server_h    = resp.headers.get("Server",       "") or ""
                powered_by  = resp.headers.get("X-Powered-By", "") or ""
                combined    = f"{server_h} {powered_by}".lower()

                indicadores_java = [
                    "apache-coyote", "coyote", "tomcat", "jboss",
                    "wildfly", "jetty", "undertow", "weblogic", "websphere",
                ]
                for indicador in indicadores_java:
                    if indicador in combined:
                        java_stack_detectado = True
                        server_identificado  = server_h or powered_by
                        break
        except Exception:
            return

        if not java_stack_detectado:
            return

        tls_sin_sni = False
        try:
            ctx_nosni = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_nosni.check_hostname = False
            ctx_nosni.verify_mode    = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=self._timeout) as sock:
                with ctx_nosni.wrap_socket(sock):
                    tls_sin_sni = True
        except Exception:
            tls_sin_sni = False

        if java_stack_detectado and tls_sin_sni:
            result.findings.append(Finding(
                severity="HIGH",
                category="CVE / Log4j",
                name="SSL-LOG4J-001: Posible CVE-2026-34477 — Log4j TLS bypass via JMSAppender",
                detail=(
                    f"Servidor identificado como stack Java ({server_identificado!r}) + TLS acepta "
                    "conexión sin SNI. CVE-2026-34477 afecta a aplicaciones con Log4j ≤ 2.23.1 "
                    "y JMSAppender activo: el canal JMS puede establecerse sin verificar el certificado "
                    "del servidor (TLS bypass). Verificar versión de Log4j e inspeccionar la "
                    "configuración de JMSAppender y del TLS del broker de mensajería."
                ),
                remediation=_REMED_LOG4J_TLS,
            ))

    def _phase_session_resumption(self, result: AuditResult) -> None:
        """
        Detecta si el servidor usa TLS session tickets y verifica si se rotan
        entre conexiones sucesivas. Tickets fijos debilitan la forward secrecy.
        """
        if result.error:
            return

        host   = result.host
        port   = result.port
        tickets: list[bytes | None] = []

        for _ in range(2):
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE

                with socket.create_connection((host, port), timeout=self._timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        sesion = ssock.session
                        if sesion is not None and sesion.has_ticket:
                            tickets.append(sesion.ticket)
                        else:
                            tickets.append(None)
            except Exception:
                return

        if len(tickets) < 2:
            return

        ticket_a, ticket_b = tickets[0], tickets[1]

        ticket_fijo = (
            ticket_a is not None
            and ticket_b is not None
            and len(ticket_a) > 0
            and ticket_a == ticket_b
        )

        if ticket_fijo:
            result.findings.append(Finding(
                severity="MEDIUM",
                category="TLS / Session",
                name="SSL-RESUME-001: TLS session tickets sin rotación detectados",
                detail=(
                    "El servidor emite TLS session tickets idénticos en conexiones sucesivas. "
                    "Los session tickets sin rotación frecuente debilitan la forward secrecy: "
                    "si la clave del ticket se compromete, un atacante puede descifrar sesiones "
                    "TLS pasadas capturadas durante ese período."
                ),
                remediation=_REMED_SESSION_TICKETS,
            ))
        elif ticket_a is not None and len(ticket_a) > 0:
            result.findings.append(Finding(
                severity="INFO",
                category="TLS / Session",
                name="SSL-RESUME-001: TLS session tickets activos (rotación detectada)",
                detail=(
                    "El servidor emite TLS session tickets con rotación activa entre sesiones. "
                    "La forward secrecy se mantiene adecuadamente si la rotación es frecuente "
                    "(recomendado: cada hora como máximo)."
                ),
                remediation="",
            ))

    def _phase_ocsp_stapling(self, result: AuditResult) -> None:
        """
        Comprueba si el certificado tiene URL OCSP y si el servidor envía
        OCSP Stapling (respuesta OCSP embebida en el handshake TLS).
        """
        if not result.cert or result.error:
            return

        try:
            pem = ssl.get_server_certificate(
                (result.host, result.port),
                timeout=self._timeout,
            )
            cert_obj = x509.load_pem_x509_certificate(pem.encode())
        except Exception:
            return

        ocsp_url: str | None = None
        try:
            aia = cert_obj.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            )
            for access in aia.value:
                if access.access_method.dotted_string == "1.3.6.1.5.5.7.48.1":
                    ocsp_url = access.access_location.value
                    break
        except x509.ExtensionNotFound:
            pass
        except Exception:
            pass

        if not ocsp_url:
            result.findings.append(Finding(
                severity="MEDIUM",
                category="Certificado",
                name="Sin URL OCSP en el certificado",
                detail=(
                    "El certificado no contiene una URL de responder OCSP en la extensión AIA. "
                    "Sin ella, los clientes no pueden verificar el estado de revocación en tiempo real."
                ),
                remediation=_REMED_OCSP_NO_URL,
            ))
            return

        stapling_found = False
        try:
            proc = subprocess.run(
                [
                    "openssl", "s_client",
                    "-connect", f"{result.host}:{result.port}",
                    "-servername", result.host,
                    "-status",
                    "-brief",
                ],
                input=b"Q\n",
                capture_output=True,
                timeout=self._timeout + 5,
            )
            salida = proc.stdout.decode(errors="replace") + proc.stderr.decode(errors="replace")
            stapling_found = (
                "OCSP Response Status: successful" in salida
                or "OCSP response:" in salida.lower()
                and "no response sent" not in salida.lower()
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return
        except Exception:
            return

        if not stapling_found:
            result.findings.append(Finding(
                severity="LOW",
                category="Certificado",
                name="OCSP Stapling no detectado",
                detail=(
                    f"El certificado tiene URL OCSP ({ocsp_url}) pero el servidor "
                    "no envía una respuesta OCSP stapled en el handshake TLS. "
                    "Esto obliga al cliente a contactar directamente al responder OCSP, "
                    "ralentizando la conexión y filtrando qué sitios visita el usuario."
                ),
                remediation=_REMED_OCSP_NO_STAPLING,
            ))

    def _phase_ct_logs(self, result: AuditResult) -> None:
        """
        Verifica que el certificado aparece en Certificate Transparency logs (crt.sh)
        y que contiene SCTs (Signed Certificate Timestamps) embebidos.
        """
        if not result.cert or result.error:
            return

        hostname = result.host
        serial   = result.cert.serial

        try:
            pem = ssl.get_server_certificate(
                (result.host, result.port),
                timeout=self._timeout,
            )
            cert_obj = x509.load_pem_x509_certificate(pem.encode())
            sct_oid  = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")
            try:
                cert_obj.extensions.get_extension_for_oid(sct_oid)
                has_sct_embedded = True
            except x509.ExtensionNotFound:
                has_sct_embedded = False
        except Exception:
            has_sct_embedded = None

        if has_sct_embedded is False:
            result.findings.append(Finding(
                severity="LOW",
                category="Certificado",
                name="Sin SCTs embebidos en el certificado",
                detail=(
                    "El certificado no contiene Signed Certificate Timestamps (SCTs) embebidos. "
                    "Los SCTs son obligatorios para que navegadores como Chrome confíen en el certificado. "
                    "Pueden entregarse también vía extensión TLS o respuesta OCSP, "
                    "pero la forma embebida es la más robusta."
                ),
                remediation=_REMED_NO_SCT,
            ))

        try:
            url     = f"https://crt.sh/?q={hostname}&output=json"
            req_obj = urllib.request.Request(
                url,
                headers={"User-Agent": f"VampSecureLabs-SSLAudit/{VERSION}"},
            )
            with urllib.request.urlopen(req_obj, timeout=self._timeout) as resp:
                datos = json.loads(resp.read().decode("utf-8"))
        except Exception:
            return

        serial_norm = serial.upper().lstrip("0") if serial else ""

        found_in_ct = False
        for entrada in datos:
            entry_serial = str(entrada.get("serial_number", "")).upper().lstrip("0")
            if serial_norm and (
                serial_norm == entry_serial
                or serial_norm in entry_serial
                or entry_serial in serial_norm
            ):
                found_in_ct = True
                break

        if not found_in_ct and serial_norm:
            result.findings.append(Finding(
                severity="MEDIUM",
                category="Certificado",
                name="Certificado no encontrado en CT logs (crt.sh)",
                detail=(
                    f"El certificado con serial {result.cert.serial} para '{hostname}' "
                    "no fue encontrado en los Certificate Transparency logs consultados en crt.sh. "
                    "Posibles causas: cert emitido por CA privada, emisión muy reciente "
                    "(CT puede tardar horas en indexarlo) o CA no cumple con CT."
                ),
                remediation=_REMED_CT_NO_LOG,
            ))

    def _audit_dane(self, domain: str, port: int, findings: list) -> None:
        """
        Valida el registro DANE/TLSA del dominio (RFC 6698).
        """
        if not _DNS_AVAILABLE:
            return

        tlsa_name = f"_{port}._tcp.{domain}"
        try:
            answers = dns.resolver.resolve(tlsa_name, "TLSA")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            findings.append(Finding(
                severity="INFO",
                category="DANE/TLSA",
                name="DANE/TLSA no configurado",
                detail=(
                    f"No se encontró registro TLSA en {tlsa_name}. "
                    "Sin DANE no existe anclaje de certificado por DNS: la validación "
                    "del certificado depende exclusivamente de la jerarquía de CAs."
                ),
            ))
            return
        except dns.exception.DNSException:
            findings.append(Finding(
                severity="INFO",
                category="DANE/TLSA",
                name="DANE/TLSA no configurado",
                detail=(
                    f"No se pudo resolver el registro TLSA en {tlsa_name}. "
                    "Sin DANE no existe anclaje de certificado por DNS."
                ),
            ))
            return
        except Exception:
            return

        for rdata in answers:
            try:
                usage    = rdata.usage
                selector = rdata.selector
                mtype    = rdata.mtype
            except AttributeError:
                findings.append(Finding(
                    severity="MEDIUM",
                    category="DANE/TLSA",
                    name="Registro TLSA malformado",
                    detail=(
                        f"Registro TLSA encontrado en {tlsa_name} pero no se puede "
                        "parsear correctamente. Formato esperado: "
                        "usage selector matching-type certificate-data."
                    ),
                ))
                return

            if usage == 3 and selector == 1:
                findings.append(Finding(
                    severity="INFO",
                    category="DANE/TLSA",
                    name="DANE/TLSA configurado correctamente",
                    detail=(
                        f"Registro TLSA encontrado en {tlsa_name}: "
                        f"usage={usage} (DANE-EE), selector={selector} (SPKI), "
                        f"matching-type={mtype}. Configuración DANE óptima para "
                        "anclaje de clave pública sin dependencia de CA."
                    ),
                ))
            else:
                findings.append(Finding(
                    severity="INFO",
                    category="DANE/TLSA",
                    name="DANE/TLSA configurado",
                    detail=(
                        f"Registro TLSA encontrado en {tlsa_name}: "
                        f"usage={usage}, selector={selector}, matching-type={mtype}. "
                        "Anclaje de certificado DNS activo."
                    ),
                ))
            return

    def _check_ct_logs(self, domain: str, findings: list) -> None:
        """
        Consulta crt.sh para obtener el recuento de certificados emitidos
        para el dominio y el más reciente.
        """
        url = f"https://crt.sh/?q={domain}&output=json"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": f"{TOOL_NAME}/{VERSION}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                datos = json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception:
            findings.append(Finding(
                severity="INFO",
                category="CT Logs",
                name="CT check omitido (no disponible)",
                detail=(
                    f"No se pudo consultar crt.sh para el dominio {domain}. "
                    "La verificación de Certificate Transparency logs no está disponible."
                ),
            ))
            return

        total = len(datos) if isinstance(datos, list) else 0

        if total > 0:
            mas_reciente = ""
            try:
                fechas = [
                    str(e.get("not_before", ""))
                    for e in datos
                    if e.get("not_before")
                ]
                if fechas:
                    mas_reciente = max(fechas)
            except Exception:
                pass

            detalle = (
                f"Se encontraron {total} certificado(s) en CT logs para '{domain}'."
            )
            if mas_reciente:
                detalle += f" Más reciente emitido: {mas_reciente}."

            findings.append(Finding(
                severity="INFO",
                category="CT Logs",
                name=f"CT logs: {total} certificado(s) registrados",
                detail=detalle,
            ))
        else:
            findings.append(Finding(
                severity="INFO",
                category="CT Logs",
                name="CT check omitido (no disponible)",
                detail=(
                    f"crt.sh no devolvió certificados para '{domain}'. "
                    "Puede deberse a un dominio privado o a que crt.sh no tiene datos aún."
                ),
            ))


# ---------------------------------------------------------------------------
# Delta scan
# ---------------------------------------------------------------------------

def apply_delta_scan(
    results: "list[AuditResult]", delta_path: str
) -> "tuple[list[AuditResult], list[str]]":
    """
    Compara resultados actuales con un informe JSON previo (--delta FILE).
    Marca cada hallazgo como 'new' o 'recurring'.
    Clave única: host:port:category:name.
    Devuelve (results_marcados, resolved_keys).
    """
    try:
        baseline_data = json.loads(Path(delta_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"No se puede leer el delta baseline '{delta_path}': {exc}") from exc
    baseline_keys: set = set()
    for br in baseline_data.get("results", []):
        h, p = br.get("host", ""), br.get("port", 0)
        for bf in br.get("findings", []):
            baseline_keys.add(f"{h}:{p}:{bf.get('category','')}:{bf.get('name','')}")
    current_keys: set = set()
    for r in results:
        for f in r.findings:
            k = f"{r.host}:{r.port}:{f.category}:{f.name}"
            f.delta_state = "recurring" if k in baseline_keys else "new"
            current_keys.add(k)
    resolved = sorted(baseline_keys - current_keys)
    return results, resolved
