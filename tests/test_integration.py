# © VampSecure Studios — VampSecure Labs Security Research Division
"""
Tests de integración para vamp-ssl-audit.
Usa un servidor mock TLS (ssl.wrap_socket) levantado en localhost para
simular escenarios reales sin depender de servicios externos.

Si el entorno tiene Docker disponible se puede descomentar el test con
nginx + certificado auto-firmado (marcado con pytest.mark.docker).
"""

import ssl
import socket
import threading
import tempfile
import os
import sys
import subprocess
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vamp_ssl_audit import AuditResult, CertInfo, Finding, compute_grade, _apply_cap


# ---------------------------------------------------------------------------
# Helpers: servidor TLS mínimo en localhost para tests de integración
# ---------------------------------------------------------------------------

def _generar_cert_autofirmado(tmpdir: str):
    """Genera par clave/cert auto-firmado para el servidor mock (requiere openssl CLI)."""
    keyfile = os.path.join(tmpdir, "server.key")
    certfile = os.path.join(tmpdir, "server.crt")
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", keyfile,
        "-out", certfile,
        "-days", "1",
        "-nodes",
        "-subj", "/CN=localhost",
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        return keyfile, certfile
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None, None


# ---------------------------------------------------------------------------
# Test 1: _apply_cap — comportamiento end-to-end con secuencia de caps
# ---------------------------------------------------------------------------

class TestApplyCapIntegracion:
    """Secuencias reales de caps aplicadas en cadena."""

    def test_cadena_completa_llega_a_f(self):
        # Simula lo que haría compute_grade al acumular caps
        grado = "A+"
        caps = ["B", "C", "F", "A-"]
        for cap in caps:
            grado = _apply_cap(grado, cap)
        # La "F" debe ganar aunque venga después de ella caps menos restrictivos
        assert grado == "F"

    def test_cadena_sin_f_llega_a_c(self):
        grado = "A+"
        caps = ["B", "A-", "C", "B"]
        for cap in caps:
            grado = _apply_cap(grado, cap)
        assert grado == "C"

    def test_cap_a_mas_nunca_mejora(self):
        # "A+" como cap no puede mejorar un grado ya restrictivo
        grado = "B"
        grado = _apply_cap(grado, "A+")
        assert grado == "B"


# ---------------------------------------------------------------------------
# Test 2: compute_grade — resultado completo con múltiples findings
# ---------------------------------------------------------------------------

class TestComputeGradeIntegracion:
    """Prueba compute_grade con AuditResult poblados como en producción."""

    def _make_result(self, protocol="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384",
                     findings=None, error=None):
        """Fábrica de AuditResult para tests de integración."""
        cert = CertInfo()
        cert.subject = "CN=example.com"
        cert.issuer = "CN=Test CA"
        cert.not_before = datetime(2025, 1, 1, tzinfo=timezone.utc)
        cert.not_after = datetime(2026, 1, 1, tzinfo=timezone.utc)
        cert.san = ["example.com"]
        cert.sig_alg = "sha256WithRSAEncryption"
        cert.key_bits = 2048
        cert.key_type = "RSA"
        cert.ocsp_urls = []
        cert.crl_urls = []
        cert.ct_present = True

        r = AuditResult(
            host="example.com",
            port=443,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        r.negotiated_protocol = protocol
        r.negotiated_cipher = cipher
        r.supported_protocols = [protocol]
        r.cert = cert
        r.hsts_header = "max-age=63072000; includeSubDomains; preload"
        r.x_frame_options = "DENY"
        r.x_content_type = "nosniff"
        r.findings = findings or []
        r.grade = "A+"
        r.error = error
        r.strict_tls13 = False
        r.mtls_required = False
        return r

    def test_tls13_sin_hallazgos_es_a_mas(self):
        r = self._make_result()
        assert compute_grade(r) == "A+"

    def test_protocolo_sslv3_produce_al_menos_c(self):
        f = Finding(
            severity="CRITICAL",
            category="PROTOCOL",
            name="SSLv3 habilitado",
            detail="Servidor acepta SSLv3",
            remediation="Deshabilitar SSLv3",
            grade_cap="C",
        )
        r = self._make_result(protocol="SSLv3", findings=[f])
        grado = compute_grade(r)
        from vamp_ssl_audit import GRADE_ORDER_LIST
        idx = GRADE_ORDER_LIST.index(grado)
        assert idx >= GRADE_ORDER_LIST.index("C")

    def test_cert_caducado_produce_f(self):
        f = Finding(
            severity="CRITICAL",
            category="CERT",
            name="Certificado caducado",
            detail="Expirado el 2023-01-01",
            remediation="Renovar",
            grade_cap="F",
        )
        r = self._make_result(findings=[f])
        assert compute_grade(r) == "F"

    def test_error_de_conexion_produce_f(self):
        r = self._make_result(error="Connection refused")
        assert compute_grade(r) == "F"

    def test_multiples_caps_acumulan_correctamente(self):
        findings = [
            Finding(
                severity="MEDIUM", category="CIPHER",
                name="3DES", detail="Cifrado débil",
                remediation="Eliminar 3DES", grade_cap="B",
            ),
            Finding(
                severity="HIGH", category="PROTOCOL",
                name="TLS 1.0", detail="Protocolo obsoleto",
                remediation="Desactivar TLS 1.0", grade_cap="B",
            ),
            Finding(
                severity="MEDIUM", category="CERT",
                name="SHA-1 signature", detail="Firma débil",
                remediation="Reemplazar cert", grade_cap="C",
            ),
        ]
        r = self._make_result(findings=findings)
        grado = compute_grade(r)
        from vamp_ssl_audit import GRADE_ORDER_LIST
        # Debe ser al menos "C" (el más restrictivo de los caps aplicados)
        assert GRADE_ORDER_LIST.index(grado) >= GRADE_ORDER_LIST.index("C")
