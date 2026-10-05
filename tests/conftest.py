# © VampSecure Studios — VampSecure Labs Security Research Division
"""
Fixtures compartidos para los tests de vamp-ssl-audit.
Proporciona objetos de prueba reutilizables: AuditResult, CertInfo, Finding.
"""

import sys
import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

# Añadir el directorio padre al path para importar el módulo principal
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vamp_ssl_audit import (
    AuditResult,
    CertInfo,
    Finding,
    GRADE_ORDER_LIST,
    compute_grade,
    _apply_cap,
)


# ---------------------------------------------------------------------------
# Fixtures de objetos de datos
# ---------------------------------------------------------------------------

@pytest.fixture()
def cert_valido():
    """Certificado simulado con datos válidos (no auto-firmado, no caducado)."""
    cert = CertInfo()
    cert.subject = "CN=example.com"
    cert.issuer = "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US"
    cert.not_before = datetime(2025, 1, 1, tzinfo=timezone.utc)
    cert.not_after = datetime(2026, 1, 1, tzinfo=timezone.utc)
    cert.san = ["example.com", "www.example.com"]
    cert.serial = "123456789"
    cert.sig_alg = "sha256WithRSAEncryption"
    cert.key_bits = 2048
    cert.key_type = "RSA"
    cert.ocsp_urls = ["http://ocsp.letsencrypt.org"]
    cert.crl_urls = []
    cert.ct_present = True
    return cert


@pytest.fixture()
def cert_autofirmado():
    """Certificado auto-firmado: subject == issuer → debe producir cap 'T'."""
    cert = CertInfo()
    cert.subject = "CN=localhost"
    cert.issuer = "CN=localhost"
    cert.not_before = datetime(2025, 1, 1, tzinfo=timezone.utc)
    cert.not_after = datetime(2026, 1, 1, tzinfo=timezone.utc)
    cert.san = ["localhost"]
    cert.serial = "1"
    cert.sig_alg = "sha256WithRSAEncryption"
    cert.key_bits = 2048
    cert.key_type = "RSA"
    cert.ocsp_urls = []
    cert.crl_urls = []
    cert.ct_present = False
    return cert


@pytest.fixture()
def resultado_limpio(cert_valido):
    """AuditResult sin hallazgos: debería calificar como A+."""
    r = AuditResult(
        host="example.com",
        port=443,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    r.negotiated_protocol = "TLSv1.3"
    r.negotiated_cipher = "TLS_AES_256_GCM_SHA384"
    r.supported_protocols = ["TLSv1.3"]
    r.cert = cert_valido
    r.hsts_header = "max-age=63072000; includeSubDomains; preload"
    r.x_frame_options = "DENY"
    r.x_content_type = "nosniff"
    r.findings = []
    r.grade = "A+"
    r.error = None
    r.strict_tls13 = False
    r.mtls_required = False
    return r


@pytest.fixture()
def resultado_con_tls10(cert_valido):
    """AuditResult con TLS 1.0 habilitado → cap 'B'."""
    r = AuditResult(
        host="legacy.example.com",
        port=443,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    r.negotiated_protocol = "TLSv1.2"
    r.negotiated_cipher = "ECDHE-RSA-AES128-GCM-SHA256"
    r.supported_protocols = ["TLSv1.0", "TLSv1.2"]
    r.cert = cert_valido
    r.hsts_header = "max-age=63072000; includeSubDomains"
    r.x_frame_options = "SAMEORIGIN"
    r.x_content_type = "nosniff"
    r.findings = []
    r.grade = None
    r.error = None
    r.strict_tls13 = False
    r.mtls_required = False
    return r


@pytest.fixture()
def finding_critico():
    """Finding de severidad CRITICAL con cap de grado 'F'."""
    f = Finding(
        severity="CRITICAL",
        category="CERT",
        name="Certificado caducado",
        detail="El certificado expiró el 2024-01-01",
        remediation="Renovar el certificado inmediatamente",
        grade_cap="F",
    )
    return f


@pytest.fixture()
def finding_medio():
    """Finding de severidad MEDIUM con cap de grado 'B'."""
    f = Finding(
        severity="MEDIUM",
        category="PROTOCOL",
        name="TLS 1.0 habilitado",
        detail="El servidor acepta TLS 1.0, protocolo obsoleto",
        remediation="Deshabilitar TLS 1.0 y TLS 1.1",
        grade_cap="B",
    )
    return f
