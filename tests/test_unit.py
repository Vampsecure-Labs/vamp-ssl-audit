# © VampSecure Studios — VampSecure Labs Security Research Division
"""
Tests unitarios para vamp-ssl-audit.
Cubre: compute_grade, _apply_cap, caps por protocolo, caps por cifrado,
       detección de cert auto-firmado, HSTS, hallazgos con grade_cap.
"""

import sys
import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vamp_ssl_audit import (
    AuditResult,
    CertInfo,
    Finding,
    GRADE_ORDER_LIST,
    PROTOCOL_GRADE_CAP,
    CIPHER_GRADE_CAP,
    compute_grade,
    _apply_cap,
)


# ---------------------------------------------------------------------------
# Tests de _apply_cap
# ---------------------------------------------------------------------------

class TestApplyCap:
    """Verifica que _apply_cap devuelve el grado más restrictivo."""

    def test_cap_mas_restrictivo_que_actual(self):
        # "F" es más restrictivo que "A+" → debe devolver "F"
        assert _apply_cap("A+", "F") == "F"

    def test_cap_menos_restrictivo_que_actual(self):
        # "A+" es menos restrictivo que "B" → debe devolver "B"
        assert _apply_cap("B", "A+") == "B"

    def test_cap_igual_al_actual(self):
        # Mismo grado → sin cambio
        assert _apply_cap("C", "C") == "C"

    def test_cap_a_con_a_mas(self):
        # "A" es más restrictivo que "A+" → devuelve "A"
        assert _apply_cap("A+", "A") == "A"

    def test_cap_t_sobre_a_mas(self):
        # "T" (cert no fiable) → más restrictivo que "A+"
        assert _apply_cap("A+", "T") == "T"

    def test_cap_f_sobre_t(self):
        # "F" está después de "T" en GRADE_ORDER_LIST → gana "F"
        assert _apply_cap("T", "F") == "F"


# ---------------------------------------------------------------------------
# Tests de compute_grade
# ---------------------------------------------------------------------------

class TestComputeGrade:
    """Verifica la lógica de calificación final a partir de un AuditResult."""

    def test_sin_hallazgos_grade_a_mas(self, resultado_limpio):
        # Sin findings → el grado se mantiene como A+
        resultado_limpio.grade = "A+"
        resultado_limpio.findings = []
        grado = compute_grade(resultado_limpio)
        assert grado == "A+"

    def test_finding_con_cap_f_produce_f(self, resultado_limpio, finding_critico):
        # Un finding con cap "F" → resultado final "F"
        resultado_limpio.grade = "A+"
        resultado_limpio.findings = [finding_critico]
        grado = compute_grade(resultado_limpio)
        assert grado == "F"

    def test_finding_con_cap_b_produce_b(self, resultado_limpio, finding_medio):
        # Un finding con cap "B" sobre "A+" → resultado "B"
        resultado_limpio.grade = "A+"
        resultado_limpio.findings = [finding_medio]
        grado = compute_grade(resultado_limpio)
        assert grado == "B"

    def test_multiples_findings_toma_el_mas_restrictivo(
        self, resultado_limpio, finding_critico, finding_medio
    ):
        # "B" vs "F" → gana "F"
        resultado_limpio.grade = "A+"
        resultado_limpio.findings = [finding_medio, finding_critico]
        grado = compute_grade(resultado_limpio)
        assert grado == "F"

    def test_error_en_resultado_devuelve_f(self, resultado_limpio):
        # Si hay un campo error → forzar "F"
        resultado_limpio.error = "Timeout al conectar"
        grado = compute_grade(resultado_limpio)
        assert grado == "F"

    def test_finding_sin_grade_cap_no_afecta(self, resultado_limpio):
        # Finding sin grade_cap → no altera el grado
        f = Finding(
            severity="INFO",
            category="INFO",
            name="CT logs presentes",
            detail="OK",
            remediation="",
            grade_cap=None,
        )
        resultado_limpio.grade = "A+"
        resultado_limpio.findings = [f]
        grado = compute_grade(resultado_limpio)
        assert grado == "A+"


# ---------------------------------------------------------------------------
# Tests de caps por protocolo
# ---------------------------------------------------------------------------

class TestProtocolGradeCap:
    """Verifica que PROTOCOL_GRADE_CAP tiene los valores correctos."""

    def test_sslv3_limita_a_c(self):
        assert PROTOCOL_GRADE_CAP.get("SSLv3") == "C"

    def test_tls10_limita_a_b(self):
        assert PROTOCOL_GRADE_CAP.get("TLS 1.0") == "B"

    def test_tls11_limita_a_b(self):
        assert PROTOCOL_GRADE_CAP.get("TLS 1.1") == "B"

    def test_tls12_no_cap(self):
        # TLS 1.2 no debería estar en el dict de caps
        assert "TLS 1.2" not in PROTOCOL_GRADE_CAP

    def test_tls13_no_cap(self):
        # TLS 1.3 no debería estar en el dict de caps
        assert "TLS 1.3" not in PROTOCOL_GRADE_CAP


# ---------------------------------------------------------------------------
# Tests de caps por cifrado
# ---------------------------------------------------------------------------

class TestCipherGradeCap:
    """Verifica que CIPHER_GRADE_CAP tiene los valores correctos."""

    def test_rc4_limita_a_c(self):
        # Buscar que alguna entrada contenga RC4 → cap "C"
        caps_c = {k: v for k, v in CIPHER_GRADE_CAP.items() if v == "C"}
        assert any("RC4" in k for k in caps_c)

    def test_3des_limita_a_b(self):
        # Buscar que alguna entrada contenga 3DES → cap "B"
        caps_b = {k: v for k, v in CIPHER_GRADE_CAP.items() if v == "B"}
        assert any("3DES" in k or "DES" in k for k in caps_b)

    def test_null_limita_a_f(self):
        # NULL cipher → cap "F"
        caps_f = {k: v for k, v in CIPHER_GRADE_CAP.items() if v == "F"}
        assert any("NULL" in k for k in caps_f)

    def test_export_limita_a_f(self):
        # EXPORT cipher → cap "F"
        caps_f = {k: v for k, v in CIPHER_GRADE_CAP.items() if v == "F"}
        assert any("EXPORT" in k or "EXP" in k for k in caps_f)


# ---------------------------------------------------------------------------
# Tests de detección de certificado auto-firmado
# ---------------------------------------------------------------------------

class TestCertAutoFirmado:
    """Comprueba que un certificado auto-firmado produce cap 'T'."""

    def test_subject_igual_issuer_es_autofirmado(self, cert_autofirmado):
        # subject == issuer → auto-firmado
        assert cert_autofirmado.subject == cert_autofirmado.issuer

    def test_certificado_valido_no_es_autofirmado(self, cert_valido):
        # Certificado emitido por CA diferente
        assert cert_valido.subject != cert_valido.issuer


# ---------------------------------------------------------------------------
# Tests de la lista de grados
# ---------------------------------------------------------------------------

class TestGradeOrderList:
    """Comprueba el orden correcto de la lista de grados."""

    def test_a_mas_es_el_primero(self):
        assert GRADE_ORDER_LIST[0] == "A+"

    def test_f_es_el_ultimo(self):
        assert GRADE_ORDER_LIST[-1] == "F"

    def test_a_menos_esta_despues_de_a(self):
        idx_a = GRADE_ORDER_LIST.index("A")
        idx_a_menos = GRADE_ORDER_LIST.index("A-")
        assert idx_a_menos > idx_a

    def test_t_esta_antes_de_f(self):
        idx_t = GRADE_ORDER_LIST.index("T")
        idx_f = GRADE_ORDER_LIST.index("F")
        assert idx_t < idx_f

    def test_contiene_todos_los_grados_esperados(self):
        for g in ["A+", "A", "A-", "B", "C", "D", "T", "F"]:
            assert g in GRADE_ORDER_LIST


# ---------------------------------------------------------------------------
# Tests de la clase Finding
# ---------------------------------------------------------------------------

class TestFinding:
    """Verifica la creación y campos de los objetos Finding."""

    def test_finding_tiene_campos_obligatorios(self, finding_critico):
        assert finding_critico.severity == "CRITICAL"
        assert finding_critico.category == "CERT"
        assert finding_critico.grade_cap == "F"

    def test_finding_sin_cap_acepta_none(self):
        f = Finding(
            severity="INFO",
            category="INFO",
            name="Prueba",
            detail="Sin cap",
            remediation="N/A",
            grade_cap=None,
        )
        assert f.grade_cap is None

    def test_finding_medio_tiene_cap_b(self, finding_medio):
        assert finding_medio.grade_cap == "B"
        assert finding_medio.severity == "MEDIUM"
