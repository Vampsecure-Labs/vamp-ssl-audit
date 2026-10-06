# © VampSecure Studios — VampSecure Labs Security Research Division
"""
_models.py — Constantes, estructuras de datos y remediaciones de vamp-ssl-audit
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

VERSION   = "1.7.0"
TOOL_NAME = "vamp-ssl-audit"

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

_REMED_OCSP_NO_URL = (
    "El certificado no incluye una URL de responder OCSP en la extensión AIA.\n"
    "Al renovar el certificado, asegurarse de que la CA incluye OCSP en la AIA.\n"
    "Las CAs públicas modernas (Let's Encrypt, DigiCert, etc.) la incluyen siempre.\n"
    "Sin OCSP URL, los clientes no pueden verificar la revocación del certificado."
)

_REMED_OCSP_NO_STAPLING = (
    "Habilitar OCSP Stapling en el servidor para enviar la respuesta OCSP al cliente:\n"
    "  nginx:   ssl_stapling on;\n"
    "           ssl_stapling_verify on;\n"
    "           resolver 8.8.8.8 1.1.1.1 valid=300s;\n"
    "  apache:  SSLUseStapling on\n"
    "           SSLStaplingCache 'shmcb:/var/run/ocsp(128000)'\n"
    "  haproxy: tune.ssl.default-dh-param 2048  # + configurar resolvers\n"
    "OCSP Stapling evita que el cliente contacte al responder OCSP directamente,\n"
    "mejorando privacidad y rendimiento. Ref: RFC 6961"
)

_REMED_CT_NO_LOG = (
    "El certificado no aparece en los Certificate Transparency logs (crt.sh).\n"
    "Posibles causas:\n"
    "  · Certificado muy reciente (CT puede tardar horas en indexarlo)\n"
    "  · Certificado emitido por una CA privada/interna\n"
    "  · Certificado no enviado a CT (non-compliant CA)\n"
    "A partir de Chrome 68, los certificados sin SCT son rechazados.\n"
    "Ref: RFC 9162 — Certificate Transparency Version 2.0"
)

_REMED_NO_SCT = (
    "El certificado no contiene SCTs (Signed Certificate Timestamps) embebidos.\n"
    "Los SCTs son obligatorios para que los navegadores modernos confíen en el cert.\n"
    "Solución: Obtener el certificado de una CA que soporte CT y embeba SCTs.\n"
    "Todas las CAs públicas de confianza (Let's Encrypt, DigiCert, etc.) los incluyen.\n"
    "Ref: RFC 6962 §3.3 — los SCTs pueden venir embebidos en el cert o via TLS extension"
)

_REMED_SC081V3 = (
    "Renovar el certificado con validez máxima de 200 días (CA/B Forum SC081v3, vigente marzo 2026):\n"
    "  Let's Encrypt:  certbot renew --force-renewal  (renueva a ~90 días automáticamente)\n"
    "  Comercial:      al renovar, solicitar certificado de máximo 200 días de validez\n"
    "  Automatización: usar ACME o integración CI/CD para renovar antes de los 200 días\n"
    "Reducción gradual SC081v3: 200 días (mar 2026) → 90 días (2027) → 47 días (2029).\n"
    "Ref: https://cabforum.org/2024/03/15/ballot-sc081v3-validity-period-reduction"
)

_REMED_LOG4J_TLS = (
    "Actualizar Log4j a versión >= 2.24.0 para mitigar CVE-2026-34477 (TLS bypass via JMSAppender):\n"
    "  Maven:   <log4j.version>2.24.0</log4j.version>\n"
    "  Gradle:  implementation 'org.apache.logging.log4j:log4j-core:2.24.0'\n"
    "  Mitigación inmediata: deshabilitar JMSAppender con log4j2.enableJndiJms=false\n"
    "  Revisar configuración mTLS para que el servidor valide el certificado del cliente.\n"
    "Ref: CVE-2026-34477 · Apache Log4j Security Advisories · https://logging.apache.org/log4j/2.x/security.html"
)

_REMED_SESSION_TICKETS = (
    "Configurar rotación frecuente de TLS session ticket keys:\n"
    "  nginx:   ssl_session_tickets off;  # deshabilitar si no se necesita resumption\n"
    "           # o rotar la clave periódicamente (cada hora) con ssl_session_ticket_key\n"
    "  apache:  SSLSessionTickets off  # Apache 2.4.11+\n"
    "  haproxy: ssl-default-bind-options no-tls-tickets  # deshabilitar tickets\n"
    "Los tickets de larga duración sin rotación permiten descifrar tráfico capturado\n"
    "si la clave del ticket se compromete, debilitando la forward secrecy.\n"
    "Ref: RFC 5077 §5 — TLS Session Ticket Security Considerations"
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
    remediation: str = ""
    grade_cap:   str = ""
    delta_state: str = ""

    @property
    def order(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 99)


@dataclass
class CertInfo:
    """Detalles extraídos del certificado X.509."""
    subject:        str = ""
    issuer:         str = ""
    not_before:     datetime | None = None
    not_after:      datetime | None = None
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
    cert:                  CertInfo | None = None
    # Cabeceras HTTP
    hsts_header:           str | None = None
    x_frame_options:       str | None = None
    x_content_type:        str | None = None
    # Hallazgos consolidados
    findings:              list[Finding] = field(default_factory=list)
    # Calificación SSLabs-style (calculada al finalizar la auditoría)
    grade:                 str = ""
    # Error fatal (host no alcanzable, etc.)
    error:                 str | None = None
    # Modo estricto TLS 1.3 (--strict-tls13)
    strict_tls13:          bool = False
    # mTLS: True si el servidor requiere certificado cliente
    mtls_required:         bool = False

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "INFO"
        return min(self.findings, key=lambda f: f.order).severity

    @property
    def target(self) -> str:
        return f"{self.host}:{self.port}"
