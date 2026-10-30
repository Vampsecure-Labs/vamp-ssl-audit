# © VampSecure Studios — VampSecure Labs Security Research Division
"""
_models.py — Constantes, estructuras de datos y remediaciones de vamp-ssl-audit
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

VERSION   = "1.8.0"
TOOL_NAME = "vamp-ssl-audit"

# ---------------------------------------------------------------------------
# Bilingual support
# ---------------------------------------------------------------------------

LANG: str = "en"  # overridden by CLI: _models.LANG = args.lang


class _T:
    """Lazy bilingual string — resolves at str() time, not at definition time."""
    __slots__ = ("_en", "_es")

    def __init__(self, en: str, es: str) -> None:
        self._en, self._es = en, es

    def __str__(self) -> str:
        return self._es if LANG == "es" else self._en

    def __repr__(self) -> str:
        return str(self)

    def format(self, **kw: object) -> str:
        return str(self).format(**kw)


# ---------------------------------------------------------------------------
# Constantes de clasificación de protocolos y cifrados
# ---------------------------------------------------------------------------

PROTOCOL_RISK: dict[str, tuple[str, _T]] = {
    "SSLv3":   ("CRITICAL", _T(
        "Obsolete protocol, vulnerable to POODLE (RFC 7568)",
        "Protocolo obsoleto, vulnerable a POODLE (RFC 7568)")),
    "TLS 1.0": ("CRITICAL", _T(
        "Obsolete protocol, vulnerable to BEAST/POODLE (RFC 8996)",
        "Protocolo obsoleto, vulnerable a BEAST/POODLE (RFC 8996)")),
    "TLS 1.1": ("HIGH",     _T(
        "Obsolete protocol, deprecated in RFC 8996",
        "Protocolo obsoleto, depreciado en RFC 8996")),
    "TLS 1.2": ("INFO",     _T(
        "Acceptable protocol, AEAD cipher recommended",
        "Protocolo aceptable, recomendado cifrado AEAD")),
    "TLS 1.3": ("INFO",     _T(
        "Optimal protocol, mandatory forward-secrecy",
        "Protocolo óptimo, forward-secrecy obligatoria")),
}

# Cap de nota SSLabs por protocolo legacy detectado
PROTOCOL_GRADE_CAP: dict[str, str] = {
    "SSLv3":   "C",
    "TLS 1.0": "B",
    "TLS 1.1": "B",
}

# Fragmentos de nombre de cipher que indican debilidad
WEAK_CIPHER_PATTERNS: dict[str, tuple[str, _T]] = {
    "NULL":    ("CRITICAL", _T(
        "No encryption — traffic in cleartext",
        "Sin cifrado — tráfico en claro")),
    "EXPORT":  ("CRITICAL", _T(
        "Export cipher — intentionally reduced key",
        "Cifrado de exportación — clave reducida intencional")),
    "ADH":     ("CRITICAL", _T(
        "Anonymous Diffie-Hellman — no server authentication",
        "Diffie-Hellman anónimo — sin autenticación del servidor")),
    "AECDH":   ("CRITICAL", _T(
        "Anonymous ECDH — no server authentication",
        "ECDH anónimo — sin autenticación del servidor")),
    "RC4":     ("CRITICAL", _T(
        "Broken RC4, documented statistical biases (RFC 7465)",
        "RC4 roto, sesgos estadísticos documentados (RFC 7465)")),
    "DES ":    ("CRITICAL", _T(
        "56-bit DES, broken in 1999",
        "DES de 56 bits, roto en 1999")),
    "_DES_":   ("HIGH",     _T(
        "3DES vulnerable to Sweet32 (64-bit block)",
        "3DES vulnerable a Sweet32 (bloque de 64 bits)")),
    "3DES":    ("HIGH",     _T(
        "3DES vulnerable to Sweet32 (64-bit block)",
        "3DES vulnerable a Sweet32 (bloque de 64 bits)")),
    "MD5":     ("HIGH",     _T(
        "HMAC-MD5 as MAC — known weakness",
        "HMAC-MD5 como MAC — debilidad conocida")),
    "RC2":     ("HIGH",     _T(
        "RC2 obsolete and without active support",
        "RC2 obsoleto y sin soporte activo")),
    "IDEA":    ("MEDIUM",   _T(
        "IDEA obsolete",
        "IDEA desusado")),
    "CAMELLIA":("MEDIUM",   _T(
        "Camellia — acceptable but uncommon",
        "Camellia — aceptable pero poco habitual")),
    "SEED":    ("MEDIUM",   _T(
        "SEED — obsolete Korean standard",
        "SEED — estándar coreano obsoleto")),
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
SIG_ALG_RISK: dict[str, tuple[str, _T]] = {
    "md5":    ("CRITICAL", _T(
        "MD5 signature — trivially demonstrable collisions",
        "Firma MD5 — colisiones triviales demostrables")),
    "sha1":   ("HIGH",     _T(
        "SHA-1 signature — deprecated, known collisions (SHAttered)",
        "Firma SHA-1 — depreciada, colisiones conocidas (SHAttered)")),
    "sha256": ("INFO",     _T(
        "SHA-256 — minimum recommended standard",
        "SHA-256 — estándar mínimo recomendado")),
    "sha384": ("INFO",     _T(
        "SHA-384 — robust",
        "SHA-384 — robusto")),
    "sha512": ("INFO",     _T(
        "SHA-512 — robust",
        "SHA-512 — robusto")),
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

GRADE_DESCRIPTION: dict[str, _T] = {
    "A+": _T(
        "Exceptional configuration — all best practices met",
        "Configuración excepcional — todas las mejores prácticas cumplidas"),
    "A":  _T(
        "Good configuration — no significant issues",
        "Buena configuración — sin problemas significativos"),
    "A-": _T(
        "Good configuration — HSTS or TLS 1.3 support improvable",
        "Buena configuración — HSTS o soporte de TLS 1.3 mejorable"),
    "B":  _T(
        "Acceptable configuration — legacy protocols or weak ciphers present",
        "Configuración aceptable — protocolos legacy o cifrados débiles presentes"),
    "C":  _T(
        "Poor configuration — SSLv3, RC4 or MD5 signature accepted",
        "Configuración deficiente — SSLv3, RC4 o firma MD5 aceptada"),
    "D":  _T(
        "Very poor configuration",
        "Configuración muy deficiente"),
    "T":  _T(
        "Untrusted certificate — self-signed or hostname not covered",
        "Certificado no confiable — autofirmado o sin cobertura del hostname"),
    "F":  _T(
        "Critical failure — null cipher, expired certificate or connection impossible",
        "Fallo crítico — cifrado nulo, certificado expirado o conexión imposible"),
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

_REMED_TLS_LEGACY = _T(
    "Remove the protocol from the allowed list:\n"
    "  nginx:   ssl_protocols TLSv1.2 TLSv1.3;\n"
    "  apache:  SSLProtocol -all +TLSv1.2 +TLSv1.3\n"
    "  haproxy: bind *:443 ssl-min-ver TLSv1.2\n"
    "Ref: RFC 8996, PCI-DSS 4.0 §4.2.1",
    "Eliminar el protocolo de la lista permitida:\n"
    "  nginx:   ssl_protocols TLSv1.2 TLSv1.3;\n"
    "  apache:  SSLProtocol -all +TLSv1.2 +TLSv1.3\n"
    "  haproxy: bind *:443 ssl-min-ver TLSv1.2\n"
    "Ref: RFC 8996, PCI-DSS 4.0 §4.2.1",
)

_REMED_NULL_CIPHER = _T(
    "Remove NULL ciphers from the configuration:\n"
    "  nginx:   ssl_ciphers ECDH+AESGCM:ECDH+CHACHA20:!NULL:!EXPORT;\n"
    "  apache:  SSLCipherSuite HIGH:!NULL:!EXPORT:!MD5:!3DES\n"
    "  haproxy: ssl-default-bind-ciphers ECDH+AESGCM:ECDH+CHACHA20\n"
    "Urgency: CRITICAL — traffic is transmitted in cleartext.",
    "Eliminar cifrados NULL de la configuración:\n"
    "  nginx:   ssl_ciphers ECDH+AESGCM:ECDH+CHACHA20:!NULL:!EXPORT;\n"
    "  apache:  SSLCipherSuite HIGH:!NULL:!EXPORT:!MD5:!3DES\n"
    "  haproxy: ssl-default-bind-ciphers ECDH+AESGCM:ECDH+CHACHA20\n"
    "Urgencia: CRÍTICA — el tráfico circula en claro.",
)

_REMED_EXPORT_CIPHER = _T(
    "Remove EXPORT ciphers (intentionally designed to be weak):\n"
    "  nginx:   ssl_ciphers '!EXPORT:HIGH:ECDH+AESGCM:ECDH+CHACHA20';\n"
    "  apache:  SSLCipherSuite HIGH:!EXPORT:!NULL\n"
    "Urgency: CRITICAL — session key reducible to ≤40 bits.",
    "Eliminar cifrados EXPORT (diseñados para ser débiles intencionalmente):\n"
    "  nginx:   ssl_ciphers '!EXPORT:HIGH:ECDH+AESGCM:ECDH+CHACHA20';\n"
    "  apache:  SSLCipherSuite HIGH:!EXPORT:!NULL\n"
    "Urgencia: CRÍTICA — clave de sesión reducible a ≤40 bits.",
)

_REMED_ANON_CIPHER = _T(
    "Remove anonymous ciphers (no server authentication):\n"
    "  nginx:   ssl_ciphers '!ADH:!AECDH:HIGH:ECDH+AESGCM';\n"
    "  apache:  SSLCipherSuite HIGH:!ADH:!AECDH:!EXPORT\n"
    "Urgency: CRITICAL — anyone can impersonate the server.",
    "Eliminar cifrados anónimos (sin autenticación del servidor):\n"
    "  nginx:   ssl_ciphers '!ADH:!AECDH:HIGH:ECDH+AESGCM';\n"
    "  apache:  SSLCipherSuite HIGH:!ADH:!AECDH:!EXPORT\n"
    "Urgencia: CRÍTICA — cualquiera puede hacerse pasar por el servidor.",
)

_REMED_RC4 = _T(
    "Remove RC4 (statistical biases allow recovering plaintext):\n"
    "  nginx:   ssl_ciphers '!RC4:ECDH+AESGCM:ECDH+CHACHA20';\n"
    "  apache:  SSLCipherSuite HIGH:!RC4:!EXPORT\n"
    "Ref: RFC 7465",
    "Eliminar RC4 (sesgos estadísticos permiten recuperar texto claro):\n"
    "  nginx:   ssl_ciphers '!RC4:ECDH+AESGCM:ECDH+CHACHA20';\n"
    "  apache:  SSLCipherSuite HIGH:!RC4:!EXPORT\n"
    "Ref: RFC 7465",
)

_REMED_DES = _T(
    "Remove DES (56-bit key, broken since 1998):\n"
    "  nginx:   ssl_ciphers 'HIGH:!DES:!3DES:ECDH+AESGCM';\n"
    "  apache:  SSLCipherSuite HIGH:!DES:!3DES",
    "Eliminar DES (clave de 56 bits, roto desde 1998):\n"
    "  nginx:   ssl_ciphers 'HIGH:!DES:!3DES:ECDH+AESGCM';\n"
    "  apache:  SSLCipherSuite HIGH:!DES:!3DES",
)

_REMED_3DES = _T(
    "Remove 3DES (vulnerable to Sweet32, 64-bit block):\n"
    "  nginx:   ssl_ciphers 'HIGH:!3DES:ECDH+AESGCM:ECDH+CHACHA20';\n"
    "  apache:  SSLCipherSuite HIGH:!3DES:!DES:!RC4\n"
    "Ref: CVE-2016-2183 (Sweet32)",
    "Eliminar 3DES (vulnerable a Sweet32, bloque de 64 bits):\n"
    "  nginx:   ssl_ciphers 'HIGH:!3DES:ECDH+AESGCM:ECDH+CHACHA20';\n"
    "  apache:  SSLCipherSuite HIGH:!3DES:!DES:!RC4\n"
    "Ref: CVE-2016-2183 (Sweet32)",
)

_REMED_CERT_EXPIRED = _T(
    "Renew the certificate immediately:\n"
    "  Let's Encrypt:  certbot renew --force-renewal\n"
    "  Commercial CA:  generate a new CSR and renew at the CA\n"
    "Urgency: CRITICAL — browsers reject the connection.",
    "Renovar el certificado de inmediato:\n"
    "  Let's Encrypt:  certbot renew --force-renewal\n"
    "  Comercial:      generar nueva CSR y renovar en la CA\n"
    "Urgencia: CRÍTICA — los navegadores rechazan la conexión.",
)

_REMED_CERT_EXPIRING = _T(
    "Renew the certificate before it expires:\n"
    "  Let's Encrypt:  certbot renew  (can be run now)\n"
    "  Commercial CA:  start renewal process at the CA\n"
    "Recommended: renew with ≥30 days in advance.",
    "Renovar el certificado antes de su vencimiento:\n"
    "  Let's Encrypt:  certbot renew  (se puede ejecutar ya)\n"
    "  Comercial:      iniciar proceso de renovación en la CA\n"
    "Recomendado: renovar con ≥30 días de antelación.",
)

_REMED_SELF_SIGNED = _T(
    "Obtain a certificate signed by a trusted CA:\n"
    "  Free:      certbot --nginx -d example.com  (Let's Encrypt)\n"
    "  Internal:  configure the corporate root CA on clients\n"
    "Urgency: HIGH — browsers show a security warning.",
    "Obtener un certificado firmado por una CA de confianza:\n"
    "  Gratuito:  certbot --nginx -d ejemplo.com  (Let's Encrypt)\n"
    "  Interno:   configurar la CA raíz corporativa en los clientes\n"
    "Urgencia: ALTA — los navegadores muestran advertencia de seguridad.",
)

_REMED_RSA_SMALL = _T(
    "Generate an RSA key of at least 2048 bits (recommended 4096):\n"
    "  openssl genrsa -out key.key 4096\n"
    "  openssl req -new -key key.key -out request.csr\n"
    "Ref: NIST SP 800-131Ar2",
    "Generar una clave RSA de mínimo 2048 bits (recomendado 4096):\n"
    "  openssl genrsa -out clave.key 4096\n"
    "  openssl req -new -key clave.key -out solicitud.csr\n"
    "Ref: NIST SP 800-131Ar2",
)

_REMED_RSA_WEAK = _T(
    "Generate an RSA key of at least 2048 bits (recommended 4096):\n"
    "  openssl genrsa -out key.key 4096\n"
    "  openssl req -new -key key.key -out request.csr\n"
    "Ref: NIST SP 800-131Ar2",
    "Generar una clave RSA de al menos 2048 bits (recomendado 4096):\n"
    "  openssl genrsa -out clave.key 4096\n"
    "  openssl req -new -key clave.key -out solicitud.csr\n"
    "Ref: NIST SP 800-131Ar2",
)

_REMED_SHA1 = _T(
    "Renew the certificate with a SHA-256 or higher signature algorithm:\n"
    "  openssl req -new -sha256 -key key.key -out request.csr\n"
    "Modern browsers show warnings for SHA-1 signatures since 2017.",
    "Renovar el certificado con algoritmo de firma SHA-256 o superior:\n"
    "  openssl req -new -sha256 -key clave.key -out solicitud.csr\n"
    "Los navegadores modernos muestran advertencia con SHA-1 desde 2017.",
)

_REMED_MD5 = _T(
    "Renew the certificate with a SHA-256 or higher signature algorithm:\n"
    "  openssl req -new -sha256 -key key.key -out request.csr\n"
    "Urgency: CRITICAL — MD5 collisions are trivial (Flame, 2012).",
    "Renovar el certificado con algoritmo de firma SHA-256 o superior:\n"
    "  openssl req -new -sha256 -key clave.key -out solicitud.csr\n"
    "Urgencia: CRÍTICA — colisiones MD5 son triviales (Flame, 2012).",
)

_REMED_HSTS_ABSENT = _T(
    "Add the HSTS header to the server response:\n"
    "  nginx:   add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload';\n"
    "  apache:  Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload'\n"
    "  haproxy: http-response set-header Strict-Transport-Security max-age=31536000;includeSubDomains;preload\n"
    "Ref: RFC 6797 · Register at https://hstspreload.org for preload",
    "Añadir cabecera HSTS a la respuesta del servidor:\n"
    "  nginx:   add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload';\n"
    "  apache:  Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload'\n"
    "  haproxy: http-response set-header Strict-Transport-Security max-age=31536000;includeSubDomains;preload\n"
    "Ref: RFC 6797 · Registrar en https://hstspreload.org para preload",
)

_REMED_HSTS_SHORT = _T(
    "Increase max-age to at least 180 days (15,552,000 s), recommended 1 year:\n"
    "  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n"
    "The current value is insufficient for browser preloading.",
    "Aumentar max-age a mínimo 180 días (15 552 000 s), recomendado 1 año:\n"
    "  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n"
    "El valor actual es insuficiente para el preload de navegadores.",
)

_REMED_HSTS_NO_SUBS = _T(
    "Add includeSubDomains to the HSTS header:\n"
    "  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n"
    "Without includeSubDomains, subdomains remain unprotected.",
    "Añadir includeSubDomains a la cabecera HSTS:\n"
    "  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n"
    "Sin includeSubDomains los subdominios quedan desprotegidos.",
)

_REMED_XFO = _T(
    "Add the X-Frame-Options header to prevent clickjacking:\n"
    "  nginx:   add_header X-Frame-Options DENY;\n"
    "  apache:  Header always set X-Frame-Options DENY\n"
    "Use SAMEORIGIN if the app legitimately embeds its own content.",
    "Añadir cabecera X-Frame-Options para prevenir clickjacking:\n"
    "  nginx:   add_header X-Frame-Options DENY;\n"
    "  apache:  Header always set X-Frame-Options DENY\n"
    "Usar SAMEORIGIN si la app legítimamente embebe su propio contenido.",
)

_REMED_XCTO = _T(
    "Add the X-Content-Type-Options header to prevent MIME sniffing:\n"
    "  nginx:   add_header X-Content-Type-Options nosniff;\n"
    "  apache:  Header always set X-Content-Type-Options nosniff",
    "Añadir cabecera X-Content-Type-Options para prevenir MIME sniffing:\n"
    "  nginx:   add_header X-Content-Type-Options nosniff;\n"
    "  apache:  Header always set X-Content-Type-Options nosniff",
)

_REMED_HOSTNAME = _T(
    "The installed certificate does not cover this hostname.\n"
    "Solutions:\n"
    "  a) Obtain a certificate that includes this hostname in its SAN\n"
    "  b) Add the hostname as an additional SAN when renewing\n"
    "Ref: RFC 2818 §3.1 — CN is ignored if SAN entries exist",
    "El certificado instalado no cubre este hostname.\n"
    "Soluciones:\n"
    "  a) Obtener un certificado que incluya este hostname en su SAN\n"
    "  b) Añadir el hostname como SAN adicional al renovar\n"
    "Ref: RFC 2818 §3.1 — el CN es ignorado si existen SAN",
)

_REMED_DSA = _T(
    "Migrate to RSA (≥2048 bits) or EC (P-256/P-384) key:\n"
    "  openssl ecparam -name prime256v1 -genkey -noout -out ec-key.key\n"
    "  openssl req -new -sha256 -key ec-key.key -out request.csr\n"
    "DSA has been deprecated by most CAs since 2015.",
    "Migrar a clave RSA (≥2048 bits) o EC (P-256/P-384):\n"
    "  openssl ecparam -name prime256v1 -genkey -noout -out clave-ec.key\n"
    "  openssl req -new -sha256 -key clave-ec.key -out solicitud.csr\n"
    "DSA está depreciado en la mayoría de CAs desde 2015.",
)

_REMED_OCSP_NO_URL = _T(
    "The certificate does not include an OCSP responder URL in the AIA extension.\n"
    "When renewing the certificate, ensure the CA includes OCSP in the AIA.\n"
    "Modern public CAs (Let's Encrypt, DigiCert, etc.) always include it.\n"
    "Without an OCSP URL, clients cannot verify certificate revocation status.",
    "El certificado no incluye una URL de responder OCSP en la extensión AIA.\n"
    "Al renovar el certificado, asegurarse de que la CA incluye OCSP en la AIA.\n"
    "Las CAs públicas modernas (Let's Encrypt, DigiCert, etc.) la incluyen siempre.\n"
    "Sin OCSP URL, los clientes no pueden verificar la revocación del certificado.",
)

_REMED_OCSP_NO_STAPLING = _T(
    "Enable OCSP Stapling on the server to send the OCSP response to the client:\n"
    "  nginx:   ssl_stapling on;\n"
    "           ssl_stapling_verify on;\n"
    "           resolver 8.8.8.8 1.1.1.1 valid=300s;\n"
    "  apache:  SSLUseStapling on\n"
    "           SSLStaplingCache 'shmcb:/var/run/ocsp(128000)'\n"
    "  haproxy: tune.ssl.default-dh-param 2048  # + configure resolvers\n"
    "OCSP Stapling prevents the client from contacting the OCSP responder directly,\n"
    "improving privacy and performance. Ref: RFC 6961",
    "Habilitar OCSP Stapling en el servidor para enviar la respuesta OCSP al cliente:\n"
    "  nginx:   ssl_stapling on;\n"
    "           ssl_stapling_verify on;\n"
    "           resolver 8.8.8.8 1.1.1.1 valid=300s;\n"
    "  apache:  SSLUseStapling on\n"
    "           SSLStaplingCache 'shmcb:/var/run/ocsp(128000)'\n"
    "  haproxy: tune.ssl.default-dh-param 2048  # + configurar resolvers\n"
    "OCSP Stapling evita que el cliente contacte al responder OCSP directamente,\n"
    "mejorando privacidad y rendimiento. Ref: RFC 6961",
)

_REMED_CT_NO_LOG = _T(
    "The certificate does not appear in Certificate Transparency logs (crt.sh).\n"
    "Possible causes:\n"
    "  · Very recent certificate (CT may take hours to index it)\n"
    "  · Certificate issued by a private/internal CA\n"
    "  · Certificate not submitted to CT (non-compliant CA)\n"
    "As of Chrome 68, certificates without SCTs are rejected.\n"
    "Ref: RFC 9162 — Certificate Transparency Version 2.0",
    "El certificado no aparece en los Certificate Transparency logs (crt.sh).\n"
    "Posibles causas:\n"
    "  · Certificado muy reciente (CT puede tardar horas en indexarlo)\n"
    "  · Certificado emitido por una CA privada/interna\n"
    "  · Certificado no enviado a CT (non-compliant CA)\n"
    "A partir de Chrome 68, los certificados sin SCT son rechazados.\n"
    "Ref: RFC 9162 — Certificate Transparency Version 2.0",
)

_REMED_NO_SCT = _T(
    "The certificate does not contain embedded SCTs (Signed Certificate Timestamps).\n"
    "SCTs are required for modern browsers to trust the certificate.\n"
    "Solution: Obtain the certificate from a CA that supports CT and embeds SCTs.\n"
    "All trusted public CAs (Let's Encrypt, DigiCert, etc.) include them.\n"
    "Ref: RFC 6962 §3.3 — SCTs can come embedded in the cert or via TLS extension",
    "El certificado no contiene SCTs (Signed Certificate Timestamps) embebidos.\n"
    "Los SCTs son obligatorios para que los navegadores modernos confíen en el cert.\n"
    "Solución: Obtener el certificado de una CA que soporte CT y embeba SCTs.\n"
    "Todas las CAs públicas de confianza (Let's Encrypt, DigiCert, etc.) los incluyen.\n"
    "Ref: RFC 6962 §3.3 — los SCTs pueden venir embebidos en el cert o via TLS extension",
)

_REMED_SC081V3 = _T(
    "Renew the certificate with a maximum validity of 200 days (CA/B Forum SC081v3, effective March 2026):\n"
    "  Let's Encrypt:  certbot renew --force-renewal  (auto-renews to ~90 days)\n"
    "  Commercial CA:  when renewing, request a certificate with max 200 days validity\n"
    "  Automation:     use ACME or CI/CD integration to renew before 200 days\n"
    "SC081v3 gradual reduction: 200 days (Mar 2026) → 90 days (2027) → 47 days (2029).\n"
    "Ref: https://cabforum.org/2024/03/15/ballot-sc081v3-validity-period-reduction",
    "Renovar el certificado con validez máxima de 200 días (CA/B Forum SC081v3, vigente marzo 2026):\n"
    "  Let's Encrypt:  certbot renew --force-renewal  (renueva a ~90 días automáticamente)\n"
    "  Comercial:      al renovar, solicitar certificado de máximo 200 días de validez\n"
    "  Automatización: usar ACME o integración CI/CD para renovar antes de los 200 días\n"
    "Reducción gradual SC081v3: 200 días (mar 2026) → 90 días (2027) → 47 días (2029).\n"
    "Ref: https://cabforum.org/2024/03/15/ballot-sc081v3-validity-period-reduction",
)

_REMED_LOG4J_TLS = _T(
    "Update Log4j to version >= 2.24.0 to mitigate CVE-2026-34477 (TLS bypass via JMSAppender):\n"
    "  Maven:   <log4j.version>2.24.0</log4j.version>\n"
    "  Gradle:  implementation 'org.apache.logging.log4j:log4j-core:2.24.0'\n"
    "  Immediate mitigation: disable JMSAppender with log4j2.enableJndiJms=false\n"
    "  Review mTLS configuration so the server validates client certificates.\n"
    "Ref: CVE-2026-34477 · Apache Log4j Security Advisories · https://logging.apache.org/log4j/2.x/security.html",
    "Actualizar Log4j a versión >= 2.24.0 para mitigar CVE-2026-34477 (TLS bypass via JMSAppender):\n"
    "  Maven:   <log4j.version>2.24.0</log4j.version>\n"
    "  Gradle:  implementation 'org.apache.logging.log4j:log4j-core:2.24.0'\n"
    "  Mitigación inmediata: deshabilitar JMSAppender con log4j2.enableJndiJms=false\n"
    "  Revisar configuración mTLS para que el servidor valide el certificado del cliente.\n"
    "Ref: CVE-2026-34477 · Apache Log4j Security Advisories · https://logging.apache.org/log4j/2.x/security.html",
)

_REMED_SESSION_TICKETS = _T(
    "Configure frequent rotation of TLS session ticket keys:\n"
    "  nginx:   ssl_session_tickets off;  # disable if resumption not needed\n"
    "           # or rotate the key periodically (every hour) with ssl_session_ticket_key\n"
    "  apache:  SSLSessionTickets off  # Apache 2.4.11+\n"
    "  haproxy: ssl-default-bind-options no-tls-tickets  # disable tickets\n"
    "Long-lived tickets without rotation allow decrypting captured traffic\n"
    "if the ticket key is compromised, weakening forward secrecy.\n"
    "Ref: RFC 5077 §5 — TLS Session Ticket Security Considerations",
    "Configurar rotación frecuente de TLS session ticket keys:\n"
    "  nginx:   ssl_session_tickets off;  # deshabilitar si no se necesita resumption\n"
    "           # o rotar la clave periódicamente (cada hora) con ssl_session_ticket_key\n"
    "  apache:  SSLSessionTickets off  # Apache 2.4.11+\n"
    "  haproxy: ssl-default-bind-options no-tls-tickets  # deshabilitar tickets\n"
    "Los tickets de larga duración sin rotación permiten descifrar tráfico capturado\n"
    "si la clave del ticket se compromete, debilitando la forward secrecy.\n"
    "Ref: RFC 5077 §5 — TLS Session Ticket Security Considerations",
)

# ---------------------------------------------------------------------------
# Estructuras de datos
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """Individual security finding with remediation and grade cap."""
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
    """Details extracted from the X.509 certificate."""
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
    """Complete audit result for a host:port."""
    host:                  str
    port:                  int
    timestamp:             str
    # Protocol
    negotiated_protocol:   str = ""
    negotiated_cipher:     str = ""
    supported_protocols:   list[str] = field(default_factory=list)
    unsupported_protocols: list[str] = field(default_factory=list)
    # Certificate
    cert:                  CertInfo | None = None
    # HTTP headers
    hsts_header:           str | None = None
    x_frame_options:       str | None = None
    x_content_type:        str | None = None
    # Consolidated findings
    findings:              list[Finding] = field(default_factory=list)
    # SSLabs-style grade (computed at end of audit)
    grade:                 str = ""
    # Fatal error (host unreachable, etc.)
    error:                 str | None = None
    # Strict TLS 1.3 mode (--strict-tls13)
    strict_tls13:          bool = False
    # mTLS: True if server requires client certificate
    mtls_required:         bool = False

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "INFO"
        return min(self.findings, key=lambda f: f.order).severity

    @property
    def target(self) -> str:
        return f"{self.host}:{self.port}"
