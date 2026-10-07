"""
Certificate-aware parsing (parse + report only).

Adapted from SnafflePy's certs.py, but with the password-cracking dictionary
removed: we try to open a cert/keystore with no password, report what we learn
about it, and if it is password-protected we simply note that and move on.
"""

import base64
import logging

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12

log = logging.getLogger("manspider.parser.certs")

# file extensions we treat as certificates / key material
CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".pfx", ".p12", ".pk12", ".pkcs12"}

_PEM_CERT_HEADER = "-----BEGIN CERTIFICATE-----"
_PEM_CERT_FOOTER = "-----END CERTIFICATE-----"
_PEM_RSA_KEY_HEADER = "-----BEGIN RSA PRIVATE KEY-----"
_PEM_KEY_HEADERS = (
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
)


class _NeedsPassword(Exception):
    """Raised when a keystore can't be opened without a password."""


class ParsedCert:
    __slots__ = ("cert", "has_private_key")

    def __init__(self, cert, has_private_key):
        self.cert = cert
        self.has_private_key = has_private_key


def _rfc2253(name):
    try:
        return name.rfc4514_string()
    except Exception:
        return str(name)


def _get_bytes_from_pem(pem_string, header, footer):
    start = pem_string.find(header)
    if start < 0:
        return None
    start += len(header)
    end = pem_string.find(footer, start)
    if end < 0:
        return None
    try:
        return base64.b64decode(pem_string[start:end])
    except Exception:
        return None


def _parse_cert(data, extension):
    """Parse cert material with no password. Raises _NeedsPassword if encrypted."""
    if extension and extension.lower() == ".pem":
        try:
            pem_string = data.decode("utf-8", errors="replace")
        except Exception:
            return None
        cert_buffer = _get_bytes_from_pem(pem_string, _PEM_CERT_HEADER, _PEM_CERT_FOOTER)
        if cert_buffer is None:
            return None
        try:
            cert = x509.load_der_x509_certificate(cert_buffer)
        except Exception:
            return None
        has_key = any(h in pem_string for h in _PEM_KEY_HEADERS)
        return ParsedCert(cert, has_key)

    # PKCS#12 (.pfx/.p12/...) first, then bare DER
    try:
        key, cert, _extra = pkcs12.load_key_and_certificates(data, None)
        if cert is not None:
            return ParsedCert(cert, key is not None)
    except Exception:
        # not a (passwordless) PKCS#12 container — try DER, else assume encrypted
        try:
            cert = x509.load_der_x509_certificate(data)
            return ParsedCert(cert, False)
        except Exception:
            raise _NeedsPassword()

    try:
        cert = x509.load_der_x509_certificate(data)
        return ParsedCert(cert, False)
    except Exception:
        raise _NeedsPassword()


def _key_usage_string(ext_value):
    names = []
    mapping = [
        ("digital_signature", "DigitalSignature"),
        ("content_commitment", "NonRepudiation"),
        ("key_encipherment", "KeyEncipherment"),
        ("data_encipherment", "DataEncipherment"),
        ("key_agreement", "KeyAgreement"),
        ("key_cert_sign", "KeyCertSign"),
        ("crl_sign", "CrlSign"),
    ]
    for attr, label in mapping:
        try:
            if getattr(ext_value, attr):
                names.append(label)
        except ValueError:
            continue
    return ", ".join(names) if names else "None"


def inspect_cert(filepath, extension):
    """
    Parse a certificate/keystore and return (reasons, triage), or None if the
    file can't be understood as a certificate.

    reasons -- list of human-readable findings (HasPrivateKey, IsCACert, ...)
    triage  -- severity: "black" (unprotected private key), "red" (protected
               key / encrypted store) or "green" (public cert only)
    """
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception as e:
        log.debug(f"could not read cert file {filepath}: {e}")
        return None

    reasons = []
    parsed_cert = None
    nopwrequired = False

    try:
        parsed_cert = _parse_cert(data, extension)
        nopwrequired = True
    except _NeedsPassword:
        reasons.append("HasPassword")
        reasons.append("LookNearbyForPassword")
    except Exception as e:
        log.debug(f"error parsing cert {filepath}: {e}")
        return None

    if parsed_cert is None:
        # encrypted keystore we couldn't open, but still a finding
        if reasons:
            return reasons, "red"
        return None

    cert = parsed_cert.cert
    triage = "green"

    if parsed_cert.has_private_key:
        reasons.append("HasPrivateKey")
        if nopwrequired:
            reasons.append("NoPasswordRequired")
            triage = "black"
        else:
            triage = "red"

    reasons.append("Subject:" + _rfc2253(cert.subject))

    for ext in cert.extensions:
        try:
            if isinstance(ext.value, x509.BasicConstraints):
                if ext.value.ca:
                    reasons.append("IsCACert")
            elif isinstance(ext.value, x509.KeyUsage):
                reasons.append("KeyUsage:" + _key_usage_string(ext.value))
            elif isinstance(ext.value, x509.ExtendedKeyUsage):
                ekus = [getattr(oid, "_name", None) or oid.dotted_string for oid in ext.value]
                reasons.append("EKU:" + "|".join(ekus))
            elif isinstance(ext.value, x509.SubjectAlternativeName):
                sans = []
                for gn in ext.value:
                    try:
                        sans.append(str(gn.value))
                    except Exception:
                        continue
                if sans:
                    reasons.append("SAN:" + ", ".join(sans))
        except Exception:
            continue

    try:
        expiry = cert.not_valid_after_utc
    except AttributeError:
        expiry = cert.not_valid_after
    reasons.append("Expiry:" + expiry.strftime("%Y-%m-%d %H:%M:%S"))
    reasons.append("Issuer:" + _rfc2253(cert.issuer))

    return reasons, triage
