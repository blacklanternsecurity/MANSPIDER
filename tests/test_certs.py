import datetime

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from man_spider.lib.parser.certs import inspect_cert


@pytest.fixture(scope="module")
def cert_and_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2030, 1, 1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def test_public_pem_is_green(tmp_path, cert_and_key):
    cert, _key = cert_and_key
    p = tmp_path / "cert.pem"
    p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    reasons, triage = inspect_cert(str(p), ".pem")
    assert triage == "green"
    assert "IsCACert" in reasons
    assert any(r.startswith("Expiry:") for r in reasons)
    assert "HasPrivateKey" not in reasons


def test_public_der_is_green(tmp_path, cert_and_key):
    cert, _key = cert_and_key
    p = tmp_path / "cert.der"
    p.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    reasons, triage = inspect_cert(str(p), ".der")
    assert triage == "green"
    assert "IsCACert" in reasons


def test_pem_with_private_key_is_black(tmp_path, cert_and_key):
    cert, key = cert_and_key
    p = tmp_path / "bundle.pem"
    pem = cert.public_bytes(serialization.Encoding.PEM) + key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    p.write_bytes(pem)
    reasons, triage = inspect_cert(str(p), ".pem")
    assert triage == "black"
    assert "HasPrivateKey" in reasons


def test_pkcs12_no_password_is_black(tmp_path, cert_and_key):
    cert, key = cert_and_key
    p = tmp_path / "nopass.p12"
    p.write_bytes(pkcs12.serialize_key_and_certificates(b"t", key, cert, None, serialization.NoEncryption()))
    reasons, triage = inspect_cert(str(p), ".p12")
    assert triage == "black"
    assert "HasPrivateKey" in reasons
    assert "NoPasswordRequired" in reasons


def test_pkcs12_with_password_is_red_and_not_cracked(tmp_path, cert_and_key):
    cert, key = cert_and_key
    p = tmp_path / "haspass.pfx"
    enc = serialization.BestAvailableEncryption(b"Secret123")
    p.write_bytes(pkcs12.serialize_key_and_certificates(b"t", key, cert, None, enc))
    reasons, triage = inspect_cert(str(p), ".pfx")
    assert triage == "red"
    assert "HasPassword" in reasons
    # parse + report only: no password-cracking is attempted
    assert not any("PasswordCracked" in r for r in reasons)


def test_non_cert_returns_none(tmp_path):
    p = tmp_path / "notacert.pem"
    p.write_text("this is not a certificate at all\n")
    assert inspect_cert(str(p), ".pem") is None
