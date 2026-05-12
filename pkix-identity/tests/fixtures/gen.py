#!/usr/bin/env python3
"""
Generate DER fixtures for pkix-identity verify_dns_name integration tests.

Each fixture is a self-signed leaf certificate with a Subject Alternative
Name extension containing a curated set of identities. The tests do not
validate any chain — `pkix-identity` is a pure-function library over a
single `Certificate` — so self-signed certs are sufficient.

Validity 2000-01-01 to 2050-01-01; key material is P-256 ECDSA so the
fixtures can be regenerated quickly. The signature is not exercised by
the consumer tests.

Oracle: pyca/cryptography 48.0.0. The Rust verifier under test never
participates in fixture creation, so the test corpus is independent of
the code being verified.

Run from this directory:

    /home/mark/PROJECT/PKIX/pkix-difftest/python/.venv/bin/python3 gen.py

(or any other Python environment with cryptography installed).
"""

import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import ipaddress

# RFC 8398 §3 id-on-SmtpUTF8Mailbox
OID_SMTP_UTF8_MAILBOX = ObjectIdentifier("1.3.6.1.5.5.7.8.9")


def utf8_string_der(s: str) -> bytes:
    """DER-encode a UTF8String (tag 0x0c)."""
    data = s.encode("utf-8")
    if len(data) < 128:
        return bytes([0x0C, len(data)]) + data
    if len(data) < 256:
        return bytes([0x0C, 0x81, len(data)]) + data
    raise NotImplementedError("UTF8String longer than 255 bytes not supported in fixtures")

OUT = Path(__file__).parent
NOT_BEFORE = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2050, 1, 1, tzinfo=datetime.timezone.utc)


def build_leaf(sans, *, common_name="leaf", omit_san=False):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if not omit_san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(sans),
            critical=False,
        )
    return builder.sign(key, hashes.SHA256())


fixtures = {
    # ----- DNS / IP SAN fixtures (PKIX-fmtv.11.1) -----
    # Exact DNS name only.
    "san-exact-dns.der": build_leaf([x509.DNSName("www.example.com")]),
    # Single-label leftmost wildcard.
    "san-wildcard-dns.der": build_leaf([x509.DNSName("*.example.com")]),
    # Multiple DNS entries.
    "san-multi-dns.der": build_leaf([
        x509.DNSName("www.example.com"),
        x509.DNSName("api.example.com"),
        x509.DNSName("*.cdn.example.com"),
    ]),
    # IPv4 SAN.
    "san-ipv4.der": build_leaf([x509.IPAddress(ipaddress.IPv4Address("192.0.2.5"))]),
    # IPv6 SAN.
    "san-ipv6.der": build_leaf([x509.IPAddress(ipaddress.IPv6Address("2001:db8::1"))]),
    # Mixed DNS + IPv4.
    "san-mixed.der": build_leaf([
        x509.DNSName("host.example.com"),
        x509.IPAddress(ipaddress.IPv4Address("203.0.113.10")),
    ]),
    # IDN: A-label SAN entry (real-world CAs only put A-labels in SANs).
    "san-idn-alabel.der": build_leaf([x509.DNSName("xn--bcher-kva.example")]),
    # Mixed-case SAN: matching must be case-insensitive.
    "san-mixed-case.der": build_leaf([x509.DNSName("Host.Example.COM")]),
    # No SAN extension at all.
    "san-missing.der": build_leaf([], omit_san=True),
    # CN-only cert (no SAN). Identity in CN should NOT be honored.
    "cn-only.der": build_leaf([], omit_san=True),

    # ----- Mailbox SAN fixtures (PKIX-fmtv.12.1) -----
    # Plain rfc822Name.
    "san-rfc822.der": build_leaf([x509.RFC822Name("alice@example.com")]),
    # rfc822Name with mixed-case domain (must still match lowercase target).
    "san-rfc822-mixedcase.der": build_leaf([x509.RFC822Name("alice@Example.COM")]),
    # otherName SmtpUTF8Mailbox with internationalized local-part.
    "san-smtputf8.der": build_leaf([
        x509.OtherName(
            OID_SMTP_UTF8_MAILBOX,
            utf8_string_der("用户@example.com"),
        )
    ]),
    # otherName SmtpUTF8Mailbox with U-label domain (RFC 8398 §3 form).
    "san-smtputf8-u-label-domain.der": build_leaf([
        x509.OtherName(
            OID_SMTP_UTF8_MAILBOX,
            utf8_string_der("user@bücher.example"),
        )
    ]),
    # Mixed: rfc822Name AND otherName SmtpUTF8Mailbox.
    "san-mailbox-mixed.der": build_leaf([
        x509.RFC822Name("alice@example.com"),
        x509.OtherName(
            OID_SMTP_UTF8_MAILBOX,
            utf8_string_der("用户@example.com"),
        ),
    ]),
}

for name, cert in fixtures.items():
    path = OUT / name
    path.write_bytes(cert.public_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.DER))
    print(f"wrote {path.relative_to(OUT.parent.parent)}")
