#!/usr/bin/env python3
"""
Name forms `pkix-path` cannot match, with and without a constraint on them
in effect.

WHAT THE RULE IS
----------------
RFC 5280 §4.2.1.10 requires a certificate to be rejected when a name
constraint applies to a form the implementation cannot evaluate.
`pkix-path` cannot match `otherName`, `ediPartyName` or `registeredID`
constraints, so `check_san_name_form` refuses a SAN of one of those forms
whenever a constraint on that form is in effect -- and only then.

The whole rule rests on one match guard, and the PKITS corpus has no
vector for any of these forms, so the guard had no test in either
direction. Always false, an unevaluable form passes under a constraint
that applies to it; always true, it is refused with no constraint in sight.

  root                       the anchor
  ca-regid                   nameConstraints permits registeredID 1.2.3.4
  ca-dns                     nameConstraints permits dNSName example.com
  leaf-regid-under-regid     SAN registeredID 1.2.3.4, issued by ca-regid
  leaf-regid-under-dns       the same SAN, issued by ca-dns

The value in the SAN matches the one in the permitted subtree on purpose.
The rule is about the form being unevaluable, not about the value failing
to match, and a fixture whose value differed could not tell those apart.

THE SmtpUTF8Mailbox CONDITION
-----------------------------
`check_san_name_form` also routes an `SmtpUTF8Mailbox` otherName through
the rfc822Name constraints (RFC 8398 §6), under a two-part condition: the
otherName's type-id is SmtpUTF8Mailbox AND an rfc822Name constraint is in
effect. Loosened to either, any otherName reaching that point is read as a
mailbox, and one whose value is not a UTF8String is refused as malformed.

  ca-rfc822                  nameConstraints permits rfc822Name example.com
  leaf-othername-under-rfc822  SAN otherName(1.2.3.5) whose value is an
                               INTEGER, not a UTF8String

That leaf must be accepted: no otherName constraint is in effect, so the
form is evaluable-by-irrelevance, and it is not a mailbox.

Oracle: pyca/cryptography. The Rust validator never participates.

Run from this directory:

    /home/mark/PROJECT/PKIX/pkix-difftest/python/.venv/bin/python3 gen.py
"""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import NameOID, ObjectIdentifier

NOT_BEFORE = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2050, 1, 1, tzinfo=datetime.timezone.utc)

REG_ID = ObjectIdentifier("1.2.3.4")
OTHER_ID = ObjectIdentifier("1.2.3.5")
# id-on-SmtpUTF8Mailbox (RFC 8398 §3).
SMTP_UTF8_MAILBOX = ObjectIdentifier("1.3.6.1.5.5.7.8.9")


def utf8_string(text):
    """DER UTF8String, the encoding RFC 8398 §3 requires for the value."""
    body = text.encode("utf-8")
    assert len(body) < 0x80, "short form only; these fixtures are small"
    return bytes([0x0C, len(body)]) + body
# DER INTEGER 7 -- deliberately not a UTF8String, so a mailbox reading of
# this otherName fails rather than matching.
OTHER_VALUE = bytes([0x02, 0x01, 0x07])

CA_KEY_USAGE = x509.KeyUsage(
    digital_signature=False,
    content_commitment=False,
    key_encipherment=False,
    data_encipherment=False,
    key_agreement=False,
    key_cert_sign=True,
    crl_sign=True,
    encipher_only=False,
    decipher_only=False,
)


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def write(fname, cert):
    path = Path(__file__).resolve().parent / fname
    path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    print(f"wrote {path.name} ({path.stat().st_size} bytes)")


def main():
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = name("NC Forms Root")
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(0x1001)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(CA_KEY_USAGE, critical=True)
        .sign(root_key, hashes.SHA256())
    )
    write("root.der", root)

    def ca(cn, serial, permitted, excluded=None):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(name(cn))
            .issuer_name(root_name)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(NOT_BEFORE)
            .not_valid_after(NOT_AFTER)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0), critical=True
            )
            .add_extension(CA_KEY_USAGE, critical=True)
            .add_extension(
                x509.NameConstraints(
                    permitted_subtrees=permitted, excluded_subtrees=excluded
                ),
                critical=True,
            )
            .sign(root_key, hashes.SHA256())
        )
        return key, cert

    regid_key, ca_regid = ca("NC Forms CA RegId", 0x1002, [x509.RegisteredID(REG_ID)])
    dns_key, ca_dns = ca(
        "NC Forms CA Dns", 0x1003, [x509.DNSName("example.com")]
    )
    rfc822_key, ca_rfc822 = ca(
        "NC Forms CA Rfc822", 0x1004, [x509.RFC822Name("example.com")]
    )
    write("ca-regid.der", ca_regid)
    write("ca-dns.der", ca_dns)
    write("ca-rfc822.der", ca_rfc822)

    def leaf(cn, serial, issuer_cert, issuer_key, sans, subject=None):
        key = ec.generate_private_key(ec.SECP256R1())
        return (
            x509.CertificateBuilder()
            .subject_name(subject or name(cn))
            .issuer_name(issuer_cert.subject)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(NOT_BEFORE)
            .not_valid_after(NOT_AFTER)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .sign(issuer_key, hashes.SHA256())
        )

    write(
        "leaf-regid-under-regid.der",
        leaf("NC Forms Leaf A", 0x1005, ca_regid, regid_key, [x509.RegisteredID(REG_ID)]),
    )
    write(
        "leaf-regid-under-dns.der",
        leaf("NC Forms Leaf B", 0x1006, ca_dns, dns_key, [x509.RegisteredID(REG_ID)]),
    )
    write(
        "leaf-othername-under-rfc822.der",
        leaf(
            "NC Forms Leaf C",
            0x1007,
            ca_rfc822,
            rfc822_key,
            [x509.OtherName(OTHER_ID, OTHER_VALUE)],
        ),
    )


    # An emailAddress attribute encoded as UTF8String. PKCS #9 defines it
    # as IA5String, so pkix-path cannot check it against an rfc822Name
    # constraint and fails closed -- but only when such a constraint is in
    # effect. Under the dNSName-only CA nothing constrains mailboxes, the
    # RDN walk must not run, and the certificate is accepted. The guard that
    # decides is `forms_in_effect.intersects(RFC822) && !subject_is_empty`.
    #
    # An emailAddress carried as UTF8String is a known CA misissuance rather
    # than an invented shape.
    write(
        "leaf-utf8-email-under-dns.der",
        leaf(
            "NC Forms Leaf D",
            0x1008,
            ca_dns,
            dns_key,
            [x509.DNSName("example.com")],
            subject=x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "NC Forms Leaf D"),
                    x509.NameAttribute(
                        NameOID.EMAIL_ADDRESS,
                        "leaf-d@example.com",
                        _type=_ASN1Type.UTF8String,
                    ),
                ]
            ),
        ),
    )


    # ------------------------------------------------------------------
    # Excluded subtrees: where failing to evaluate means failing to
    # EXCLUDE.
    #
    # Under a permitted subtree an unevaluable form is refused twice
    # over: step (0) refuses it, and if step (0) did not, the generic
    # permitted check refuses it too, because a name the matchers cannot
    # decide matches no subtree and a constrained type that matches
    # nothing is a violation. So `leaf-regid-under-regid` above cannot
    # tell whether step (0) ran.
    #
    # An excluded subtree inverts that. The generic excluded check asks
    # whether the name matches a subtree, and a name the matchers cannot
    # decide matches none -- so it raises no violation and the
    # certificate passes. Only step (0) stands between a CA that said
    # "never this registeredID" and a certificate carrying exactly it.
    # ------------------------------------------------------------------
    excl_regid_key, ca_excl_regid = ca(
        "NC Forms CA Excl RegId", 0x1009, None, [x509.RegisteredID(REG_ID)]
    )
    write("ca-excl-regid.der", ca_excl_regid)
    write(
        "leaf-regid-under-excl-regid.der",
        leaf(
            "NC Forms Leaf E",
            0x100A,
            ca_excl_regid,
            excl_regid_key,
            [x509.RegisteredID(REG_ID)],
        ),
    )

    # The same inversion for the RFC 8398 mailbox path. A
    # SmtpUTF8Mailbox otherName is routed to the rfc822Name subtrees, and
    # its domain part must be ASCII to be compared with one; a U-label
    # domain cannot be, so the check fails closed.
    #
    # Neither mailbox below is under `example.com`, so neither matches
    # the exclusion. That is deliberate: the pair differs only in
    # whether the domain is ASCII, which is the one thing under test.
    # Were the domain a subdomain of the excluded one, the comparison
    # would refuse it anyway and the fixture would prove nothing.
    excl_rfc822_key, ca_excl_rfc822 = ca(
        "NC Forms CA Excl Rfc822", 0x100B, None, [x509.RFC822Name("example.com")]
    )
    write("ca-excl-rfc822.der", ca_excl_rfc822)
    for fname, serial, mailbox in (
        ("leaf-utf8mb-ascii-under-excl-rfc822.der", 0x100C, "leaf-f@other.example"),
        ("leaf-utf8mb-nonascii-under-excl-rfc822.der", 0x100D, "leaf-g@\u00f6ther.example"),
    ):
        write(
            fname,
            leaf(
                f"NC Forms Leaf {chr(0x46 + serial - 0x100C)}",
                serial,
                ca_excl_rfc822,
                excl_rfc822_key,
                [x509.OtherName(SMTP_UTF8_MAILBOX, utf8_string(mailbox))],
            ),
        )


if __name__ == "__main__":
    main()
