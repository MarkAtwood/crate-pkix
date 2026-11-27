#!/usr/bin/env python3
"""
Two CAs in one path whose name constraints have to be combined, in the
shapes where the combining code's deduplication decides the answer.

WHAT THE RULES ARE
------------------
RFC 5280 §6.1.4(g): permitted subtrees intersect down the path, excluded
subtrees union. `chain_walk` does both, and each keeps a set free of
duplicates -- where "duplicate" means two entries of the same name form
that contain each other. Both of those dedup tests are three-part
conjunctions, and loosening either part changes which subtrees survive.

permitted-*: THE INTERSECTION DROPS THE WRONG ENTRY
---------------------------------------------------
  ca-specific  permits dNSName sub.a.example, then dNSName a.example
  ca-broad     permits dNSName example
  leaf-other-a      SAN dNSName other.a.example -- permitted
  leaf-other-example SAN dNSName host.other.example -- inside `example`,
                    outside both of ca-specific's entries, so refused

The order in `ca-specific` is load-bearing. Intersecting against the
broader `example` keeps both of its entries, and the second one --
`a.example` -- is reached with `sub.a.example` already in the result. The
two are the same name form and one contains the other in one direction
only, which is exactly the input that tells a two-way containment test from
a one-way one or from a bare same-form test.

Drop `a.example` and the permitted set shrinks to `sub.a.example`, so
`other.a.example` stops being permitted although both CAs allow it.

excluded-*: THE UNION DROPS AN EXCLUSION
----------------------------------------
  ca-excl-a   excludes dNSName a.example
  ca-excl-b   excludes dNSName b.example
  leaf-in-b   SAN dNSName host.b.example

Two different exclusions of the same name form. Treat "same form" as
"already present" and the second CA's exclusion is discarded, which is the
fail-open direction: a name the path excludes becomes permitted.

  ca-excl-sub     excludes dNSName sub.bad.example
  ca-excl-bad     excludes dNSName bad.example
  leaf-other-bad  SAN dNSName other.bad.example

The nested pair, for the other half of the same conjunction. Here the two
exclusions contain each other in one direction only, so a containment test
satisfied by either direction discards the broader one -- and
`other.bad.example` is under the broader exclusion and outside the
narrower, so it becomes permitted.

Oracle: pyca/cryptography. The Rust validator never participates.

Run from this directory:

    /home/mark/PROJECT/PKIX/pkix-difftest/python/.venv/bin/python3 gen.py
"""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

NOT_BEFORE = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2050, 1, 1, tzinfo=datetime.timezone.utc)

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
    root_name = name("NC Intersect Root")
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(0x2001)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(CA_KEY_USAGE, critical=True)
        .sign(root_key, hashes.SHA256())
    )
    write("root.der", root)

    def ca(cn, serial, issuer_name, issuer_key, path_length, permitted, excluded):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(name(cn))
            .issuer_name(issuer_name)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(NOT_BEFORE)
            .not_valid_after(NOT_AFTER)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=path_length), critical=True
            )
            .add_extension(CA_KEY_USAGE, critical=True)
            .add_extension(
                x509.NameConstraints(
                    permitted_subtrees=permitted, excluded_subtrees=excluded
                ),
                critical=True,
            )
            .sign(issuer_key, hashes.SHA256())
        )
        return key, cert

    def leaf(cn, serial, issuer_cert, issuer_key, dns):
        key = ec.generate_private_key(ec.SECP256R1())
        return (
            x509.CertificateBuilder()
            .subject_name(name(cn))
            .issuer_name(issuer_cert.subject)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(NOT_BEFORE)
            .not_valid_after(NOT_AFTER)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(dns)]), critical=False
            )
            .sign(issuer_key, hashes.SHA256())
        )

    # The permitted-intersection chain. sub.a.example comes first so that
    # a.example is considered with it already in the result set.
    specific_key, ca_specific = ca(
        "NC Intersect CA Specific",
        0x2002,
        root_name,
        root_key,
        1,
        [x509.DNSName("sub.a.example"), x509.DNSName("a.example")],
        None,
    )
    broad_key, ca_broad = ca(
        "NC Intersect CA Broad",
        0x2003,
        ca_specific.subject,
        specific_key,
        0,
        [x509.DNSName("example")],
        None,
    )
    write("ca-specific.der", ca_specific)
    write("ca-broad.der", ca_broad)
    write(
        "leaf-other-a.der",
        leaf("NC Intersect Leaf A", 0x2004, ca_broad, broad_key, "other.a.example"),
    )
    # The control for the intersection: inside ca-broad's `example` but
    # outside both of ca-specific's entries, so the intersection refuses it.
    # Without it, a validator that had stopped applying permitted subtrees
    # would satisfy the test above.
    write(
        "leaf-other-example.der",
        leaf("NC Intersect Leaf C", 0x2008, ca_broad, broad_key, "host.other.example"),
    )

    # The excluded-union chain.
    excl_a_key, ca_excl_a = ca(
        "NC Intersect CA Excl A",
        0x2005,
        root_name,
        root_key,
        1,
        None,
        [x509.DNSName("a.example")],
    )
    excl_b_key, ca_excl_b = ca(
        "NC Intersect CA Excl B",
        0x2006,
        ca_excl_a.subject,
        excl_a_key,
        0,
        None,
        [x509.DNSName("b.example")],
    )
    write("ca-excl-a.der", ca_excl_a)
    write("ca-excl-b.der", ca_excl_b)
    write(
        "leaf-in-b.der",
        leaf("NC Intersect Leaf B", 0x2007, ca_excl_b, excl_b_key, "host.b.example"),
    )

    # The nested-exclusion chain. Two exclusions of one name form where one
    # contains the other in a single direction, which is what separates a
    # two-way containment test from a one-way one. The broader exclusion
    # arrives second, so dropping it as a duplicate lets everything under it
    # but outside the narrower one through.
    excl_sub_key, ca_excl_sub = ca(
        "NC Intersect CA Excl Sub",
        0x2009,
        root_name,
        root_key,
        1,
        None,
        [x509.DNSName("sub.bad.example")],
    )
    excl_bad_key, ca_excl_bad = ca(
        "NC Intersect CA Excl Bad",
        0x200A,
        ca_excl_sub.subject,
        excl_sub_key,
        0,
        None,
        [x509.DNSName("bad.example")],
    )
    write("ca-excl-sub.der", ca_excl_sub)
    write("ca-excl-bad.der", ca_excl_bad)
    write(
        "leaf-other-bad.der",
        leaf("NC Intersect Leaf D", 0x200B, ca_excl_bad, excl_bad_key, "other.bad.example"),
    )


if __name__ == "__main__":
    main()
