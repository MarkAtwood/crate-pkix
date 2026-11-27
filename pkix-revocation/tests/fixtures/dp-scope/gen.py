#!/usr/bin/env python3
"""
RFC 5280 §6.3.3(b)(1) distribution-point scope: the two cases where the
distribution point names agree and the CRL still does not apply.

WHAT THE RULES ARE
------------------
`check_dp_scope` walks a certificate's `cRLDistributionPoints` and asks, per
distribution point, which DN issues its CRLs. Two match guards decide that,
and both are reachable only when the names would otherwise intersect -- so a
fixture where the names differ proves nothing about either.

  1. A distribution point with no `cRLIssuer` speaks for the certificate's
     own issuer, and only for it. `None if names_match(crl_issuer,
     cert_issuer)`. Without the guard, such a distribution point vouches for
     whatever CRL is presented, and an indirect CRL from an unrelated CA
     counts as in scope.

  2. A distribution point that does name a `cRLIssuer` speaks only for an
     indirect CRL. `Some(dn) if crl_is_indirect`. RFC 5280 ties `cRLIssuer`
     to indirect CRLs; without the guard a direct CRL claims the scope of
     one.

WHY THE URIs MATCH ON PURPOSE
-----------------------------
Both pairs here name the same distribution point, `http://crl.example/a.crl`.
That is what makes the guards load-bearing: with the names agreeing, the
issuer question is the only thing left to refuse on, and a weakened guard
returns `Ok(())` instead of `OutOfScope`. Differing names would be refused
by the name half of the rule whatever the guards did.

  ca-a                       the issuer of both leaves
  ca-b                       an unrelated CA
  leaf-dp-no-crlissuer       CDP: distributionPoint, no cRLIssuer
  leaf-dp-with-crlissuer     CDP: distributionPoint + cRLIssuer = CA-A
  indirect-crl-from-b        CRL by CA-B, IDP indirectCRL + same DP name
  direct-crl-from-a          CRL by CA-A, IDP same DP name, not indirect
  leaf-dp-dirname            CDP: distributionPoint is a directoryName
  direct-crl-from-a-dirname  CRL by CA-A, IDP names the same DN in another
                             case

THE directoryName PAIR
----------------------
`general_name_matches` compares two `GeneralName`s, and the reason it is not
just `PartialEq` is `directoryName`: DNs compare under RFC 4518 string prep,
not byte for byte. Every other distribution point here is a URI, which takes
the derived comparison, so nothing exercised the DN arm. The pair above names
one DN in two cases: equal under the rule, different as DER.

`crl_applies_to` is a pure scope predicate and verifies no signature, but
the CRLs are signed properly anyway so they stay usable if a later test
wants to drive them through `CrlChecker`.

Oracle: pyca/cryptography. The Rust predicate never participates.

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
CRL_THIS = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
CRL_NEXT = datetime.datetime(2050, 1, 1, tzinfo=datetime.timezone.utc)

DP_URI = "http://crl.example/a.crl"

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


def ca(subject, key, serial):
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(CA_KEY_USAGE, critical=True)
        .sign(key, hashes.SHA256())
    )


def leaf(
    subject_cn,
    issuer_name,
    issuer_key,
    leaf_key,
    serial,
    crl_issuer_name,
    dp_name=None,
):
    dp = x509.DistributionPoint(
        full_name=[dp_name or x509.UniformResourceIdentifier(DP_URI)],
        relative_name=None,
        crl_issuer=(
            [x509.DirectoryName(crl_issuer_name)] if crl_issuer_name is not None else None
        ),
        reasons=None,
    )
    return (
        x509.CertificateBuilder()
        .subject_name(name(subject_cn))
        .issuer_name(issuer_name)
        .public_key(leaf_key.public_key())
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.CRLDistributionPoints([dp]), critical=False)
        .sign(issuer_key, hashes.SHA256())
    )


def crl(issuer_name, key, indirect, dp_name=None):
    return (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_name)
        .last_update(CRL_THIS)
        .next_update(CRL_NEXT)
        .add_extension(
            x509.IssuingDistributionPoint(
                only_contains_user_certs=False,
                only_contains_ca_certs=False,
                indirect_crl=indirect,
                only_contains_attribute_certs=False,
                only_some_reasons=None,
                full_name=[dp_name or x509.UniformResourceIdentifier(DP_URI)],
                relative_name=None,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )


def write(fname, der):
    path = Path(__file__).resolve().parent / fname
    path.write_bytes(der)
    print(f"wrote {path.name} ({path.stat().st_size} bytes)")


def main():
    a_key = ec.generate_private_key(ec.SECP256R1())
    b_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())

    a_name = name("DP Scope CA A")
    b_name = name("DP Scope CA B")

    ca_a = ca(a_name, a_key, 0xD001)
    ca_b = ca(b_name, b_key, 0xD002)

    write("ca-a.der", ca_a.public_bytes(serialization.Encoding.DER))
    write("ca-b.der", ca_b.public_bytes(serialization.Encoding.DER))
    write(
        "leaf-dp-no-crlissuer.der",
        leaf("DP Scope Leaf Plain", a_name, a_key, leaf_key, 0xD003, None).public_bytes(
            serialization.Encoding.DER
        ),
    )
    write(
        "leaf-dp-with-crlissuer.der",
        leaf(
            "DP Scope Leaf Named", a_name, a_key, leaf_key, 0xD004, a_name
        ).public_bytes(serialization.Encoding.DER),
    )
    write(
        "indirect-crl-from-b.der",
        crl(b_name, b_key, True).public_bytes(serialization.Encoding.DER),
    )
    write(
        "direct-crl-from-a.der",
        crl(a_name, a_key, False).public_bytes(serialization.Encoding.DER),
    )

    # A directoryName distribution point, named in two encodings that
    # RFC 4518 case folding makes equal.
    write(
        "leaf-dp-dirname.der",
        leaf(
            "DP Scope Leaf DirName",
            a_name,
            a_key,
            leaf_key,
            0xD005,
            None,
            dp_name=x509.DirectoryName(name("dp scope point")),
        ).public_bytes(serialization.Encoding.DER),
    )
    write(
        "direct-crl-from-a-dirname.der",
        crl(
            a_name,
            a_key,
            False,
            dp_name=x509.DirectoryName(name("DP Scope Point")),
        ).public_bytes(serialization.Encoding.DER),
    )


if __name__ == "__main__":
    main()
