#!/usr/bin/env python3
"""
An indirect CRL and two candidate cRLIssuer certificates that differ only
in the `cRLSign` KeyUsage bit.

WHAT THE RULE IS
----------------
RFC 5280 §6.3.3(f): a CRL issuer that has a KeyUsage extension MUST assert
`cRLSign`. `check_crl_sign` enforces it, and it only ever runs on the
separate cRLIssuer certificate -- the direct case checks the certificate's
own issuer, which is trusted to sign its own CRL, and the anchor case
skips it because an anchor is trusted by construction. So the rule is
reachable only through an indirect CRL, and nothing in the suite built
one with a non-conforming signer. `Error::CrlSignMissing` had no test at
all: the whole check could return `Ok(())` unnoticed, and an indirect CRL
signed by a certificate not authorised to sign CRLs would be accepted.

WHY TWO CERTIFICATES WITH ONE KEY
---------------------------------
`crl-issuer-with-crlsign` and `crl-issuer-no-crlsign` share a subject DN
*and* a public key, so the same CRL verifies under either and the
KeyUsage bit is the only thing that differs between the accepting and the
refusing case. Anything else -- a different key, a different name --
would be rejected a step earlier and the KeyUsage check would decide
nothing.

Oracle: pyca/cryptography. The Rust checker never participates.

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


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def key_usage(crl_sign):
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=crl_sign,
        encipher_only=False,
        decipher_only=False,
    )


def write(fname, der):
    path = Path(__file__).resolve().parent / fname
    path.write_bytes(der)
    print(f"wrote {path.name} ({path.stat().st_size} bytes)")


def main():
    ca_key = ec.generate_private_key(ec.SECP256R1())
    crl_issuer_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())

    ca_name = name("Indirect CRL Test CA")
    crl_issuer_name = name("Indirect CRL Issuer")

    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(0xB001)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(key_usage(True), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    def crl_issuer_cert(serial, crl_sign):
        return (
            x509.CertificateBuilder()
            .subject_name(crl_issuer_name)
            .issuer_name(ca_name)
            .public_key(crl_issuer_key.public_key())
            .serial_number(serial)
            .not_valid_before(NOT_BEFORE)
            .not_valid_after(NOT_AFTER)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .add_extension(key_usage(crl_sign), critical=True)
            .sign(ca_key, hashes.SHA256())
        )

    leaf = (
        x509.CertificateBuilder()
        .subject_name(name("Indirect CRL Leaf"))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(0xB004)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    # Empty CRL: the leaf is not revoked, so the accepting case returns Ok
    # and the refusing case cannot be mistaken for a revocation.
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(crl_issuer_name)
        .last_update(CRL_THIS)
        .next_update(CRL_NEXT)
        .add_extension(
            x509.IssuingDistributionPoint(
                only_contains_user_certs=False,
                only_contains_ca_certs=False,
                indirect_crl=True,
                only_contains_attribute_certs=False,
                only_some_reasons=None,
                full_name=None,
                relative_name=None,
            ),
            critical=True,
        )
        .sign(crl_issuer_key, hashes.SHA256())
    )

    write("ca.der", ca.public_bytes(serialization.Encoding.DER))
    write("leaf.der", leaf.public_bytes(serialization.Encoding.DER))
    write(
        "crl-issuer-with-crlsign.der",
        crl_issuer_cert(0xB002, True).public_bytes(serialization.Encoding.DER),
    )
    write(
        "crl-issuer-no-crlsign.der",
        crl_issuer_cert(0xB003, False).public_bytes(serialization.Encoding.DER),
    )
    write("indirect-crl.der", crl.public_bytes(serialization.Encoding.DER))


if __name__ == "__main__":
    main()
