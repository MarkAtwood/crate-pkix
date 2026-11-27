#!/usr/bin/env python3
"""
Base and delta CRLs with deliberately chosen numbers, for RFC 5280 §5.2.4.

WHAT THE RULE IS
----------------
A delta CRL's `deltaCRLIndicator` names the `cRLNumber` of the base it
updates, and `CrlChecker::with_delta` refuses the pair when the delta
expects a base newer than the one supplied: `delta_base_num > base_num`.

The existing `delta-crl-*` fixtures are a matching pair -- base
cRLNumber 1, delta BaseCRLNumber 1 -- which satisfies the comparison without
distinguishing it from any other. Every mutant in the three functions that
read these numbers survived: `uint_to_u64` returning a constant, `crl_number`
returning `None` or a constant, `base_crl_number` the same. A delta that
expects a newer base than it was given would have been applied.

  base-5          cRLNumber 5
  delta-base-3    BaseCRLNumber 3  -- older base is fine, 3 <= 5
  delta-base-9    BaseCRLNumber 9  -- newer base expected, must be refused

THE EIGHT-BYTE CASE
-------------------
`uint_to_u64` refuses an INTEGER longer than eight bytes, because that is
where a u64 stops. The rustdoc says a cRLNumber above 2^64 "must not
silently disable the staleness check", so it becomes a parse error rather
than a skipped comparison. Nothing tested either side of that boundary, and
the numbers in the existing fixtures are one byte long.

  base-2pow56     cRLNumber 2^56, encoded in exactly eight bytes -- fits
  base-2pow64     cRLNumber 2^64, encoded in nine -- does not
  delta-base-1    BaseCRLNumber 1, to pair with either

DER strips leading zeros from an INTEGER, so 2^56 is the smallest value
whose encoding reaches eight bytes and 2^64 the smallest that reaches nine.

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

ISSUER_CN = "Delta Number Test CA"


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def write(fname, der):
    path = Path(__file__).resolve().parent / fname
    path.write_bytes(der)
    print(f"wrote {path.name} ({path.stat().st_size} bytes)")


def main():
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = name(ISSUER_CN)

    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(0xE001)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    def crl(extension, critical):
        return (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca_name)
            .last_update(CRL_THIS)
            .next_update(CRL_NEXT)
            .add_extension(extension, critical=critical)
            .sign(ca_key, hashes.SHA256())
        )

    def base(number):
        return crl(x509.CRLNumber(number), False)

    def delta(base_number):
        # RFC 5280 §5.2.4: deltaCRLIndicator MUST be critical.
        return crl(x509.DeltaCRLIndicator(base_number), True)

    write("ca.der", ca.public_bytes(serialization.Encoding.DER))
    for label, number in [("5", 5), ("2pow56", 2**56), ("2pow64", 2**64)]:
        write(f"base-{label}.der", base(number).public_bytes(serialization.Encoding.DER))
    for number in (1, 3, 9):
        write(
            f"delta-base-{number}.der",
            delta(number).public_bytes(serialization.Encoding.DER),
        )


if __name__ == "__main__":
    main()
