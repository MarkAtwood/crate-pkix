#!/usr/bin/env python3
"""
A chain padded with self-issued CA certificates, for the two length bounds
in `validate_path`.

WHAT THE BOUNDS ARE
-------------------
RFC 5280 §4.2.1.9 counts only non-self-issued intermediates against
`pathLenConstraint`, so a chain may legitimately be longer than
`max_path_len` suggests: a CA re-certifying itself under a new key adds a
certificate that costs nothing against the limit. `validate_path` therefore
applies two bounds:

  * a cheap one on `chain.len()` before anything super-linear, against
    `max_chain_certs(max_path_len)` = 2 * max_path_len + 3;
  * the §4.2.1.9 one on the non-self-issued intermediate count.

Both report `Error::PathTooLong`, which is why a fixture has to be built to
separate them: a chain refused by the second tells you nothing about the
first. Telling them apart needs a chain whose *length* sits at the cheap
bound while its non-self-issued count stays inside the §4.2.1.9 one, and
that means self-issued padding.

  root        self-signed anchor
  ca          issued by root, key K0 -- the one non-self-issued intermediate
  si1..si4    subject and issuer both `ca`'s DN, keys K1..K4, each signed by
              the one before
  leaf5       signed by K3, for a five-certificate chain
  leaf6       signed by K4, for a six-certificate chain

At `max_path_len = 1` the cheap bound is five. The five-certificate chain
sits exactly on it and must validate; the six-certificate chain is one past
it and must not. Between them they pin the comparison and the arithmetic
that produces the bound -- `2 * n + 3` read as `2 * n * 3` or `2 + n + 3`
moves the bound to six either way.

Every CA is unconstrained by its own basicConstraints, so the policy's
`max_path_len` is the only limit in play.

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


def ca_cert(subject, issuer, pubkey, signing_key, serial):
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pubkey)
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(CA_KEY_USAGE, critical=True)
        .sign(signing_key, hashes.SHA256())
    )


def main():
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = name("Chain Length Root")
    root = ca_cert(root_name, root_name, root_key.public_key(), root_key, 0x3001)
    write("root.der", root)

    ca_name = name("Chain Length CA")
    keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(5)]  # K0..K4

    # K0's certificate is issued by the root, so it is the one
    # non-self-issued intermediate.
    write("ca.der", ca_cert(ca_name, root_name, keys[0].public_key(), root_key, 0x3002))

    # K1..K4 each re-certify the same CA DN under a new key, signed by the
    # key before. Subject and issuer are both the CA's DN, which is what
    # makes them self-issued and free against pathLenConstraint.
    for i in range(1, 5):
        write(
            f"si{i}.der",
            ca_cert(
                ca_name, ca_name, keys[i].public_key(), keys[i - 1], 0x3002 + i
            ),
        )

    def leaf(cn, serial, signing_key):
        key = ec.generate_private_key(ec.SECP256R1())
        return (
            x509.CertificateBuilder()
            .subject_name(name(cn))
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(NOT_BEFORE)
            .not_valid_after(NOT_AFTER)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .sign(signing_key, hashes.SHA256())
        )

    write("leaf5.der", leaf("Chain Length Leaf 5", 0x3010, keys[3]))
    write("leaf6.der", leaf("Chain Length Leaf 6", 0x3011, keys[4]))


if __name__ == "__main__":
    main()
