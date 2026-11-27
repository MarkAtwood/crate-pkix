#!/usr/bin/env python3
"""
An OCSP response whose `thisUpdate` is later than its `producedAt`.

WHY THIS FIXTURE HAS TO EXIST
-----------------------------
`OcspChecker` refuses a response on three freshness grounds, in order:
`now < producedAt`, `now < thisUpdate`, `now > nextUpdate`. For any
response a conformant responder would issue, `producedAt >= thisUpdate`
(RFC 6960 §4.2.2.1: `thisUpdate` is when the status was known correct,
`producedAt` when the response was signed), so `now < thisUpdate` implies
`now < producedAt` and the first check always fires first. The second one
is then unreachable, and a mutation to its comparison cannot be caught by
any conformant fixture -- every response in `../` is generated with
`producedAt` at generation time and `thisUpdate` in the past.

The check is still live, for a response no conformant responder would
issue: `thisUpdate` in the future relative to `producedAt`. A responder
that emits one is claiming to describe a status it cannot have observed
yet, and the window it declares must still be honoured rather than
ignored. This fixture is that response, so the rule has a test.

The dates are absolute rather than relative to generation time: a window
that moved with the fixture would drift out from under the assertions.

Oracle: pyca/cryptography. The Rust checker never participates.

Run from this directory:

    /home/mark/PROJECT/PKIX/pkix-difftest/python/.venv/bin/python3 gen.py
"""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID

# Both after any plausible generation time, so producedAt < thisUpdate.
THIS_UPDATE = datetime.datetime(2027, 6, 1, tzinfo=datetime.timezone.utc)
NEXT_UPDATE = datetime.datetime(2028, 6, 1, tzinfo=datetime.timezone.utc)

NOT_BEFORE = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2050, 1, 1, tzinfo=datetime.timezone.utc)


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def write(fname, der):
    path = Path(__file__).resolve().parent / fname
    path.write_bytes(der)
    print(f"wrote {path.name} ({path.stat().st_size} bytes)")


def main():
    ca_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = name("OCSP Future ThisUpdate CA")

    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(0xA001)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    leaf = (
        x509.CertificateBuilder()
        .subject_name(name("OCSP Future ThisUpdate Leaf"))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(0xA002)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    response = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=leaf,
            issuer=ca,
            algorithm=hashes.SHA256(),
            cert_status=ocsp.OCSPCertStatus.GOOD,
            this_update=THIS_UPDATE,
            next_update=NEXT_UPDATE,
            revocation_time=None,
            revocation_reason=None,
        )
        .responder_id(ocsp.OCSPResponderEncoding.NAME, ca)
        .sign(ca_key, hashes.SHA256())
    )

    write("ca.der", ca.public_bytes(serialization.Encoding.DER))
    write("leaf.der", leaf.public_bytes(serialization.Encoding.DER))
    write("response.der", response.public_bytes(serialization.Encoding.DER))


if __name__ == "__main__":
    main()
