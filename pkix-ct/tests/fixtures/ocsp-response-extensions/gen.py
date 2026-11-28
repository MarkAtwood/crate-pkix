#!/usr/bin/env python3
"""
An OCSP response carrying its SCT list in top-level `responseExtensions`.

WHAT THE RULE IS
----------------
RFC 6962 §3.3 delivers SCTs over OCSP in the
`1.3.6.1.4.1.11129.2.4.5` extension, and RFC 6960 §4.2.1 gives a
response two places to put an extension: `singleExtensions`, inside the
`SingleResponse` for one certificate, and `responseExtensions`, at the
top of the `ResponseData`. `sct_list_from_ocsp_response` looks in the
first and then falls back to the second.

`../resp-sct-extension.der` -- the real-world fixture borrowed from
pyca's vectors -- carries its four SCTs in `singleExtensions`, so the
fallback branch had no test at all. Not merely its OID comparison: the
whole branch. A responder that puts the list at the top level would have
its SCTs silently ignored, and the caller would see a certificate with no
CT evidence rather than one with four SCTs.

  with-sct.der      SCT list in responseExtensions, and one other
                    extension before it
  without-sct.der   the same response with only the other extension,
                    so "no SCT list" is distinguishable from "wrong
                    branch"

The nonce extension comes first on purpose. The branch scans for the SCT
OID, and with that comparison negated it matches the first extension
that is *not* the SCT list -- so a response whose only top-level
extension were the SCT list would fall through to `None` either way,
while this one tries to parse a nonce as an SCT list.

The SCT list itself is one SCT taken from `../sct-oracle/sct.bin`, so
its fields are the ones that fixture's own tests already pin.

`sct_list_from_ocsp_response` verifies no signature -- extracting the
list is a parsing step, and the caller validates the response
separately -- but this is signed properly anyway, with a key generated
here, so the fixture is a response and not a shape that happens to
parse.

Usage: python3 gen.py   (run from this directory; needs `cryptography`)
"""

import datetime
import struct
from pathlib import Path

from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

HERE = Path(__file__).resolve().parent
ORACLE_SCT = HERE / "../sct-oracle/sct.bin"

UTC = datetime.timezone.utc
NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=UTC)
NOT_AFTER = datetime.datetime(2036, 1, 1, tzinfo=UTC)
THIS_UPDATE = datetime.datetime(2026, 1, 2, tzinfo=UTC)
NEXT_UPDATE = datetime.datetime(2026, 2, 1, tzinfo=UTC)

# RFC 6962 §3.3: the OCSP delivery OID.
SCT_OCSP_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.5")
# RFC 6960 §4.4.1 Nonce, used here only as a second extension so the
# scan has something wrong to find.
OCSP_NONCE_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.48.1.2")


def der_octet_string(body):
    n = len(body)
    if n < 0x80:
        return bytes([0x04, n]) + body
    be = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x04, 0x80 | len(be)]) + be + body


def sct_list_extension_value(scts_wire):
    """RFC 6962 §3.3 SignedCertificateTimestampList, DER-wrapped.

    `UnrecognizedExtension` takes the payload that goes inside the
    extension's own extnValue OCTET STRING, so the list is wrapped once
    here and once by the builder.
    """
    inner = bytearray()
    for sct in scts_wire:
        inner += struct.pack(">H", len(sct)) + sct
    return der_octet_string(bytes(struct.pack(">H", len(inner)) + inner))


def dn(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def main():
    sct_wire = ORACLE_SCT.read_bytes()

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_dn = dn("pkix-ct ocsp responder CA")
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_dn)
        .issuer_name(ca_dn)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(dn("pkix-ct ocsp subject"))
        .issuer_name(ca_dn)
        .public_key(leaf_key.public_key())
        .serial_number(2)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .sign(ca_key, hashes.SHA256())
    )

    nonce = x509.UnrecognizedExtension(
        OCSP_NONCE_OID, der_octet_string(bytes(range(16)))
    )

    def build(extensions):
        b = (
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
        )
        for ext in extensions:
            b = b.add_extension(ext, False)
        return b.sign(ca_key, hashes.SHA256())

    sct_ext = x509.UnrecognizedExtension(
        SCT_OCSP_OID, sct_list_extension_value([sct_wire])
    )

    with_sct = build([nonce, sct_ext])
    without_sct = build([nonce])

    for name, resp in (("with-sct.der", with_sct), ("without-sct.der", without_sct)):
        der = resp.public_bytes(serialization.Encoding.DER)
        (HERE / name).write_bytes(der)
        print(f"wrote {name} ({len(der)} bytes)")

    # The placement is the whole point, so assert it rather than trust
    # the builder: the SCT list must be at the top level and nowhere in
    # any SingleResponse.
    top = [e.oid.dotted_string for e in with_sct.extensions]
    assert SCT_OCSP_OID.dotted_string in top, f"SCT list must be top-level; got {top}"
    assert top.index(OCSP_NONCE_OID.dotted_string) < top.index(
        SCT_OCSP_OID.dotted_string
    ), "the nonce must come first, so a negated scan finds it"
    assert not list(with_sct.single_extensions), "and nothing in singleExtensions"
    assert SCT_OCSP_OID.dotted_string not in [
        e.oid.dotted_string for e in without_sct.extensions
    ], "the control carries no SCT list"
    print("placement checks passed")


if __name__ == "__main__":
    main()
