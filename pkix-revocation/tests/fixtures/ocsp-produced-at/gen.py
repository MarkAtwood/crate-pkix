#!/usr/bin/env python3
"""
A delegated OCSP response whose `producedAt` sits exactly on a responder
certificate's validity edge.

WHAT THE RULE IS
----------------
RFC 6960 §4.2.2.2 requires the delegated responder's certificate to have
been valid when the response was produced. `validate_delegate_responder_cert`
enforces it as

    if produced_at_unix < nb || produced_at_unix > na

and a certificate validity period is inclusive at both ends (RFC 5280
§4.1.2.5), so `producedAt` equal to `notBefore` or to `notAfter` is valid.
Neither comparison was pinned: `<` read as `<=` or `==`, and `>` read as
`>=`, all refuse a response produced on an edge, and nothing noticed
because `producedAt` in every other fixture here is the wall-clock second
the fixture was generated -- months away from any edge.

WHY THESE NEED A GENERATOR OF THEIR OWN
---------------------------------------
`cryptography`'s OCSP builder does not take `producedAt`; OpenSSL fills it
in with the current time at signing. `../ocsp-delegated-good.der` carries
`2026-05-08 20:05:11` for exactly that reason. So the value cannot be
chosen through the builder -- but it can be written. Each response below
is built, then its `ResponseData` is rebuilt at the DER level with
`producedAt` replaced, then re-signed with the responder key this script
holds, which is the same surgery `../../gen_ocsp_delegated_fixtures.py`
could not do and `pkix-path/tests/fixtures/dup-ext/gen.py` established.

  ca.der              the CA that issues the leaf and both responders
  leaf.der            the certificate the responses are about

  at-not-before.der       producedAt == responder notBefore      accept
  before-not-before.der   producedAt == notBefore - 1 second     refuse
  at-not-after.der        producedAt == responder notAfter       accept
  after-not-after.der     producedAt == notAfter + 1 second      refuse

Two responder certificates, four responses. Within each pair everything
is identical but one second of `producedAt`, which is what makes these a
test of the comparison and not of anything else. Both responder
certificates carry the id-kp-OCSPSigning EKU and are signed by `ca.der`,
so checks (a), (b) and (d) pass and (c) is the only one in question.

`producedAt` stays at or below the tests' NOW (2026-06-01), because a
response claiming to be produced in the future is refused earlier as
malformed.

Usage: python3 gen.py   (run from this directory; needs `cryptography`)
"""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OUT = Path(__file__).resolve().parent
UTC = datetime.timezone.utc

# The edge every fixture is positioned around. Before the tests' NOW
# (2026-06-01) and after thisUpdate, so only check (c) is in play.
EDGE = datetime.datetime(2026, 2, 1, tzinfo=UTC)
SECOND = datetime.timedelta(seconds=1)

THIS_UPDATE = datetime.datetime(2026, 1, 1, tzinfo=UTC)
NEXT_UPDATE = datetime.datetime(2027, 1, 1, tzinfo=UTC)
CA_NOT_BEFORE = datetime.datetime(2024, 1, 1, tzinfo=UTC)
CA_NOT_AFTER = datetime.datetime(2030, 1, 1, tzinfo=UTC)

TAG_GENERALIZED_TIME = 0x18


# --- minimal DER TLV helpers ------------------------------------------------


def read_tlv(buf, i=0):
    """Return (tag, content_bytes, index_after)."""
    tag = buf[i]
    i += 1
    n = buf[i]
    i += 1
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(buf[i : i + k], "big")
        i += k
    return tag, buf[i : i + n], i + n


def children(content):
    out, i = [], 0
    while i < len(content):
        tag, body, i = read_tlv(content, i)
        out.append((tag, body))
    return out


def enc(tag, content):
    n = len(content)
    if n < 0x80:
        head = bytes([tag, n])
    else:
        nb = n.to_bytes((n.bit_length() + 7) // 8, "big")
        head = bytes([tag, 0x80 | len(nb)]) + nb
    return head + content


def generalized_time(when):
    """DER GeneralizedTime: YYYYMMDDHHMMSSZ, as RFC 6960 requires."""
    return enc(TAG_GENERALIZED_TIME, when.strftime("%Y%m%d%H%M%SZ").encode("ascii"))


# --- the surgery ------------------------------------------------------------


def set_produced_at(response_der, responder_key, when):
    """Re-emit `response_der` with `producedAt` set to `when`.

    OCSPResponse wraps a ResponseBytes whose OCTET STRING holds a
    BasicOCSPResponse, whose first field is the signed ResponseData. The
    third field of ResponseData is `producedAt`: version is `[0]` and
    OPTIONAL with a DEFAULT, so it is located by tag rather than by index.
    """
    _, outer, _ = read_tlv(response_der)
    status_tag, status_body = children(outer)[0]
    bytes_tag, bytes_body = children(outer)[1]
    assert bytes_tag == 0xA0, f"expected [0] responseBytes, found {bytes_tag:#x}"
    # [0] is EXPLICIT, so its content is the ResponseBytes SEQUENCE itself.
    seq_tag, rbytes_body = children(bytes_body)[0]
    assert seq_tag == 0x30, f"expected a ResponseBytes SEQUENCE, found {seq_tag:#x}"
    rtype_tag, rtype_body = children(rbytes_body)[0]
    octet_tag, basic_der = children(rbytes_body)[1]
    assert octet_tag == 0x04, f"expected an OCTET STRING, found {octet_tag:#x}"

    _, basic_body, _ = read_tlv(basic_der)
    basic = children(basic_body)
    _, rdata_body = basic[0]
    sigalg_tag, sigalg_body = basic[1]
    certs = basic[3:]

    fields = children(rdata_body)
    at = next(i for i, (t, _) in enumerate(fields) if t == TAG_GENERALIZED_TIME)
    old = fields[at][1].decode("ascii")
    fields[at] = (TAG_GENERALIZED_TIME, generalized_time(when)[2:])
    new_rdata = enc(0x30, b"".join(enc(t, b) for t, b in fields))

    # Re-sign: the signature covers the DER of ResponseData, which just
    # changed. sha256WithRSAEncryption, matching the signatureAlgorithm
    # left in place below.
    sig = responder_key.sign(new_rdata, padding.PKCS1v15(), hashes.SHA256())
    new_basic = enc(
        0x30,
        new_rdata
        + enc(sigalg_tag, sigalg_body)
        + enc(0x03, b"\x00" + sig)
        + b"".join(enc(t, b) for t, b in certs),
    )
    rebuilt = enc(
        0x30,
        enc(status_tag, status_body)
        + enc(0xA0, enc(0x30, enc(rtype_tag, rtype_body) + enc(0x04, new_basic))),
    )

    # Confirm it round-trips, says what it was asked to say, and that the
    # new signature verifies under the embedded responder certificate --
    # the splice is worthless if the response no longer authenticates,
    # and `validate_delegate_responder_cert` would then be refusing it
    # for the wrong reason.
    parsed = ocsp.load_der_ocsp_response(rebuilt)
    want = when.replace(tzinfo=None)
    assert parsed.produced_at == want, f"{parsed.produced_at} != {want}"
    parsed.certificates[0].public_key().verify(
        sig, new_rdata, padding.PKCS1v15(), hashes.SHA256()
    )
    print(f"      producedAt {old} -> {when.strftime('%Y%m%d%H%M%SZ')}, signature OK")
    return rebuilt


# --- the chain --------------------------------------------------------------


def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def dn(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


ca_key = rsa_key()
ca_name = dn("OCSP producedAt CA")
ca = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_key.public_key())
    .serial_number(1)
    .not_valid_before(CA_NOT_BEFORE)
    .not_valid_after(CA_NOT_AFTER)
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(ca_key, hashes.SHA256())
)

leaf_key = rsa_key()
leaf = (
    x509.CertificateBuilder()
    .subject_name(dn("OCSP producedAt leaf"))
    .issuer_name(ca_name)
    .public_key(leaf_key.public_key())
    .serial_number(2)
    .not_valid_before(CA_NOT_BEFORE)
    .not_valid_after(CA_NOT_AFTER)
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .sign(ca_key, hashes.SHA256())
)


def responder(cn, serial, not_before, not_after):
    key = rsa_key()
    cert = (
        x509.CertificateBuilder()
        .subject_name(dn(cn))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert, key


def response(responder_cert, responder_key, produced_at):
    built = (
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
        .responder_id(ocsp.OCSPResponderEncoding.NAME, responder_cert)
        .certificates([responder_cert])
        .sign(responder_key, hashes.SHA256())
    )
    return set_produced_at(
        built.public_bytes(serialization.Encoding.DER), responder_key, produced_at
    )


# `starts_at_edge` begins on EDGE, so producedAt == notBefore is its lower
# edge. `ends_at_edge` ends on EDGE, so producedAt == notAfter is its upper
# one. Neither window is degenerate: each is years wide, and only the one
# edge under test is at EDGE.
starts_at_edge, starts_key = responder("OCSP responder from edge", 3, EDGE, CA_NOT_AFTER)
ends_at_edge, ends_key = responder("OCSP responder until edge", 4, CA_NOT_BEFORE, EDGE)

files = {
    "ca.der": ca.public_bytes(serialization.Encoding.DER),
    "leaf.der": leaf.public_bytes(serialization.Encoding.DER),
    "at-not-before.der": (starts_at_edge, starts_key, EDGE),
    "before-not-before.der": (starts_at_edge, starts_key, EDGE - SECOND),
    "at-not-after.der": (ends_at_edge, ends_key, EDGE),
    "after-not-after.der": (ends_at_edge, ends_key, EDGE + SECOND),
}
for fname, spec in files.items():
    print(f"  {fname}:")
    data = spec if isinstance(spec, bytes) else response(*spec)
    (OUT / fname).write_bytes(data)
    print(f"      {len(data)} bytes")
