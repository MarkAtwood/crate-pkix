#!/usr/bin/env python3
"""A pre-2050 date encoded as GeneralizedTime: what `tbs_certificate_der` is for.

WHAT THE RULE IS
----------------
RFC 5280 §4.1.2.5 says a validity time before 2050 MUST be encoded as
UTCTime and one from 2050 on as GeneralizedTime. Every certificate in this
workspace follows it, which is why the function that exists for the
violation had nothing to exercise it.

`x509-cert` re-encodes a parsed `Certificate` under that profile, so a
pre-2050 date it read from a GeneralizedTime comes back out as a UTCTime.
Those are different bytes, and the issuer signed the bytes it wrote. So
`cert.tbs_certificate().to_der()` yields a TBSCertificate whose signature
no longer checks, and `pkix_path::tbs_certificate_der` exists to return
the bytes as they were parsed instead.

A certificate of this shape is non-conformant and real: a CA that wrote a
2026 date as GeneralizedTime produces one, and refusing its signature is a
validation failure for a certificate that is otherwise fine.

  utctime-control.der    self-signed, both times UTCTime -- conformant, and
                         the case where the two encodings agree
  gentime-both.der       the same certificate with notBefore and notAfter
                         re-tagged as GeneralizedTime
  gentime-not-before.der only notBefore re-tagged, the mixed form a CA with
                         one bad code path actually emits

`cryptography` will not emit these -- it follows §4.1.2.5 -- so each is
built by rebuilding the TBSCertificate at the DER level with the time
re-tagged and then signing the rebuilt bytes, the same surgery as
`../dup-ext/gen.py`. Signing after the splice matters: path validation
checks the signature before anything else, so an unsigned splice would be
refused for the wrong reason.

Each certificate is self-signed, so the key inside it verifies the
signature on it and the fixture carries its own oracle. The signed bytes
are written out next to it as `<name>-tbs.bin`, and `gen.py` checks the
signature over them before writing either file.

Usage: python3 gen.py   (run from this directory; needs `cryptography`)
"""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

OUT = Path(__file__).parent
# Both before 2050, so §4.1.2.5 requires UTCTime for both and the re-tagged
# forms are the violation this directory is about.
NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2036, 1, 1, tzinfo=datetime.timezone.utc)

TAG_UTC_TIME = 0x17
TAG_GENERALIZED_TIME = 0x18


# --- minimal DER TLV helpers (same shape as ../dup-ext/gen.py) --------------


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


def to_generalized(tag, body):
    """Re-tag one `Time` as GeneralizedTime, widening its year to four digits.

    UTCTime content is `YYMMDDHHMMSSZ` and GeneralizedTime's is
    `YYYYMMDDHHMMSSZ`. RFC 5280 §4.1.2.5.1 reads a two-digit year below 50
    as 20YY, which is the only range these fixtures use.
    """
    assert tag == TAG_UTC_TIME, f"expected UTCTime, found tag {tag:#x}"
    text = body.decode("ascii")
    assert len(text) == 13 and text.endswith("Z"), f"unexpected UTCTime {text!r}"
    year = int(text[:2])
    assert year < 50, "these fixtures are all 20YY"
    return TAG_GENERALIZED_TIME, f"20{text}".encode("ascii")


def tbs_of(der):
    """The TBSCertificate TLV of a certificate, as bytes: what was signed."""
    _, cert_body, _ = read_tlv(der)
    tag, body = children(cert_body)[0]
    return enc(tag, body)


def retag_validity(cert, signing_key, which):
    """Re-emit `cert` with the named validity times as GeneralizedTime.

    `which` is a set of indices into the validity SEQUENCE: 0 is notBefore
    and 1 is notAfter.
    """
    der = cert.public_bytes(serialization.Encoding.DER)
    _, cert_body, _ = read_tlv(der)
    tbs_tag, tbs_body = children(cert_body)[0]
    sigalg_tag, sigalg_body = children(cert_body)[1]

    fields = children(tbs_body)
    # v3 TBSCertificate: [0] version, serialNumber, signature, issuer,
    # validity, subject, subjectPublicKeyInfo, ... -- validity is index 4
    # whenever the version field is present, which it is for every v3
    # certificate `cryptography` emits.
    assert fields[0][0] == 0xA0, "expected [0] version as the first field"
    times = children(fields[4][1])
    assert len(times) == 2, f"validity holds two times, found {len(times)}"
    new_times = [
        to_generalized(*t) if i in which else t for i, t in enumerate(times)
    ]
    new_fields = list(fields)
    new_fields[4] = (0x30, b"".join(enc(t, b) for t, b in new_times))
    new_tbs_body = b"".join(enc(t, b) for t, b in new_fields)
    new_tbs = enc(tbs_tag, new_tbs_body)

    sig = signing_key.sign(new_tbs, ec.ECDSA(hashes.SHA256()))
    return enc(
        0x30,
        new_tbs + enc(sigalg_tag, sigalg_body) + enc(0x03, b"\x00" + sig),
    )


key = ec.generate_private_key(ec.SECP256R1())
subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PKIX gentime")])

control = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(subject)
    .public_key(key.public_key())
    .serial_number(1)
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
    .sign(key, hashes.SHA256())
)

certs = {
    "utctime-control": control.public_bytes(serialization.Encoding.DER),
    "gentime-both": retag_validity(control, key, {0, 1}),
    "gentime-not-before": retag_validity(control, key, {0}),
}

for stem, der in certs.items():
    # The signed bytes alongside each certificate. The test compares what
    # `tbs_certificate_der` returns against these rather than re-deriving
    # them, so the oracle is the generator that signed them.
    tbs = tbs_of(der)
    key.public_key().verify(
        children(read_tlv(der)[1])[2][1][1:], tbs, ec.ECDSA(hashes.SHA256())
    )
    for fname, data in ((f"{stem}.der", der), (f"{stem}-tbs.bin", tbs)):
        (OUT / fname).write_bytes(data)
        print(f"  wrote {fname} ({len(data)} bytes)")
