#!/usr/bin/env python3
"""Fixtures for RFC 5280 4.2 duplicate-extension rejection.

"A certificate MUST NOT include more than one instance of a particular
extension."  `check_duplicate_extensions` enforces it and had no test and no
fixture: the whole function could be deleted, and mutating its `exts.len() < 2`
early return to `<= 2` or `== 2` -- which lets a certificate with EXACTLY two
extensions, both the same OID, through -- left the suite green.

`cryptography` refuses to build such a certificate ("This extension has
already been set"), correctly.  So the TBSCertificate is rebuilt here at the
DER level with one extension duplicated, and then re-signed, because
chain_walk verifies the signature before it looks at extensions -- an
unsigned splice would be rejected for the wrong reason.

  dup-ext-root.der   self-signed CA, anchor
  dup-ext-leaf.der   leaf with basicConstraints appearing TWICE
  dup-ext-ok.der     the same leaf with the duplicate removed, as a control
"""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID

OUT = Path(__file__).parent
NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2036, 1, 1, tzinfo=datetime.timezone.utc)


# --- minimal DER TLV helpers ------------------------------------------------

def read_tlv(buf, i=0):
    """Return (tag, content_bytes, index_after)."""
    tag = buf[i]
    i += 1
    n = buf[i]
    i += 1
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(buf[i:i + k], "big")
        i += k
    return tag, buf[i:i + n], i + n


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


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


# --- build the chain --------------------------------------------------------

root_key = ec.generate_private_key(ec.SECP256R1())
leaf_key = ec.generate_private_key(ec.SECP256R1())
root_name = name("PKIX dup-ext root")

root = (
    x509.CertificateBuilder()
    .subject_name(root_name)
    .issuer_name(root_name)
    .public_key(root_key.public_key())
    .serial_number(1)
    .not_valid_before(NOT_BEFORE)
    .not_valid_after(NOT_AFTER)
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(
        x509.KeyUsage(
            digital_signature=False, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=True, crl_sign=True, encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    .sign(root_key, hashes.SHA256())
)

# A leaf with exactly ONE extension, so duplicating it yields exactly two --
# the width at which the `< 2` early return's mutations become visible.
leaf_ok = (
    x509.CertificateBuilder()
    .subject_name(name("PKIX dup-ext leaf"))
    .issuer_name(root_name)
    .public_key(leaf_key.public_key())
    .serial_number(2)
    .not_valid_before(NOT_BEFORE)
    .not_valid_after(NOT_AFTER)
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .sign(root_key, hashes.SHA256())
)


def duplicate_first_extension(cert, signing_key):
    """Re-emit `cert` with its first extension present twice."""
    der = cert.public_bytes(serialization.Encoding.DER)
    _, cert_body, _ = read_tlv(der)
    tbs_tag, tbs_body = children(cert_body)[0]
    sigalg_tag, sigalg_body = children(cert_body)[1]

    fields = children(tbs_body)
    # extensions are [3] EXPLICIT, the last field of a v3 TBSCertificate.
    assert fields[-1][0] == 0xA3, "expected [3] extensions as the last field"
    ext_seq_tag, ext_seq_body = children(fields[-1][1])[0]
    exts = children(ext_seq_body)
    assert len(exts) == 1, f"fixture expects one extension, found {len(exts)}"
    first = enc(*exts[0])
    new_ext_seq = enc(0x30, first + first)
    new_fields = fields[:-1] + [(0xA3, new_ext_seq)]
    new_tbs_body = b"".join(enc(t, b) for t, b in new_fields)
    new_tbs = enc(tbs_tag, new_tbs_body)

    sig = signing_key.sign(new_tbs, ec.ECDSA(hashes.SHA256()))
    return enc(
        0x30,
        new_tbs + enc(sigalg_tag, sigalg_body) + enc(0x03, b"\x00" + sig),
    )


leaf_dup = duplicate_first_extension(leaf_ok, root_key)

files = {
    "dup-ext-root.der": root.public_bytes(serialization.Encoding.DER),
    "dup-ext-ok.der": leaf_ok.public_bytes(serialization.Encoding.DER),
    "dup-ext-leaf.der": leaf_dup,
}
for fname, data in files.items():
    (OUT / fname).write_bytes(data)
    print(f"  wrote {fname} ({len(data)} bytes)")
