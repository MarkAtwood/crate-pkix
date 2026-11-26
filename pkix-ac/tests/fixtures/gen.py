#!/usr/bin/env python3
"""Build RFC 5755 attribute certificates.

Why this is hand-rolled DER
---------------------------
Neither OpenSSL nor pyca/cryptography can create an attribute
certificate — they model public-key certificates, CRLs and requests, and
so does `x509-cert`, which is why `pkix-ac` declares the ASN.1 itself.
That leaves no independent tool to generate fixtures with, so they are
assembled here from the productions in RFC 5755 Appendix A and signed
with a real key by `openssl dgst`.

The consequence is worth stating plainly: this generator is not an
independent oracle the way `pkix-ct`'s pyca-based ones are. It and the
Rust parser could in principle share a misreading of the spec. What it
does establish is that the parser reads bytes laid out the way the RFC
says, and that signature verification works over a signature a separate
tool produced. The ASN.1 here was transcribed from rfc5755.txt, whose
module is DEFINITIONS IMPLICIT TAGS — so every context tag below is
implicit, and a reader checking this against RFC 5280 habits will think
some of them are wrong.

Key and names are borrowed from the pkix-ct oracle fixtures rather than
generated, so the AA has a certificate that `pkix-path` can validate.

Run:  python3 gen.py
"""
import pathlib
import subprocess
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
CT = HERE.parent.parent.parent / "pkix-ct" / "tests" / "fixtures" / "sct-oracle"
AA_CERT = CT / "precert-issuer.der"
AA_KEY = CT / "precert-issuer-key.pem"
LEAF_CERT = CT / "precert-leaf-final.der"

# ---------------------------------------------------------------- DER ---


def tlv(tag: int, body: bytes) -> bytes:
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    n = (len(body).bit_length() + 7) // 8
    return bytes([tag, 0x80 | n]) + len(body).to_bytes(n, "big") + body


def seq(*parts: bytes) -> bytes:
    return tlv(0x30, b"".join(parts))


def integer(n: int) -> bytes:
    if n == 0:
        return tlv(0x02, b"\x00")
    b = n.to_bytes((n.bit_length() + 8) // 8, "big")
    return tlv(0x02, b)


def oid(dotted: str) -> bytes:
    parts = [int(x) for x in dotted.split(".")]
    out = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append((p & 0x7F) | 0x80)
            p >>= 7
        out += bytes(reversed(chunk))
    return tlv(0x06, out)


def gen_time(s: str) -> bytes:
    """GeneralizedTime. RFC 5755 §4.1 requires seconds and Z."""
    assert len(s) == 15 and s.endswith("Z"), s
    return tlv(0x18, s.encode())


def bitstring(b: bytes) -> bytes:
    return tlv(0x03, b"\x00" + b)


def read_len(b: bytes, i: int):
    first = b[i + 1]
    if first < 0x80:
        return first, 2
    n = first & 0x7F
    return int.from_bytes(b[i + 2 : i + 2 + n], "big"), 2 + n


def tbs_field(cert: bytes, index: int) -> bytes:
    """The index-th field of a TBSCertificate, as bytes.

    0 = version, 1 = serial, 2 = sigalg, 3 = issuer, 4 = validity,
    5 = subject, 6 = spki. Used to lift real X.501 Names out of the
    borrowed certificates instead of constructing new ones.
    """
    cv, ch = read_len(cert, 0)
    body = cert[ch : ch + cv]
    tv, th = read_len(body, 0)
    tbs = body[th : th + tv]
    off, out = 0, []
    while off < len(tbs):
        vlen, hlen = read_len(tbs, off)
        out.append(tbs[off : off + hlen + vlen])
        off += hlen + vlen
    return out[index]


# ------------------------------------------------------- RFC 5755 ------

# ecdsa-with-SHA256, matching the borrowed P-256 AA key.
ECDSA_SHA256 = seq(oid("1.2.840.10045.4.3.2"))
# id-at-role, RFC 5755 §4.4.5.
ID_AT_ROLE = "2.5.4.72"


def general_name_directory(name_der: bytes) -> bytes:
    """GeneralName directoryName [4]. EXPLICIT because Name is a CHOICE."""
    return tlv(0xA4, name_der)


def general_names(*names: bytes) -> bytes:
    return seq(*names)


def role_attribute(role_uri: str) -> bytes:
    """A Role attribute — RFC 5755 §4.4.5.

    Role ::= SEQUENCE { roleAuthority [0] GeneralNames OPTIONAL,
                        roleName      [1] GeneralName }
    roleName is a uniformResourceIdentifier [6], which §4.4.5 says
    SHOULD be used.
    """
    role_name = tlv(0x86, role_uri.encode())  # [6] IMPLICIT IA5String
    role = seq(tlv(0xA1, role_name))  # [1] holding the GeneralName
    return seq(oid(ID_AT_ROLE), tlv(0x31, role))  # SET OF AttributeValue


def acinfo(holder_name: bytes, issuer_name: bytes, serial: int,
           not_before: str, not_after: str, attrs: bytes) -> bytes:
    version = integer(1)  # AttCertVersion v2
    # IMPLICIT tagging: [1] REPLACES the SEQUENCE OF tag of GeneralNames,
    # so the GeneralName sits directly inside [1] with no inner SEQUENCE.
    # Wrapping one in — the explicit reading, and the RFC 5280 habit —
    # produces a structure one level too deep that no conforming parser
    # will read.
    holder = seq(tlv(0xA1, general_name_directory(holder_name)))
    # Likewise [0] replaces V2Form's own SEQUENCE tag. What remains
    # inside is V2Form's first field, issuerName, which is untagged and
    # so keeps its SEQUENCE OF tag.
    issuer = tlv(0xA0, general_names(general_name_directory(issuer_name)))
    validity = seq(gen_time(not_before), gen_time(not_after))
    return seq(version, holder, issuer, ECDSA_SHA256, integer(serial),
               validity, attrs)


def sign(data: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as td:
        p = pathlib.Path(td) / "acinfo.der"
        p.write_bytes(data)
        return subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(AA_KEY), str(p)],
            check=True, capture_output=True).stdout


def attribute_certificate(info: bytes) -> bytes:
    return seq(info, ECDSA_SHA256, bitstring(sign(info)))


def main() -> None:
    aa = AA_CERT.read_bytes()
    leaf = LEAF_CERT.read_bytes()
    aa_subject = tbs_field(aa, 5)
    leaf_subject = tbs_field(leaf, 5)

    # The ordinary case: one Role attribute, holder named by
    # entityName, issuer in v2Form with a directoryName. Valid for the
    # same window the borrowed certificates use.
    info = acinfo(leaf_subject, aa_subject, 0x2A,
                  "20250101000000Z", "20260101000000Z",
                  seq(role_attribute("urn:example:role:auditor")))
    (HERE / "ac-role-valid.der").write_bytes(attribute_certificate(info))

    # Two attributes, to pin that `attributes` is a SEQUENCE OF and the
    # parser keeps the order.
    info = acinfo(leaf_subject, aa_subject, 0x2B,
                  "20250101000000Z", "20260101000000Z",
                  seq(role_attribute("urn:example:role:auditor"),
                      role_attribute("urn:example:role:approver")))
    (HERE / "ac-two-roles.der").write_bytes(attribute_certificate(info))

    # Expired: notAfter in the past, everything else identical. For the
    # validity check, not the parser.
    info = acinfo(leaf_subject, aa_subject, 0x2C,
                  "20200101000000Z", "20210101000000Z",
                  seq(role_attribute("urn:example:role:auditor")))
    (HERE / "ac-expired.der").write_bytes(attribute_certificate(info))

    for f in sorted(HERE.glob("ac-*.der")):
        print(f"{f.name}: {f.stat().st_size} bytes")


if __name__ == "__main__":
    main()
