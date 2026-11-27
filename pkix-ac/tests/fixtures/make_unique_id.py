#!/usr/bin/env python3
"""
An attribute authority certificate carrying `subjectUniqueID`.

WHAT THE RULE IS
----------------
RFC 5755 §4.2.8: an AC's `issuerUniqueID` "MUST NOT be used unless it is
also used in the AC issuer's PKC, in which case it MUST be used". The
authority is the subject of its own certificate, so the field to compare
against is that certificate's `subjectUniqueID` -- and "in which case it
MUST be used" means used with the same value, or the field identifies
nothing.

`verify` decides it with a four-arm match on the two optionals. Three of
the arms had no fixture, because no certificate in this directory carries
a `subjectUniqueID`: the authority certificates come from `make_aa.sh`
and OpenSSL will not emit the field, `cryptography` will not either, and
`ac-issuer-unique-id.der` was only ever offered to an authority that has
none. So the guard could answer "always equal" or "never equal" and the
suite would not notice -- and "always equal" accepts an AC naming an
authority identifier that is not this authority's.

  aa-unique-id-cert.der   aa-cert.der with subjectUniqueID 2a2b2c

`subjectUniqueID` is `[2] IMPLICIT UniqueIdentifier` in TBSCertificate,
between `subjectPublicKeyInfo` and the `[3]` extensions, so it is spliced
in at that position and the TBSCertificate re-signed with the root key
this workspace already commits.

Re-signing matters, and the public key is what makes it possible. The
splice leaves the `subjectPublicKeyInfo` untouched, so the authority's
key is unchanged and every AC signed with `aa-key.pem` still verifies
against this certificate -- while the certificate itself remains properly
issued by the same root rather than carrying a signature it has
invalidated.

The value 2a2b2c is the one `gen.py` puts in `ac-issuer-unique-id.der`,
so that certificate is the matching case and needs no change.

Usage: python3 make_unique_id.py   (run from this directory)
"""

from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

HERE = Path(__file__).resolve().parent
ROOT_KEY = HERE / "../../../pkix-ct/tests/fixtures/sct-oracle/precert-issuer-key.pem"

# The same bytes gen.py writes into ac-issuer-unique-id.der.
UNIQUE_ID = bytes([0x2A, 0x2B, 0x2C])
# And into ac-holder-base-cert-id-uid.der. Deliberately different from
# UNIQUE_ID: the authority's identifier and the holder's PKC issuer's
# identifier are unrelated fields, and sharing a value would let a test
# pass that compared the wrong pair.
HOLDER_UNIQUE_ID = bytes([0x3A, 0x3B, 0x3C])


def read_tlv(buf, i=0):
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


def main():
    der = (HERE / "aa-cert.der").read_bytes()
    _, cert_body, _ = read_tlv(der)
    outer = children(cert_body)
    tbs_tag, tbs_body = outer[0]
    sigalg_tag, sigalg_body = outer[1]

    fields = children(tbs_body)
    # [3] extensions is the last field whenever it is present, and
    # subjectUniqueID goes immediately before it.
    assert fields[-1][0] == 0xA3, f"expected [3] extensions last, found {fields[-1][0]:#x}"
    assert not any(t == 0x82 for t, _ in fields), "already carries a subjectUniqueID"

    # [2] IMPLICIT UniqueIdentifier: the context tag replaces the BIT
    # STRING's own, so the content is the BIT STRING's -- a leading
    # unused-bit count of zero, then the value.
    subject_unique_id = enc(0x82, b"\x00" + UNIQUE_ID)
    new_fields = fields[:-1] + [(0x82, subject_unique_id[2:]), fields[-1]]
    new_tbs = enc(tbs_tag, b"".join(enc(t, b) for t, b in new_fields))

    key = serialization.load_pem_private_key(ROOT_KEY.read_bytes(), password=None)
    sig = key.sign(new_tbs, ec.ECDSA(hashes.SHA256()))
    rebuilt = enc(
        0x30,
        new_tbs + enc(sigalg_tag, sigalg_body) + enc(0x03, b"\x00" + sig),
    )

    (HERE / "aa-unique-id-cert.der").write_bytes(rebuilt)
    print(f"wrote aa-unique-id-cert.der ({len(rebuilt)} bytes)")

    # The splice is worthless unless the result is a sound certificate
    # that carries what it was supposed to and still holds the same key.
    from cryptography import x509

    before = x509.load_der_x509_certificate(der)
    after = x509.load_der_x509_certificate(rebuilt)
    key.public_key().verify(
        after.signature, after.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256())
    )
    assert after.subject == before.subject, "same authority"
    assert after.public_key().public_numbers() == before.public_key().public_numbers(), (
        "same key, so ACs signed with aa-key.pem still verify"
    )
    assert read_tlv(rebuilt)[1], "non-empty"
    spliced = [t for t, _ in children(children(read_tlv(rebuilt)[1])[0][1])]
    assert 0x82 in spliced, "subjectUniqueID present"
    print("signature verifies, subject and key unchanged, subjectUniqueID present")


def splice_issuer_unique_id():
    """The holder certificate with `issuerUniqueID`, for §4.2.2's
    `baseCertificateID.issuerUID`.

    "The AC holder.baseCertificateID.issuerUID field MUST only be used if
    the holder's PKC contains an issuerUniqueID field. If both ... are
    present, the same value MUST be present in both fields." The borrowed
    holder certificate has no issuerUniqueID, so the comparison had
    nothing to compare and could answer either way.

    `issuerUniqueID` is `[1] IMPLICIT`, before `[2] subjectUniqueID` and
    the `[3]` extensions. Re-signed by the issuer that issued it, whose
    key this workspace commits; the subject, issuer, serial and key are
    all left alone, so the certificate still answers every other question
    the same way.
    """
    leaf = HERE / "../../../pkix-ct/tests/fixtures/sct-oracle/precert-leaf-final.der"
    der = leaf.read_bytes()
    _, cert_body, _ = read_tlv(der)
    outer = children(cert_body)
    tbs_tag, tbs_body = outer[0]
    sigalg_tag, sigalg_body = outer[1]

    fields = children(tbs_body)
    assert fields[-1][0] == 0xA3, "expected [3] extensions last"
    assert not any(t == 0x81 for t, _ in fields), "already carries an issuerUniqueID"
    issuer_unique_id = enc(0x81, b"\x00" + HOLDER_UNIQUE_ID)
    new_fields = fields[:-1] + [(0x81, issuer_unique_id[2:]), fields[-1]]
    new_tbs = enc(tbs_tag, b"".join(enc(t, b) for t, b in new_fields))

    key = serialization.load_pem_private_key(ROOT_KEY.read_bytes(), password=None)
    sig = key.sign(new_tbs, ec.ECDSA(hashes.SHA256()))
    rebuilt = enc(
        0x30,
        new_tbs + enc(sigalg_tag, sigalg_body) + enc(0x03, b"\x00" + sig),
    )
    (HERE / "holder-unique-id-cert.der").write_bytes(rebuilt)
    print(f"wrote holder-unique-id-cert.der ({len(rebuilt)} bytes)")

    from cryptography import x509

    before = x509.load_der_x509_certificate(der)
    after = x509.load_der_x509_certificate(rebuilt)
    key.public_key().verify(
        after.signature, after.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256())
    )
    assert after.subject == before.subject, "same holder"
    assert after.issuer == before.issuer, "same issuer, so baseCertificateID still names it"
    assert after.serial_number == before.serial_number, "and the same serial"
    spliced = [t for t, _ in children(children(read_tlv(rebuilt)[1])[0][1])]
    assert 0x81 in spliced, "issuerUniqueID present"
    print("signature verifies, issuer and serial unchanged, issuerUniqueID present")


if __name__ == "__main__":
    main()
    splice_issuer_unique_id()
