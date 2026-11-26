#!/usr/bin/env python3
"""Certificates that an X.509 re-encoder does not reproduce.

Why these exist
---------------
RFC 6962 §3.2 signs the bytes a log was given. `pkix-ct` reconstructs
those bytes to check a `precert_entry` SCT, and it used to do that by
parsing the certificate into `x509-cert` types and asking them to
encode themselves again. That is only faithful if the encoder
reproduces its input exactly, and an encoder is under no obligation to.

Both certificates here are well-formed DER that a CA could emit and a
log would sign, and for both the re-encode differs from the original.
Measured with x509-cert 0.3 / der 0.8:

  leaf-generalizedtime-notbefore.der
      notBefore as a GeneralizedTime before 2050. RFC 5280 §4.1.2.5
      says a CA MUST use UTCTime there, and x509-cert's own encoder
      normalises it. `pkix_path::encode_tbs_certificate` exists as a
      hand-written patch for precisely this case and does preserve it.

  leaf-unsorted-rdn.der
      A subject RDN whose SET OF members are not in the order DER
      requires. x509-cert parses it and re-sorts on encode, and
      `encode_tbs_certificate` does NOT patch around that, so the
      reconstruction came out wrong: a valid SCT failed as
      InvalidSignature, with nothing to point at the encoder. This is
      the case that made the re-encoding approach untenable rather
      than merely risky.

Both are derived from `sct-oracle/precert-leaf-final.der` by byte-level
surgery, recomputing the enclosing lengths. Neither is generated with
pyca/cryptography: its builder emits canonical DER, which is the whole
thing these fixtures are not. Their signatures are therefore invalid
and nothing verifies them — they exist to be reconstructed.

Alongside each certificate this writes `<stem>-tbs-no-sct.bin`: the
TBSCertificate with the SCT-list extension removed, stripped here in
Python so that the Rust implementation is compared against something
that did not come from it.
"""
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
SRC = HERE.parent / "sct-oracle" / "precert-leaf-final.der"
SCT_LIST_OID = bytes([0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x04, 0x02])


def read_len(b, i):
    """Return (value_len, header_len) for the TLV starting at b[i]."""
    first = b[i + 1]
    if first < 0x80:
        return first, 2
    n = first & 0x7F
    assert 1 <= n <= 4, f"unsupported length form {first:#x}"
    return int.from_bytes(b[i + 2 : i + 2 + n], "big"), 2 + n


def enc_len(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag, body):
    return bytes([tag]) + enc_len(len(body)) + body


def tlvs(b):
    """Offsets and sizes of the TLVs tiling b: (offset, tag, hlen, vlen)."""
    out, i = [], 0
    while i < len(b):
        vlen, hlen = read_len(b, i)
        out.append((i, b[i], hlen, vlen))
        i += hlen + vlen
    return out


def split_cert(der):
    """(tbs_body, cert_tail) — the TBS contents and what follows it."""
    cv, ch = read_len(der, 0)
    assert der[0] == 0x30
    cert_body = der[ch : ch + cv]
    tv, th = read_len(cert_body, 0)
    assert cert_body[0] == 0x30
    return cert_body[th : th + tv], cert_body[th + tv :]


def rebuild(tbs_body, cert_tail):
    cert_body = tlv(0x30, tbs_body) + cert_tail
    return tlv(0x30, cert_body)


def tbs_fields(tbs_body):
    """TBS fields, with the index of serialNumber returned alongside."""
    fields = tlvs(tbs_body)
    base = 1 if fields[0][1] == 0xA0 else 0
    assert fields[base][1] == 0x02, "serialNumber"
    return fields, base


def generalizedtime_notbefore(tbs_body):
    """Rewrite notBefore from UTCTime to a pre-2050 GeneralizedTime."""
    fields, base = tbs_fields(tbs_body)
    off, tag, hlen, vlen = fields[base + 3]
    assert tag == 0x30, f"validity should be a SEQUENCE, got {tag:#x}"
    validity = tbs_body[off + hlen : off + hlen + vlen]

    nb_off, nb_tag, nb_hlen, nb_vlen = tlvs(validity)[0]
    assert nb_tag == 0x17, f"expected a UTCTime notBefore, got {nb_tag:#x}"
    utc = validity[nb_off + nb_hlen : nb_off + nb_hlen + nb_vlen].decode("ascii")
    assert len(utc) == 13 and utc.endswith("Z"), utc
    # YYMMDDHHMMSSZ -> YYYYMMDDHHMMSSZ, on the RFC 5280 §4.1.2.5 pivot.
    century = "19" if int(utc[:2]) >= 50 else "20"
    gen = (century + utc).encode("ascii")

    new_validity = tlv(0x18, gen) + validity[nb_off + nb_hlen + nb_vlen :]
    return (
        tbs_body[:off] + tlv(0x30, new_validity) + tbs_body[off + hlen + vlen :],
        f"notBefore {utc} (UTCTime) -> {gen.decode()} (GeneralizedTime)",
    )


def unsorted_rdn(tbs_body):
    """Add a second attribute to a subject RDN, out of DER order."""
    fields, base = tbs_fields(tbs_body)
    off, tag, hlen, vlen = fields[base + 4]
    assert tag == 0x30, f"subject should be a SEQUENCE, got {tag:#x}"
    subject = tbs_body[off + hlen : off + hlen + vlen]

    r_off, r_tag, r_hlen, r_vlen = tlvs(subject)[0]
    assert r_tag == 0x31, f"an RDN must be a SET, got {r_tag:#x}"
    rdn = subject[r_off + r_hlen : r_off + r_hlen + r_vlen]
    attrs = tlvs(rdn)
    assert len(attrs) == 1, "expected a single-valued RDN to extend"
    a_off, _, a_hlen, a_vlen = attrs[0]
    existing = rdn[a_off : a_off + a_hlen + a_vlen]

    # AttributeTypeAndValue ::= SEQUENCE { type OID, value } — an
    # organizationalUnitName (2.5.4.11) of "zz".
    ou = tlv(0x30, bytes([0x06, 0x03, 0x55, 0x04, 0x0B]) + tlv(0x13, b"zz"))
    # X.690 §11.6: SET OF members are sorted ascending by their
    # encodings. Emitting them the other way round is what makes this
    # fixture non-canonical.
    assert ou < existing, f"expected {ou.hex()} to sort first"
    new_rdn = tlv(0x31, existing + ou)

    new_subject = new_rdn + subject[r_off + r_hlen + r_vlen :]
    return (
        tbs_body[:off] + tlv(0x30, new_subject) + tbs_body[off + hlen + vlen :],
        "subject RDN holds two attributes in non-canonical SET OF order",
    )


def strip_sct_list(tbs_body):
    """The TBS with its SCT-list extension removed, at the byte level."""
    fields = tlvs(tbs_body)
    ext = [f for f in fields if f[1] == 0xA3]
    assert len(ext) == 1, "expected one [3] EXPLICIT extensions field"
    off, tag, hlen, vlen = ext[0]
    wrapper = tbs_body[off + hlen : off + hlen + vlen]

    sv, sh = read_len(wrapper, 0)
    assert wrapper[0] == 0x30
    exts = wrapper[sh : sh + sv]

    target = None
    for e_off, e_tag, e_hlen, e_vlen in tlvs(exts):
        assert e_tag == 0x30, "an Extension must be a SEQUENCE"
        body = exts[e_off + e_hlen : e_off + e_hlen + e_vlen]
        if body.startswith(SCT_LIST_OID):
            assert target is None, "two SCT-list extensions"
            target = (e_off, e_hlen + e_vlen)
    assert target is not None, "no SCT-list extension"
    t_off, t_len = target

    kept = exts[:t_off] + exts[t_off + t_len :]
    rebuilt = tlv(0xA3, tlv(0x30, kept)) if kept else b""
    return tlv(0x30, tbs_body[:off] + rebuilt + tbs_body[off + hlen + vlen :])


def main():
    der = SRC.read_bytes()
    tbs_body, cert_tail = split_cert(der)

    for stem, build in [
        ("leaf-generalizedtime-notbefore", generalizedtime_notbefore),
        ("leaf-unsorted-rdn", unsorted_rdn),
    ]:
        new_tbs_body, note = build(tbs_body)
        cert = rebuild(new_tbs_body, cert_tail)
        (HERE / f"{stem}.der").write_bytes(cert)

        stripped = strip_sct_list(new_tbs_body)
        (HERE / f"{stem}-tbs-no-sct.bin").write_bytes(stripped)

        print(f"{stem}.der  {len(cert)} bytes — {note}")
        print(f"{stem}-tbs-no-sct.bin  {len(stripped)} bytes")


if __name__ == "__main__":
    main()
