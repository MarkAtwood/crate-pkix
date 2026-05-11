#!/usr/bin/env python3
"""Generate a synthetic precert_entry SCT for offline pkix-ct verification tests.

This script is the *independent oracle* for the pre-cert branch of RFC
6962 §3.2 SCT signature verification. pkix-ct itself never participates
in producing these fixtures.

The pre-cert flow (RFC 6962 §3.1, §3.2):

1. A CA generates a final-cert TBS with the SCT-list extension absent
   (i.e., what the cert will look like *before* the SCT is glued in).
2. The CA submits that TBS to a CT log — wrapped as a "pre-cert", which
   is the same TBS plus a poison extension (1.3.6.1.4.1.11129.2.4.3,
   critical, value NULL). Submission framing only.
3. The log signs an SCT over a structure derived from the pre-cert:
       digitally-signed struct {
           Version sct_version;             // 1 byte; v1 = 0
           SignatureType signature_type;    // 1 byte; certificate_timestamp = 0
           uint64 timestamp;                // 8 bytes, big-endian
           LogEntryType entry_type;         // 2 bytes, big-endian; precert_entry = 1
           PreCert precert;
           CtExtensions extensions;         // u16-prefixed opaque
       };
   where
       struct {
           opaque issuer_key_hash[32];      // SHA-256 of issuer SubjectPublicKeyInfo DER
           TBSCertificate tbs_certificate;  // DER of TBS with poison ext removed
       } PreCert;
   Crucially, the bytes the log signs over come from a TBS with both
   the poison extension *and* the SCT-list extension absent — i.e., the
   "without either" form.
4. The CA issues the final cert: same TBS *plus* the SCT-list extension
   carrying the SCT the log returned, signed by the issuer key.
5. To verify the embedded SCT, a verifier reconstructs step (3)'s
   signed input by:
     - taking the final cert's TBS,
     - removing the SCT-list extension (1.3.6.1.4.1.11129.2.4.2),
     - computing SHA-256(issuer_cert.SubjectPublicKeyInfo_DER),
     - packing them in the digitally-signed layout above,
     - and verifying the SCT signature against the log's pubkey.

We commit these byte-for-byte fixtures:

  log-key.pem            ECDSA P-256 LOG signer (re-used / re-generated)
  log-spki.der           DER SubjectPublicKeyInfo of the log
  log-id.bin             32-byte SHA-256(log_spki) = RFC 6962 log_id
  precert-issuer.der     DER of the *issuer* CA cert
  precert-issuer-key.pem ECDSA P-256 ISSUER signing key (for re-issuance)
  precert-issuer-key-hash.bin  32-byte SHA-256(issuer SPKI DER)
  precert-leaf-final.der DER of the FINAL cert (with embedded SCT list)
  precert-tbs-no-sct.bin DER of the leaf TBSCertificate AFTER stripping
                         the SCT-list ext, as the log would have seen it
  precert-sct.bin        Wire-format SignedCertificateTimestamp
  precert-signed-input.bin The RFC 6962 §3.2 digitally-signed input
                         (issuer_key_hash || tbs_no_sct preceded by the
                         common preamble), committed for inspection.
  precert-meta.json      Decoded fields for human inspection.

The fixture is *synthetic* — there is no real CT log involved. The
SCT's correctness is established by:

  - pyca/cryptography signing the digitally-signed input using
    ec.ECDSA(SHA256) (the same primitive that all real CT logs deployed
    today use, per RFC 6962 §2.1.4).
  - The wire format hand-rolled from RFC 6962 §3.1 / §3.2.
  - openssl can independently verify the SCT signature against
    log-spki.der and precert-signed-input.bin.

Re-run with:

    python3 gen_precert_entry_sct.py --regenerate

(idempotent if you re-run with the same code; the script refuses to
overwrite existing fixtures unless --regenerate is passed).
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import struct
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

# RFC 6962 §3.2 constants.
SCT_VERSION_V1 = 0
SIG_TYPE_CERTIFICATE_TIMESTAMP = 0
ENTRY_TYPE_PRECERT = 1

# RFC 5246 §7.4.1.4.1 tags: ECDSA-P256-SHA256.
HASH_ALG_SHA256 = 4
SIG_ALG_ECDSA = 3

# RFC 6962 §3.3 SCT-list certificate extension OID.
OID_SCT_LIST = ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")


def u8(v: int) -> bytes:
    return struct.pack(">B", v)


def u16(v: int) -> bytes:
    return struct.pack(">H", v)


def u24(v: int) -> bytes:
    if not 0 <= v <= 0xFFFFFF:
        raise ValueError(f"u24 out of range: {v}")
    return bytes([(v >> 16) & 0xFF]) + u16(v & 0xFFFF)


def u64(v: int) -> bytes:
    return struct.pack(">Q", v)


def build_signed_input_precert_entry(
    timestamp_ms: int,
    issuer_key_hash: bytes,
    tbs_no_sct: bytes,
    extensions: bytes,
) -> bytes:
    """RFC 6962 §3.2 `digitally-signed` input (precert_entry branch).

    Layout:
        u8        sct_version            (0)
        u8        signature_type         (0 = certificate_timestamp)
        u64 BE    timestamp
        u16 BE    entry_type             (1 = precert_entry)
        32B       issuer_key_hash
        u24 + N   tbs_certificate        (TBS with poison ext removed,
                                          opaque<1..2^24-1>)
        u16 + M   extensions
    """
    assert len(issuer_key_hash) == 32
    out = bytearray()
    out += u8(SCT_VERSION_V1)
    out += u8(SIG_TYPE_CERTIFICATE_TIMESTAMP)
    out += u64(timestamp_ms)
    out += u16(ENTRY_TYPE_PRECERT)
    out += issuer_key_hash
    out += u24(len(tbs_no_sct)) + tbs_no_sct
    out += u16(len(extensions)) + extensions
    return bytes(out)


def build_sct_wire(
    log_id: bytes,
    timestamp_ms: int,
    extensions: bytes,
    hash_alg: int,
    sig_alg: int,
    signature: bytes,
) -> bytes:
    """RFC 6962 §3.2 on-the-wire `SignedCertificateTimestamp`."""
    out = bytearray()
    out += u8(SCT_VERSION_V1)
    out += log_id
    out += u64(timestamp_ms)
    out += u16(len(extensions)) + extensions
    out += u8(hash_alg)
    out += u8(sig_alg)
    out += u16(len(signature)) + signature
    return bytes(out)


def encode_sct_list_extension_value(scts_wire: list[bytes]) -> bytes:
    """RFC 6962 §3.3 SCT list extension value.

    The cert extension's `extnValue` is an OCTET STRING wrapping
    another DER OCTET STRING whose contents are the
    SignedCertificateTimestampList wire bytes.

    cryptography's UnrecognizedExtension takes the *already-octet-string-wrapped*
    extnValue payload — the outer OCTET STRING is added by the cert
    builder when emitting the extension. So we return:

        OCTET STRING(  // inner, holds the wire bytes
            SignedCertificateTimestampList
        )

    SignedCertificateTimestampList layout (RFC 6962 §3.3):
        u16  total_length
        (u16 sct_length, sct_length bytes of SCT) ...
    """
    inner = bytearray()
    for sct in scts_wire:
        inner += u16(len(sct))
        inner += sct
    list_bytes = u16(len(inner)) + inner

    # Wrap in DER OCTET STRING: tag 0x04, length, content.
    if len(list_bytes) < 0x80:
        length_bytes = bytes([len(list_bytes)])
    elif len(list_bytes) <= 0xFF:
        length_bytes = bytes([0x81, len(list_bytes)])
    elif len(list_bytes) <= 0xFFFF:
        length_bytes = bytes([0x82, (len(list_bytes) >> 8) & 0xFF, len(list_bytes) & 0xFF])
    else:
        raise ValueError(f"SCT list too long to encode: {len(list_bytes)}")
    return bytes([0x04]) + length_bytes + list_bytes


def make_issuer(not_before: datetime.datetime) -> tuple[bytes, ec.EllipticCurvePrivateKey, bytes]:
    """Generate a self-signed issuer CA cert.

    Returns (issuer_der, issuer_key, issuer_spki_der).
    """
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "pkix-ct precert-oracle issuer CA")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(0xCAFE)
        .not_valid_before(not_before)
        .not_valid_after(not_before + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
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
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    spki_der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return cert_der, key, spki_der


def make_leaf_without_sct(
    issuer_cert: x509.Certificate,
    issuer_key: ec.EllipticCurvePrivateKey,
    leaf_key: ec.EllipticCurvePrivateKey,
    not_before: datetime.datetime,
) -> x509.Certificate:
    """Build a leaf cert *without* an SCT-list extension.

    This is the form whose TBS the CT log signs over.
    """
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pkix-ct precert-oracle leaf")]))
        .issuer_name(issuer_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(0x9A9A)
        .not_valid_before(not_before)
        .not_valid_after(not_before + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(issuer_key, hashes.SHA256())
    )


def make_leaf_with_sct(
    issuer_cert: x509.Certificate,
    issuer_key: ec.EllipticCurvePrivateKey,
    leaf_key: ec.EllipticCurvePrivateKey,
    not_before: datetime.datetime,
    sct_list_extnvalue: bytes,
) -> x509.Certificate:
    """Build the FINAL cert, identical to the without-SCT form modulo
    the inserted SCT-list extension.

    `sct_list_extnvalue` is the DER OCTET STRING wrapping the
    SignedCertificateTimestampList wire bytes (RFC 6962 §3.3); see
    encode_sct_list_extension_value.
    """
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pkix-ct precert-oracle leaf")]))
        .issuer_name(issuer_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(0x9A9A)
        .not_valid_before(not_before)
        .not_valid_after(not_before + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.UnrecognizedExtension(OID_SCT_LIST, sct_list_extnvalue),
            critical=False,
        )
        .sign(issuer_key, hashes.SHA256())
    )


def tbs_bytes(cert: x509.Certificate) -> bytes:
    """Return the DER encoding of `cert`'s TBSCertificate.

    cryptography does not expose this directly; we recover it via the
    private `_inner` (`tbs_certificate_bytes`) attribute, which IS
    public on x509.Certificate per cryptography 38+.
    """
    return cert.tbs_certificate_bytes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path(__file__).parent,
        help="Where to write fixtures (defaults to this script's directory).",
    )
    parser.add_argument(
        "--regenerate",
        action="store_true",
        help="Regenerate even if fixtures already exist.",
    )
    args = parser.parse_args()

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    leaf_final_path = out_dir / "precert-leaf-final.der"
    if leaf_final_path.exists() and not args.regenerate:
        print(
            f"refusing to overwrite existing {leaf_final_path}; "
            "pass --regenerate to rebuild fixtures",
            file=sys.stderr,
        )
        return 2

    # --- 1. LOG signing key (a fresh one for the precert oracle so
    # x509_entry and precert_entry fixtures can be regenerated
    # independently).
    log_key = ec.generate_private_key(ec.SECP256R1())
    log_spki_der = log_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    log_id = hashlib.sha256(log_spki_der).digest()
    assert len(log_id) == 32

    # --- 2. Issuer CA.
    fixed_not_before = datetime.datetime(
        2025, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc
    ).replace(tzinfo=None)
    issuer_der, issuer_key, issuer_spki_der = make_issuer(fixed_not_before)
    issuer_cert = x509.load_der_x509_certificate(issuer_der)
    issuer_key_hash = hashlib.sha256(issuer_spki_der).digest()
    assert len(issuer_key_hash) == 32

    # --- 3. Leaf key.
    leaf_key = ec.generate_private_key(ec.SECP256R1())

    # --- 4. The "without-SCT" leaf — this is what the log signs over.
    leaf_without_sct = make_leaf_without_sct(
        issuer_cert, issuer_key, leaf_key, fixed_not_before
    )
    tbs_no_sct = tbs_bytes(leaf_without_sct)

    # --- 5. Build the RFC 6962 §3.2 signed-input for precert_entry.
    timestamp_ms = 1_750_032_000_000  # 2025-06-15T00:00:00Z, mirrors the x509_entry oracle.
    extensions = b""
    signed_input = build_signed_input_precert_entry(
        timestamp_ms=timestamp_ms,
        issuer_key_hash=issuer_key_hash,
        tbs_no_sct=tbs_no_sct,
        extensions=extensions,
    )

    # --- 6. Sign with the log key.
    signature = log_key.sign(signed_input, ec.ECDSA(hashes.SHA256()))

    # --- 7. Wire-format SCT.
    sct_wire = build_sct_wire(
        log_id=log_id,
        timestamp_ms=timestamp_ms,
        extensions=extensions,
        hash_alg=HASH_ALG_SHA256,
        sig_alg=SIG_ALG_ECDSA,
        signature=signature,
    )

    # --- 8. Embed the SCT in the FINAL leaf cert.
    sct_list_extnvalue = encode_sct_list_extension_value([sct_wire])
    leaf_final = make_leaf_with_sct(
        issuer_cert, issuer_key, leaf_key, fixed_not_before, sct_list_extnvalue
    )
    leaf_final_der = leaf_final.public_bytes(serialization.Encoding.DER)

    # --- 9. Sanity check: stripping the SCT-list ext from
    # leaf_final's TBS must yield exactly the TBS bytes we signed
    # over. If this check ever fails on regeneration, the
    # CertificateBuilder is reordering or re-encoding extensions in a
    # way that breaks the verification round-trip — see RFC 6962 §3.2
    # PreCert layout for what the verifier must reconstruct.
    #
    # We do the stripping inline here using a small DER walker so the
    # Python oracle remains independent of the Rust implementation
    # under test.
    tbs_after_strip = strip_extension_from_tbs(tbs_bytes(leaf_final), OID_SCT_LIST.dotted_string)
    assert tbs_after_strip == tbs_no_sct, (
        "stripping SCT-list ext from final-cert TBS did not reproduce the "
        "log-signed TBS; CertificateBuilder may have reordered extensions or "
        "added unrelated fields between the two builds. Inspect "
        f"len before={len(tbs_after_strip)} vs expected={len(tbs_no_sct)}."
    )

    # --- 10. Write files.
    (out_dir / "precert-log-key.pem").write_bytes(
        log_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (out_dir / "precert-log-spki.der").write_bytes(log_spki_der)
    (out_dir / "precert-log-id.bin").write_bytes(log_id)
    (out_dir / "precert-issuer.der").write_bytes(issuer_der)
    (out_dir / "precert-issuer-key.pem").write_bytes(
        issuer_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (out_dir / "precert-issuer-key-hash.bin").write_bytes(issuer_key_hash)
    (out_dir / "precert-leaf-final.der").write_bytes(leaf_final_der)
    (out_dir / "precert-tbs-no-sct.bin").write_bytes(tbs_no_sct)
    (out_dir / "precert-sct.bin").write_bytes(sct_wire)
    (out_dir / "precert-signed-input.bin").write_bytes(signed_input)

    meta = {
        "scheme": "RFC 6962 §3.2 precert_entry SCT, ECDSA-P256-SHA256",
        "log_id_hex": log_id.hex(),
        "issuer_key_hash_hex": issuer_key_hash.hex(),
        "timestamp_ms": timestamp_ms,
        "hash_alg": HASH_ALG_SHA256,
        "sig_alg": SIG_ALG_ECDSA,
        "extensions_len": len(extensions),
        "tbs_no_sct_len": len(tbs_no_sct),
        "leaf_final_len": len(leaf_final_der),
        "issuer_len": len(issuer_der),
        "signature_len": len(signature),
        "signed_input_len": len(signed_input),
        "sct_wire_len": len(sct_wire),
        "log_spki_len": len(log_spki_der),
        "oracle": "pyca/cryptography (ec.ECDSA(SHA256)) + hand-rolled RFC 6962 §3.2 wire format",
    }
    (out_dir / "precert-meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")

    print("Wrote precert-entry fixtures to", out_dir)
    print(json.dumps(meta, indent=2, sort_keys=True))
    return 0


def strip_extension_from_tbs(tbs_der: bytes, oid_dotted: str) -> bytes:
    """Remove the extension with the given OID from a TBSCertificate DER.

    Surgical DER walker — only used for the oracle's self-consistency
    check, not by pkix-ct. Returns the re-encoded TBS bytes with the
    matching extension removed (and outer/inner SEQUENCE lengths
    fixed up).

    Layout assumptions (RFC 5280 §4.1):

        TBSCertificate SEQUENCE {
            [0] EXPLICIT Version,        -- (CHOICE may be absent for v1; here always present)
            CertificateSerialNumber,
            AlgorithmIdentifier signature,
            Name issuer,
            Validity,
            Name subject,
            SubjectPublicKeyInfo,
            [1] IMPLICIT issuerUID OPTIONAL,
            [2] IMPLICIT subjectUID OPTIONAL,
            [3] EXPLICIT Extensions OPTIONAL  -- this is what we scan for
        }

    The Extensions container is at outer tag [3] (context-specific
    constructed, tag value 0xA3) wrapping a SEQUENCE OF Extension.
    """
    # Walk the outermost SEQUENCE.
    outer = _parse_tlv(tbs_der, 0)
    assert outer.tag == 0x30, f"TBSCertificate must be SEQUENCE; got tag 0x{outer.tag:02x}"

    # Iterate inner fields until we find the [3] EXPLICIT Extensions tag.
    pos = outer.content_start
    end = outer.content_end
    while pos < end:
        tlv = _parse_tlv(tbs_der, pos)
        if tlv.tag == 0xA3:
            # Found [3] EXPLICIT Extensions wrapper.
            # Inside is a SEQUENCE OF Extension.
            inner_seq = _parse_tlv(tbs_der, tlv.content_start)
            assert inner_seq.tag == 0x30
            new_seq_content = bytearray()
            sp = inner_seq.content_start
            removed_any = False
            while sp < inner_seq.content_end:
                ext_tlv = _parse_tlv(tbs_der, sp)
                assert ext_tlv.tag == 0x30, "each Extension must be SEQUENCE"
                # Each Extension SEQUENCE: { OID, [BOOLEAN critical OPTIONAL], OCTET STRING extnValue }.
                ext_oid_tlv = _parse_tlv(tbs_der, ext_tlv.content_start)
                assert ext_oid_tlv.tag == 0x06, "first field of Extension must be OID"
                oid_bytes = tbs_der[ext_oid_tlv.content_start:ext_oid_tlv.content_end]
                ext_oid_dotted = _decode_oid(oid_bytes)
                ext_total = tbs_der[sp:ext_tlv.total_end]
                if ext_oid_dotted == oid_dotted:
                    removed_any = True
                else:
                    new_seq_content += ext_total
                sp = ext_tlv.total_end
            if not removed_any:
                raise RuntimeError(
                    f"extension OID {oid_dotted} not found in TBS extensions"
                )
            # Re-emit the inner SEQUENCE OF Extension.
            new_inner_seq = _encode_seq(0x30, bytes(new_seq_content))
            new_outer_wrap = _encode_seq(0xA3, new_inner_seq)
            # Splice it back in.
            rebuilt = tbs_der[outer.content_start:pos] + new_outer_wrap + tbs_der[tlv.total_end:end]
            return _encode_seq(0x30, rebuilt)
        pos = tlv.total_end
    raise RuntimeError("no [3] EXPLICIT Extensions field in TBSCertificate")


class _Tlv:
    __slots__ = ("tag", "content_start", "content_end", "total_end")

    def __init__(self, tag: int, content_start: int, content_end: int, total_end: int):
        self.tag = tag
        self.content_start = content_start
        self.content_end = content_end
        self.total_end = total_end


def _parse_tlv(buf: bytes, pos: int) -> _Tlv:
    tag = buf[pos]
    pos += 1
    length_byte = buf[pos]
    pos += 1
    if length_byte < 0x80:
        length = length_byte
    else:
        nbytes = length_byte & 0x7F
        assert nbytes > 0, "indefinite-length not valid in DER"
        length = 0
        for _ in range(nbytes):
            length = (length << 8) | buf[pos]
            pos += 1
    content_start = pos
    content_end = pos + length
    return _Tlv(tag, content_start, content_end, content_end)


def _encode_seq(tag: int, content: bytes) -> bytes:
    length = len(content)
    if length < 0x80:
        length_bytes = bytes([length])
    elif length <= 0xFF:
        length_bytes = bytes([0x81, length])
    elif length <= 0xFFFF:
        length_bytes = bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    elif length <= 0xFFFFFF:
        length_bytes = bytes(
            [0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF]
        )
    else:
        raise ValueError(f"length too large: {length}")
    return bytes([tag]) + length_bytes + content


def _decode_oid(oid_bytes: bytes) -> str:
    """Decode a DER-encoded OBJECT IDENTIFIER content (no tag/length) to dotted notation."""
    if not oid_bytes:
        return ""
    first = oid_bytes[0]
    arc1 = first // 40
    arc2 = first % 40
    arcs = [arc1, arc2]
    i = 1
    cur = 0
    while i < len(oid_bytes):
        b = oid_bytes[i]
        cur = (cur << 7) | (b & 0x7F)
        if b & 0x80 == 0:
            arcs.append(cur)
            cur = 0
        i += 1
    return ".".join(str(a) for a in arcs)


if __name__ == "__main__":
    sys.exit(main())
