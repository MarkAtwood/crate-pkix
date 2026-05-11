#!/usr/bin/env python3
# Capture one-off live-log SCT + inclusion-proof + STH triple as offline fixtures.
#
# Usage:
#   pkix-difftest/python/.venv/bin/python \
#       pkix-ct/tests/fixtures/live-log/capture_live_log.py \
#       [--site cloudflare.com] [--log-key-substring Nimbus2026]
#
# Outputs into the script's directory:
#   leaf.der          — final cert (the one carrying the embedded SCT list)
#   issuer.der        — issuer cert (signs leaf; its SPKI feeds issuer_key_hash)
#   sct.bin           — one SerializedSCT (RFC 6962 §3.3), matching the chosen log
#   leaf-hash.bin     — 32-byte SHA-256(0x00 || MerkleTreeLeaf), the index into the log's tree
#   audit-path.bin    — packed: u32 tree_size, u32 leaf_index, u32 path_len,
#                       then path_len × 32-byte sibling hashes (big-endian u32)
#   sth.bin           — packed: u64 timestamp_ms, u64 tree_size, 32 root_hash,
#                       u8 hash_alg, u8 sig_alg, u32 sig_len, sig_len signature
#                       bytes (big-endian). Note: the log's get-sth response
#                       returns tree_head_signature as a TLS DigitallySigned
#                       struct (RFC 5246 §4.7): hash(1) + sig(1) + len(2) + sig.
#                       This file stores the unwrapped form so the Rust test can
#                       feed `signature` directly to SctVerifier::verify_sth.
#   log-spki.der      — log public key as a DER SubjectPublicKeyInfo
#   log-id.bin        — 32-byte SHA-256(log SPKI), redundant with sct.log_id
#   meta.json         — provenance: shard name + url, log_list version + timestamp,
#                       capture site, capture timestamp, leaf serial, issuer DN.
#
# The script does live network access:
#   - GET https://www.gstatic.com/ct/log_list/v3/log_list.json  (current log list)
#   - openssl s_client connect <site>:443  (cert chain capture)
#   - GET <log>/ct/v1/get-sth                (contemporary STH)
#   - GET <log>/ct/v1/get-proof-by-hash      (inclusion proof for leaf)
#
# Once the fixture is committed, the Rust integration test runs fully offline.
#
# Independent oracle role
# -----------------------
#
# This script computes the MerkleTreeLeaf bytes (RFC 6962 §3.4 precert_entry form)
# and its leaf hash directly from the RFC text, NOT by calling pkix-ct. The Rust
# test then verifies the captured inclusion proof against the captured STH-committed
# root using pkix-ct's hash-only verifier. This satisfies the test-integrity rule
# in AGENTS.md: tests must have an independent oracle.
#
# Provenance: filed per PKIX-baac.8 (do-beads autonomous loop, 2026-05-11).

import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

FIXTURE_DIR = Path(__file__).resolve().parent
LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
SCT_LIST_OID = "1.3.6.1.4.1.11129.2.4.2"

# RFC 6962 §3.4 constants.
MERKLE_LEAF_VERSION_V1 = 0
MERKLE_LEAF_TYPE_TIMESTAMPED_ENTRY = 0
LOG_ENTRY_TYPE_X509 = 0
LOG_ENTRY_TYPE_PRECERT = 1


def http_get(url: str, accept: str = "application/json", timeout: float = 30.0) -> bytes:
    req = urllib.request.Request(url, headers={"Accept": accept})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def fetch_log_list() -> dict:
    raw = http_get(LOG_LIST_URL)
    return json.loads(raw)


def find_usable_log(log_list: dict, key_substring: str) -> dict:
    """Find a `usable` log whose description contains `key_substring`."""
    for op in log_list.get("operators", []):
        for log in op.get("logs", []):
            state = log.get("state", {})
            if "usable" not in state:
                continue
            if key_substring.lower() in log.get("description", "").lower():
                return {**log, "_operator": op["name"]}
    raise SystemExit(f"no usable log matching {key_substring!r}")


def capture_chain(site: str) -> tuple[bytes, bytes]:
    """openssl s_client a TLS site; return (leaf_der, issuer_der)."""
    p = subprocess.run(
        ["openssl", "s_client", "-showcerts", "-connect", f"{site}:443",
         "-servername", site],
        input=b"",
        capture_output=True,
        timeout=30,
    )
    if p.returncode != 0:
        raise SystemExit(f"openssl s_client failed: {p.stderr.decode(errors='replace')[:400]}")
    text = p.stdout.decode(errors="replace")
    blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----", text)
    if len(blocks) < 2:
        raise SystemExit(f"expected at least 2 certs in chain, got {len(blocks)}")
    leaf_der = pem_to_der(blocks[0])
    issuer_der = pem_to_der(blocks[1])
    return leaf_der, issuer_der


def pem_to_der(pem: str) -> bytes:
    body = re.sub(r"-----.*-----", "", pem).strip()
    return base64.b64decode("".join(body.split()))


# --- DER + SCT parsing ---------------------------------------------------

def der_read_tlv(buf: bytes, off: int) -> tuple[int, int, int]:
    """Return (tag, value_offset, value_length). Big-endian length forms."""
    tag = buf[off]
    n = off + 1
    first = buf[n]
    n += 1
    if first < 0x80:
        length = first
    else:
        n_octets = first & 0x7F
        length = int.from_bytes(buf[n:n + n_octets], "big")
        n += n_octets
    return tag, n, length


def find_extension(cert_der: bytes, oid: str) -> tuple[int, int]:
    """Return (extension_start, extension_end) for the named extension.

    Walks the cert structure: Certificate ::= SEQ { tbsCert SEQ, sigAlg, sigVal }.
    The tbsCert has optional [0] EXPLICIT version, serial, sigAlg, issuer,
    validity, subject, spki, optional [1] issuerUID, optional [2] subjectUID,
    optional [3] EXPLICIT extensions. We walk to the extensions tag (0xA3) and
    scan SEQ-of-SEQ children for the one whose OID matches.
    """
    target_oid_bytes = _oid_to_der(oid)

    # Certificate outer SEQ
    tag, off, _ = der_read_tlv(cert_der, 0)
    assert tag == 0x30
    # tbsCertificate SEQ
    tag, off, length = der_read_tlv(cert_der, off)
    assert tag == 0x30
    tbs_end = off + length
    n = off
    # skip optional [0] version
    if cert_der[n] == 0xA0:
        _, vo, vl = der_read_tlv(cert_der, n)
        n = vo + vl
    # skip serial, sigAlg, issuer, validity, subject, spki, optional UIDs
    # The extensions container is [3] EXPLICIT, tag 0xA3.
    while n < tbs_end and cert_der[n] != 0xA3:
        _, vo, vl = der_read_tlv(cert_der, n)
        n = vo + vl
    if n >= tbs_end:
        raise ValueError("no extensions container")
    # [3] EXPLICIT { SEQ-OF Extension }
    _, exts_outer_off, _exts_outer_len = der_read_tlv(cert_der, n)
    # inner SEQ-OF
    _, exts_off, exts_len = der_read_tlv(cert_der, exts_outer_off)
    exts_end = exts_off + exts_len
    m = exts_off
    while m < exts_end:
        ext_start = m
        _, eo, el = der_read_tlv(cert_der, m)
        ext_end = eo + el
        # Extension ::= SEQ { extnID OID, critical BOOL DEFAULT FALSE, extnValue OCTET STRING }
        _, oo, ol = der_read_tlv(cert_der, eo)
        if cert_der[eo:oo + ol] == target_oid_bytes:
            return ext_start, ext_end
        m = ext_end
    raise ValueError(f"extension {oid} not found")


def _oid_to_der(oid_str: str) -> bytes:
    """Encode the OID's TLV (tag + length + content)."""
    parts = [int(p) for p in oid_str.split(".")]
    first = parts[0] * 40 + parts[1]
    body = bytearray([first])
    for p in parts[2:]:
        # base-128 with continuation bits
        if p == 0:
            body.append(0)
            continue
        stack = []
        while p > 0:
            stack.append(p & 0x7F)
            p >>= 7
        for i, b in enumerate(reversed(stack)):
            if i < len(stack) - 1:
                body.append(b | 0x80)
            else:
                body.append(b)
    body = bytes(body)
    return bytes([0x06, len(body)]) + body


def strip_extension(cert_der: bytes, oid: str) -> bytes:
    """Return the cert TBS bytes with the named extension removed.

    Re-encodes the SEQ-OF-extensions and TBS with corrected lengths. Returns
    just the TBS bytes (the input to RFC 6962 §3.2 PreCert.tbs_certificate).
    """
    ext_start, ext_end = find_extension(cert_der, oid)
    ext_size = ext_end - ext_start

    # Walk to find the SEQ-OF-extensions and the [3] EXPLICIT wrapping it,
    # and the TBS outer SEQ, so we can rebuild lengths.
    tag, tbs_off, _ = der_read_tlv(cert_der, 0)
    assert tag == 0x30  # outer Certificate
    tag, tbs_body_off, tbs_body_len = der_read_tlv(cert_der, tbs_off)
    assert tag == 0x30
    tbs_body_end = tbs_body_off + tbs_body_len

    n = tbs_body_off
    if cert_der[n] == 0xA0:
        _, vo, vl = der_read_tlv(cert_der, n)
        n = vo + vl
    while n < tbs_body_end and cert_der[n] != 0xA3:
        _, vo, vl = der_read_tlv(cert_der, n)
        n = vo + vl
    if n >= tbs_body_end:
        raise ValueError("no extensions container")
    exts_explicit_start = n
    _, exts_outer_off, exts_outer_len = der_read_tlv(cert_der, n)
    exts_explicit_end = exts_outer_off + exts_outer_len
    _, exts_off, exts_len = der_read_tlv(cert_der, exts_outer_off)

    # New inner SEQ-OF-extensions contents: everything in [exts_off, exts_end)
    # except the byte range [ext_start, ext_end).
    new_inner = cert_der[exts_off:ext_start] + cert_der[ext_end:exts_off + exts_len]
    new_inner_seq = _wrap_der(0x30, new_inner)
    new_explicit = _wrap_der(0xA3, new_inner_seq)

    new_tbs_body = (
        cert_der[tbs_body_off:exts_explicit_start]
        + new_explicit
        + cert_der[exts_explicit_end:tbs_body_end]
    )
    new_tbs = _wrap_der(0x30, new_tbs_body)

    # Sanity: removed exactly ext_size bytes from the extensions, plus the
    # length-encoding may have shrunk by up to a few bytes for the seq-of and
    # the explicit-tag wrappers.
    delta = len(cert_der[tbs_off:tbs_body_end + (tbs_body_off - tbs_off)]) - len(new_tbs)
    # We don't strictly assert delta == ext_size because the length encoding
    # of the seq-of and explicit-tag may have collapsed; but it must be at
    # least ext_size bytes shorter.
    assert delta >= ext_size, f"TBS only shrank by {delta} bytes, expected >= {ext_size}"
    return new_tbs


def _wrap_der(tag: int, body: bytes) -> bytes:
    length = len(body)
    if length < 0x80:
        return bytes([tag, length]) + body
    # long form
    n_octets = (length.bit_length() + 7) // 8
    return bytes([tag, 0x80 | n_octets]) + length.to_bytes(n_octets, "big") + body


def parse_sct_list_extension_value(ext_der: bytes) -> bytes:
    """Strip OID + critical + OCTET-STRING wrappers down to the SignedCertificateTimestampList bytes.

    extension SEQ { extnID OID, critical BOOL?, extnValue OCTET STRING }
      where extnValue contents = DER OCTET STRING wrapping the
        SignedCertificateTimestampList bytes (RFC 6962 §3.3).
    """
    _, eo, el = der_read_tlv(ext_der, 0)
    m = eo
    end = eo + el
    # skip OID
    _, oo, ol = der_read_tlv(ext_der, m)
    m = oo + ol
    # optional critical
    if ext_der[m] == 0x01:
        _, co, cl = der_read_tlv(ext_der, m)
        m = co + cl
    # extnValue OCTET STRING
    _, vo, vl = der_read_tlv(ext_der, m)
    # contents are another OCTET STRING (RFC 5280 §4.1)
    inner_octet = ext_der[vo:vo + vl]
    _, io, il = der_read_tlv(inner_octet, 0)
    # That second OCTET STRING's value is the raw u16-length-prefixed
    # SignedCertificateTimestampList.
    return inner_octet[io:io + il]


def parse_serialized_sct_list(buf: bytes) -> list[bytes]:
    """SignedCertificateTimestampList: u16 total_len, then concatenated SerializedSCT entries each prefixed by u16 len."""
    total_len = int.from_bytes(buf[:2], "big")
    if total_len != len(buf) - 2:
        raise ValueError(f"SCT list length mismatch: header says {total_len}, body is {len(buf) - 2}")
    out = []
    n = 2
    while n < len(buf):
        sct_len = int.from_bytes(buf[n:n + 2], "big")
        n += 2
        out.append(buf[n:n + sct_len])
        n += sct_len
    return out


def parse_sct(sct_bytes: bytes) -> dict:
    """Parse one SerializedSCT into its fields. Returns a dict carrying the wire bytes too."""
    n = 0
    version = sct_bytes[n]; n += 1
    log_id = sct_bytes[n:n + 32]; n += 32
    timestamp_ms = int.from_bytes(sct_bytes[n:n + 8], "big"); n += 8
    ext_len = int.from_bytes(sct_bytes[n:n + 2], "big"); n += 2
    extensions = sct_bytes[n:n + ext_len]; n += ext_len
    hash_alg = sct_bytes[n]; n += 1
    sig_alg = sct_bytes[n]; n += 1
    sig_len = int.from_bytes(sct_bytes[n:n + 2], "big"); n += 2
    signature = sct_bytes[n:n + sig_len]; n += sig_len
    if n != len(sct_bytes):
        raise ValueError(f"SCT has {len(sct_bytes) - n} trailing bytes")
    return {
        "version": version,
        "log_id": log_id,
        "timestamp_ms": timestamp_ms,
        "extensions": extensions,
        "hash_alg": hash_alg,
        "sig_alg": sig_alg,
        "signature": signature,
        "raw": sct_bytes,
    }


# --- MerkleTreeLeaf builder (RFC 6962 §3.4) ------------------------------

def find_spki(cert_der: bytes) -> bytes:
    """Return the SubjectPublicKeyInfo DER bytes from a cert."""
    tag, off, _ = der_read_tlv(cert_der, 0)
    assert tag == 0x30
    tag, tbs_off, tbs_len = der_read_tlv(cert_der, off)
    assert tag == 0x30
    tbs_end = tbs_off + tbs_len
    n = tbs_off
    if cert_der[n] == 0xA0:  # [0] version
        _, vo, vl = der_read_tlv(cert_der, n)
        n = vo + vl
    # skip serial (INTEGER)
    _, vo, vl = der_read_tlv(cert_der, n); n = vo + vl
    # signature (SEQ)
    _, vo, vl = der_read_tlv(cert_der, n); n = vo + vl
    # issuer (SEQ)
    _, vo, vl = der_read_tlv(cert_der, n); n = vo + vl
    # validity (SEQ)
    _, vo, vl = der_read_tlv(cert_der, n); n = vo + vl
    # subject (SEQ)
    _, vo, vl = der_read_tlv(cert_der, n); n = vo + vl
    # spki (SEQ) — capture this whole TLV
    spki_start = n
    _, vo, vl = der_read_tlv(cert_der, n)
    spki_end = vo + vl
    return cert_der[spki_start:spki_end]


def build_merkle_tree_leaf_precert(sct: dict, tbs_no_sct: bytes, issuer_key_hash: bytes) -> bytes:
    """RFC 6962 §3.4 MerkleTreeLeaf for an SCT carrying a precert_entry.

    Encoding:
        struct {
            Version version;                       // u8, v1 = 0
            MerkleLeafType leaf_type;              // u8, timestamped_entry = 0
            TimestampedEntry timestamped_entry;
        } MerkleTreeLeaf;

        struct {
            uint64 timestamp;                      // u64
            LogEntryType entry_type;               // u16, precert_entry = 1
            PreCert signed_entry;                  // when precert_entry
            CtExtensions extensions;               // u16-prefixed
        } TimestampedEntry;

        struct {
            opaque issuer_key_hash[32];
            TBSCertificate tbs_certificate;        // u24-prefixed opaque
        } PreCert;
    """
    if len(issuer_key_hash) != 32:
        raise ValueError(f"issuer_key_hash must be 32 bytes, got {len(issuer_key_hash)}")
    if len(tbs_no_sct) > (1 << 24) - 1:
        raise ValueError("TBS exceeds 2^24 - 1 octets")
    tbs_field = len(tbs_no_sct).to_bytes(3, "big") + tbs_no_sct
    ext_field = len(sct["extensions"]).to_bytes(2, "big") + sct["extensions"]

    out = bytearray()
    out.append(MERKLE_LEAF_VERSION_V1)
    out.append(MERKLE_LEAF_TYPE_TIMESTAMPED_ENTRY)
    out.extend(sct["timestamp_ms"].to_bytes(8, "big"))
    out.extend(LOG_ENTRY_TYPE_PRECERT.to_bytes(2, "big"))
    out.extend(issuer_key_hash)
    out.extend(tbs_field)
    out.extend(ext_field)
    return bytes(out)


def merkle_leaf_hash(merkle_tree_leaf: bytes) -> bytes:
    """RFC 6962 §2.1: leaf hash = SHA256(0x00 || MerkleTreeLeaf)."""
    h = hashlib.sha256()
    h.update(b"\x00")
    h.update(merkle_tree_leaf)
    return h.digest()


# --- CT log API ----------------------------------------------------------

def get_sth(log_url: str) -> dict:
    raw = http_get(log_url.rstrip("/") + "/ct/v1/get-sth")
    return json.loads(raw)


def get_proof_by_hash(log_url: str, leaf_hash_b64: str, tree_size: int) -> dict:
    url = (log_url.rstrip("/")
           + f"/ct/v1/get-proof-by-hash?hash={urllib.parse.quote(leaf_hash_b64)}"
           + f"&tree_size={tree_size}")
    raw = http_get(url)
    return json.loads(raw)


# --- main ----------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Capture a live-log SCT+proof+STH triple.")
    parser.add_argument("--site", default="cloudflare.com")
    parser.add_argument("--log-key-substring", default="Nimbus2026",
                        help="Substring to match against log description.")
    parser.add_argument("--out-dir", default=str(FIXTURE_DIR))
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[1/8] Fetching Google CT log list ...")
    log_list = fetch_log_list()
    log_list_version = log_list.get("version", "?")
    log_list_ts = log_list.get("log_list_timestamp", "?")
    print(f"      version={log_list_version} timestamp={log_list_ts}")

    print(f"[2/8] Finding usable log matching {args.log_key_substring!r} ...")
    log = find_usable_log(log_list, args.log_key_substring)
    log_url = log["url"]
    log_spki = base64.b64decode(log["key"])
    log_id_from_list = hashlib.sha256(log_spki).digest()
    print(f"      log: {log['description']} operator={log['_operator']}")
    print(f"      url: {log_url}")
    print(f"      log_id: {log_id_from_list.hex()}")

    print(f"[3/8] Capturing cert chain from {args.site}:443 ...")
    leaf_der, issuer_der = capture_chain(args.site)
    print(f"      leaf: {len(leaf_der)} bytes; issuer: {len(issuer_der)} bytes")

    print(f"[4/8] Extracting SCT-list extension and locating the SCT for chosen log ...")
    ext_start, ext_end = find_extension(leaf_der, SCT_LIST_OID)
    ext_der = leaf_der[ext_start:ext_end]
    scts_raw = parse_serialized_sct_list(parse_sct_list_extension_value(ext_der))
    print(f"      cert has {len(scts_raw)} embedded SCTs")
    target_sct = None
    for raw in scts_raw:
        s = parse_sct(raw)
        if s["log_id"] == log_id_from_list:
            target_sct = s
            break
    if target_sct is None:
        raise SystemExit(
            f"none of the cert's {len(scts_raw)} SCTs match log_id "
            f"{log_id_from_list.hex()}. Try a different --log-key-substring "
            f"or a different --site."
        )
    print(f"      matched SCT: timestamp_ms={target_sct['timestamp_ms']} "
          f"sig_len={len(target_sct['signature'])}")

    print(f"[5/8] Building MerkleTreeLeaf (precert_entry) and leaf hash ...")
    tbs_no_sct = strip_extension(leaf_der, SCT_LIST_OID)
    issuer_spki = find_spki(issuer_der)
    issuer_key_hash = hashlib.sha256(issuer_spki).digest()
    mtl = build_merkle_tree_leaf_precert(target_sct, tbs_no_sct, issuer_key_hash)
    lh = merkle_leaf_hash(mtl)
    print(f"      leaf_hash = {lh.hex()}")

    print(f"[6/8] Fetching contemporary STH from {log_url}get-sth ...")
    sth = get_sth(log_url)
    tree_size = int(sth["tree_size"])
    print(f"      tree_size={tree_size}, timestamp={sth['timestamp']}")
    sth_root_b64 = sth["sha256_root_hash"]
    sth_sig_b64 = sth["tree_head_signature"]
    sth_root = base64.b64decode(sth_root_b64)

    print(f"[7/8] Fetching inclusion proof from {log_url}get-proof-by-hash ...")
    # Try a few times — the log may not yet have integrated very recent entries.
    proof = None
    last_err = None
    for attempt in range(3):
        try:
            proof = get_proof_by_hash(log_url, base64.b64encode(lh).decode(), tree_size)
            break
        except Exception as e:
            last_err = e
            print(f"      attempt {attempt + 1} failed ({e}); waiting 10s ...")
            time.sleep(10)
    if proof is None:
        raise SystemExit(f"get-proof-by-hash failed 3x; last error: {last_err}")
    leaf_index = int(proof["leaf_index"])
    audit_path = [base64.b64decode(p) for p in proof.get("audit_path", [])]
    print(f"      leaf_index={leaf_index} path_len={len(audit_path)}")

    print(f"[8/8] Writing fixtures to {out_dir} ...")
    (out_dir / "leaf.der").write_bytes(leaf_der)
    (out_dir / "issuer.der").write_bytes(issuer_der)
    (out_dir / "sct.bin").write_bytes(target_sct["raw"])
    (out_dir / "leaf-hash.bin").write_bytes(lh)
    (out_dir / "log-spki.der").write_bytes(log_spki)
    (out_dir / "log-id.bin").write_bytes(log_id_from_list)

    # audit-path.bin: u32 tree_size, u32 leaf_index, u32 path_len, path nodes.
    ap = bytearray()
    ap.extend(tree_size.to_bytes(4, "big"))
    ap.extend(leaf_index.to_bytes(4, "big"))
    ap.extend(len(audit_path).to_bytes(4, "big"))
    for node in audit_path:
        if len(node) != 32:
            raise ValueError(f"audit-path node is {len(node)} bytes, expected 32")
        ap.extend(node)
    (out_dir / "audit-path.bin").write_bytes(bytes(ap))

    # tree_head_signature in the get-sth response is a TLS DigitallySigned struct
    # (RFC 5246 §4.7): hash_alg(1) + sig_alg(1) + sig_len(2) + sig(sig_len).
    # Unwrap it so the Rust test sees hash_alg/sig_alg as separate fields and
    # `signature` is just the ECDSA-Sig-Value (the form pkix-ct's verify_sth
    # expects).
    ds = base64.b64decode(sth_sig_b64)
    sth_hash_alg = ds[0]
    sth_sig_alg = ds[1]
    inner_sig_len = int.from_bytes(ds[2:4], "big")
    inner_sig = ds[4:4 + inner_sig_len]
    if len(inner_sig) != inner_sig_len:
        raise ValueError("tree_head_signature inner length mismatch")

    # sth.bin: u64 timestamp_ms, u64 tree_size, 32 root, u8 hash_alg, u8 sig_alg, u32 sig_len, sig.
    sth_bin = bytearray()
    sth_bin.extend(int(sth["timestamp"]).to_bytes(8, "big"))
    sth_bin.extend(tree_size.to_bytes(8, "big"))
    if len(sth_root) != 32:
        raise ValueError(f"STH root is {len(sth_root)} bytes, expected 32")
    sth_bin.extend(sth_root)
    sth_bin.append(sth_hash_alg)
    sth_bin.append(sth_sig_alg)
    sth_bin.extend(len(inner_sig).to_bytes(4, "big"))
    sth_bin.extend(inner_sig)
    (out_dir / "sth.bin").write_bytes(bytes(sth_bin))

    meta = {
        "capture_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "capture_site": args.site,
        "log_description": log["description"],
        "log_operator": log["_operator"],
        "log_url": log_url,
        "log_list_url": LOG_LIST_URL,
        "log_list_version": log_list_version,
        "log_list_timestamp": log_list_ts,
        "sct_timestamp_ms": target_sct["timestamp_ms"],
        "sct_hash_alg": target_sct["hash_alg"],
        "sct_sig_alg": target_sct["sig_alg"],
        "leaf_index": leaf_index,
        "tree_size": tree_size,
        "sth_timestamp_ms": int(sth["timestamp"]),
        "sth_hash_alg": sth_hash_alg,
        "sth_sig_alg": sth_sig_alg,
        "audit_path_length": len(audit_path),
        "leaf_hash_hex": lh.hex(),
        "sth_root_hash_hex": sth_root.hex(),
        "leaf_serial_hex": _extract_serial_hex(leaf_der),
        "leaf_issuer_dn_hint": "see issuer.der",
        "notes": (
            "Captured by capture_live_log.py. Run is one-off; the test runs offline. "
            "pkix-ct does not enforce STH freshness, so this fixture remains valid "
            "long after the log's current STH advances past this tree_size."
        ),
    }
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")

    print(f"      wrote: leaf.der issuer.der sct.bin leaf-hash.bin "
          f"audit-path.bin sth.bin log-spki.der log-id.bin meta.json")
    print(f"done.")
    return 0


def _extract_serial_hex(cert_der: bytes) -> str:
    tag, off, _ = der_read_tlv(cert_der, 0)
    assert tag == 0x30
    _, tbs_off, _ = der_read_tlv(cert_der, off)
    n = tbs_off
    if cert_der[n] == 0xA0:
        _, vo, vl = der_read_tlv(cert_der, n)
        n = vo + vl
    # serial number INTEGER
    _, vo, vl = der_read_tlv(cert_der, n)
    return cert_der[vo:vo + vl].hex()


if __name__ == "__main__":
    sys.exit(main())
