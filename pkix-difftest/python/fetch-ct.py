#!/usr/bin/env python3
"""Scrape a window of cert chains from a public RFC 6962 CT log into a
chain.pem tree consumable by ``pkix-difftest run pem-tree``.

This is the Tier-3 corpus fetcher for the PKIX differential harness. It
produces real-world-wild chains (not curated like PKITS, not adversarial
like x509-limbo) so the harness can surface verdict divergences between
``pkix-path``, OpenSSL, and pyca/cryptography on certs from production
CAs.

Tier-3 design choices
---------------------

* **Out-of-tree storage.** A typical scrape window is 100MB-500MB at
  default sample size. The bead authorising this work
  (`PKIX-5bab <../.beads/>`_) specifies that raw chains live outside
  the repo; only a summary JSON is committed in-tree. Default scrape
  destination is ``$PKIX_CT_CORPUS`` (env var) or
  ``~/PKIX-CT-CORPUS/<log-shard>/`` if unset.

* **One log shard per run.** Each public CT log shard
  (e.g. Cloudflare Nimbus2026, Google Argon2026h1) is independent.
  This script captures from one shard at a time; the operator can run
  it multiple times for breadth.

* **x509_entry only.** Log entries are either ``x509_entry`` (final
  issued certs that browsers see) or ``precert_entry`` (pre-issuance
  shape with the CT poison extension, never deployed as a TLS cert).
  We keep only x509_entry chains — those are the chains real consumers
  ask path validators to verify.

* **Trust anchor via the system bundle.** CT log entries do NOT include
  the root cert; the log stores leaf + intermediates only. To produce
  a chain validators can rely on we map the last intermediate's
  ``Issuer DN`` to a root cert in a local trust bundle (default
  ``/etc/ssl/certs/ca-certificates.crt``, override with
  ``--trust-bundle``). Chains whose root is not in the bundle are
  recorded as skipped — they are still real chains, just not
  validatable against the local trust store.

* **Stdlib only.** Mirrors ``limbo-to-pem-tree.py``: this script must
  run from system Python without the pyca venv so the fetcher remains
  trivial to run on minimal CI runners.

Wire format
-----------

The relevant pieces of RFC 6962 §3.4 / §4.6 reproduced here:

* MerkleTreeLeaf (§3.4)::

    struct {
        Version version;            // 1 byte, 0 = v1
        MerkleLeafType leaf_type;   // 1 byte, 0 = timestamped_entry
        TimestampedEntry timestamped_entry;
    } MerkleTreeLeaf;

    struct {
        uint64 timestamp;           // 8 bytes, ms since epoch
        LogEntryType entry_type;    // 2 bytes, 0 = x509, 1 = precert
        select (entry_type) {
            case x509_entry:    ASN.1Cert signed_entry;    // u24-len DER
            case precert_entry: PreCert  signed_entry;     // 32 + u24-len
        };
        CtExtensions extensions;    // u16 length prefix
    } TimestampedEntry;

* get-entries response ``extra_data`` (§4.6)::

    case x509_entry:
        ASN.1Cert certificate_chain<0..2^24-1>;
        // Outer u24 total length, then sequence of u24-prefixed DERs.
        // The chain is leaf-cert's issuer, then issuer's issuer, ...
        // up to but NOT including the root.

We need exactly the x509_entry slice of this to reconstruct
[leaf, *intermediates] from one log entry.

Usage
-----

::

    # Default: capture from Cloudflare Nimbus2026, 1000 entries near the
    # current head, write to $PKIX_CT_CORPUS or ~/PKIX-CT-CORPUS/
    python3 pkix-difftest/python/fetch-ct.py

    # Specify a log substring + sample size + output dir
    python3 pkix-difftest/python/fetch-ct.py \\
        --log-substring Argon2026h1 \\
        --sample 500 \\
        --out-dir /tmp/ct-corpus

    # Then run the harness over the produced tree:
    cargo run --release -p pkix-difftest -- run pem-tree \\
        $PKIX_CT_CORPUS \\
        --oracles pkix-path,openssl,pyca \\
        --output-md  pkix-difftest/baseline-ct-tier3.md \\
        --output-json pkix-difftest/baseline-ct-tier3.json

Filed per PKIX-5bab (Tier-3 CT log scrape corpus).
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import struct
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

# RFC 6962 §3.4 constants.
MERKLE_LEAF_VERSION_V1 = 0
MERKLE_LEAF_TYPE_TIMESTAMPED_ENTRY = 0
LOG_ENTRY_TYPE_X509 = 0
LOG_ENTRY_TYPE_PRECERT = 1

# Filename-safe pattern for the per-chain directory name (mirrors
# limbo-to-pem-tree.py's safe_id helper).
_NAME_SAFE = re.compile(r"[^a-zA-Z0-9._-]")


def http_get(url: str, accept: str = "application/json", timeout: float = 30.0) -> bytes:
    """Single retry-free HTTP GET. Caller handles transient failures."""
    req = urllib.request.Request(url, headers={"Accept": accept})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def fetch_log_list() -> dict[str, Any]:
    """Fetch Google/Chrome's published CT log list (v3 schema)."""
    return json.loads(http_get(LOG_LIST_URL))


def find_usable_log(log_list: dict[str, Any], key_substring: str) -> dict[str, Any]:
    """Pick a log whose description contains ``key_substring`` and is
    currently in the ``usable`` state. Same shape as the chooser in
    ``pkix-ct/tests/fixtures/live-log/capture_live_log.py`` — keep the two
    in sync if the schema shifts."""
    for op in log_list.get("operators", []):
        for log in op.get("logs", []):
            state = log.get("state", {})
            if "usable" not in state:
                continue
            if key_substring.lower() in log.get("description", "").lower():
                return {**log, "_operator": op["name"]}
    raise SystemExit(f"no usable log matching {key_substring!r}")


def safe_id(raw: str) -> str:
    """Normalise a string for use as a filesystem path component."""
    return _NAME_SAFE.sub("_", raw)


# --- RFC 6962 wire decoding -------------------------------------------------


def _read_u8(buf: bytes, off: int) -> tuple[int, int]:
    return buf[off], off + 1


def _read_u16(buf: bytes, off: int) -> tuple[int, int]:
    return struct.unpack_from(">H", buf, off)[0], off + 2


def _read_u24(buf: bytes, off: int) -> tuple[int, int]:
    """Big-endian 24-bit length. TLS-style; common in RFC 6962."""
    hi, lo = buf[off], struct.unpack_from(">H", buf, off + 1)[0]
    return (hi << 16) | lo, off + 3


def _read_u64(buf: bytes, off: int) -> tuple[int, int]:
    return struct.unpack_from(">Q", buf, off)[0], off + 8


def decode_merkle_tree_leaf(leaf_input: bytes) -> dict[str, Any]:
    """Decode one ``MerkleTreeLeaf`` (RFC 6962 §3.4).

    Returns a dict with the parsed fields, including the leaf cert DER for
    x509_entry leaves. precert_entry leaves carry the issuer_key_hash and
    the poisoned TBSCertificate, which are not directly useful for chain
    validation testing — for those we return ``entry_type='precert'`` and
    no cert DER, and the caller decides to skip.
    """
    off = 0
    version, off = _read_u8(leaf_input, off)
    if version != MERKLE_LEAF_VERSION_V1:
        raise ValueError(f"MerkleTreeLeaf version {version}, want 0 (v1)")
    leaf_type, off = _read_u8(leaf_input, off)
    if leaf_type != MERKLE_LEAF_TYPE_TIMESTAMPED_ENTRY:
        raise ValueError(
            f"MerkleTreeLeaf leaf_type {leaf_type}, want 0 (timestamped_entry)"
        )
    timestamp, off = _read_u64(leaf_input, off)
    entry_type, off = _read_u16(leaf_input, off)
    if entry_type == LOG_ENTRY_TYPE_X509:
        cert_len, off = _read_u24(leaf_input, off)
        cert_der = leaf_input[off:off + cert_len]
        off += cert_len
        ext_len, off = _read_u16(leaf_input, off)
        return {
            "entry_type": "x509",
            "timestamp_ms": timestamp,
            "leaf_der": cert_der,
            "extensions_len": ext_len,
        }
    if entry_type == LOG_ENTRY_TYPE_PRECERT:
        # 32-byte issuer_key_hash + u24-len TBSCertificate.
        off += 32  # issuer_key_hash
        tbs_len, off = _read_u24(leaf_input, off)
        off += tbs_len
        # extensions follow but we don't use them.
        return {
            "entry_type": "precert",
            "timestamp_ms": timestamp,
        }
    raise ValueError(f"unknown entry_type {entry_type}")


def decode_x509_extra_data(extra_data: bytes) -> list[bytes]:
    """Decode the ``extra_data`` field for an x509_entry (RFC 6962 §4.6).

    Wire shape: u24 total length, then sequence of u24-prefixed DER certs.
    Returns the list of intermediate DERs (root is NOT included by the
    log; this is RFC-mandated for x509_entry).
    """
    if len(extra_data) < 3:
        raise ValueError("extra_data too short for chain length prefix")
    total_len, off = _read_u24(extra_data, 0)
    if total_len + 3 != len(extra_data):
        raise ValueError(
            f"extra_data outer length {total_len} != bytes remaining "
            f"{len(extra_data) - 3}"
        )
    intermediates: list[bytes] = []
    while off < len(extra_data):
        cert_len, off = _read_u24(extra_data, off)
        intermediates.append(extra_data[off:off + cert_len])
        off += cert_len
    return intermediates


# --- ASN.1 DN extraction ----------------------------------------------------

# Minimal ASN.1 DER walking: enough to pull TBSCertificate.subject and
# TBSCertificate.issuer as raw DER byte strings. We never need to parse the
# RDN AVAs themselves — RDN-equality below is byte-equality on the
# canonical DER encoding, which is the right thing for matching log-shipped
# intermediates to trust-bundle roots (the bundle and the log both ship
# DER, and RFC 5280 §4.1.2.4 mandates DER for the Name SEQUENCE).
#
# This is intentionally NOT a general-purpose DER parser. We follow the
# fixed RFC 5280 §4.1 Certificate shape:
#
#     Certificate ::= SEQUENCE {
#         tbsCertificate         TBSCertificate,
#         signatureAlgorithm     AlgorithmIdentifier,
#         signatureValue         BIT STRING
#     }
#
#     TBSCertificate ::= SEQUENCE {
#         version            [0] EXPLICIT Version DEFAULT v1,
#         serialNumber       CertificateSerialNumber,
#         signature          AlgorithmIdentifier,
#         issuer             Name,
#         validity           Validity,
#         subject            Name,
#         subjectPublicKeyInfo SubjectPublicKeyInfo,
#         ...
#     }
#
# The Name field is itself a SEQUENCE (which we want as a whole, including
# the outer tag/length bytes, so we can compare it byte-for-byte against
# another cert's Name).


def _der_read_tlv(buf: bytes, off: int) -> tuple[int, int, int, int]:
    """Read one DER TLV at offset ``off``. Returns
    ``(tag, length, value_off, next_off)`` where ``value_off`` is the
    offset of the value bytes and ``next_off`` is the offset of the next
    TLV. Supports indefinite-length-free short and long-form encodings."""
    tag = buf[off]
    off += 1
    first_len = buf[off]
    off += 1
    if first_len & 0x80 == 0:
        return tag, first_len, off, off + first_len
    num_octets = first_len & 0x7F
    if num_octets == 0:
        raise ValueError("DER: indefinite length not allowed")
    length = 0
    for _ in range(num_octets):
        length = (length << 8) | buf[off]
        off += 1
    return tag, length, off, off + length


def _der_read_outer_seq(buf: bytes, off: int) -> tuple[int, int, int]:
    """Read an outer SEQUENCE and return ``(seq_start, value_off, end_off)``
    where ``seq_start`` is ``off`` (the SEQUENCE tag byte), ``value_off``
    is the start of the SEQUENCE's contents, and ``end_off`` is one past
    the end of the SEQUENCE."""
    seq_start = off
    tag, _, vlo, vhi = _der_read_tlv(buf, off)
    if tag != 0x30:
        raise ValueError(f"DER: expected SEQUENCE (0x30), got 0x{tag:02x}")
    return seq_start, vlo, vhi


def extract_issuer_and_subject_der(cert_der: bytes) -> tuple[bytes, bytes]:
    """Extract the ``issuer`` and ``subject`` Name SEQUENCEs from an X.509
    cert as raw DER bytes (including the outer tag + length bytes).

    Returns ``(issuer_der, subject_der)``.
    """
    # Certificate ::= SEQUENCE
    _, cert_v_off, _ = _der_read_outer_seq(cert_der, 0)
    # TBSCertificate ::= SEQUENCE
    _, tbs_v_off, tbs_end = _der_read_outer_seq(cert_der, cert_v_off)

    off = tbs_v_off
    # Optional [0] EXPLICIT Version. Context-specific class 0xA0.
    tag = cert_der[off]
    if tag == 0xA0:
        _, _, _, off = _der_read_tlv(cert_der, off)
    # serialNumber (INTEGER)
    _, _, _, off = _der_read_tlv(cert_der, off)
    # signature AlgorithmIdentifier (SEQUENCE)
    _, _, _, off = _der_read_tlv(cert_der, off)
    # issuer Name (SEQUENCE)
    issuer_start = off
    _, _, _, issuer_end = _der_read_tlv(cert_der, off)
    issuer_der = cert_der[issuer_start:issuer_end]
    off = issuer_end
    # validity Validity (SEQUENCE)
    _, _, _, off = _der_read_tlv(cert_der, off)
    # subject Name (SEQUENCE)
    subject_start = off
    _, _, _, subject_end = _der_read_tlv(cert_der, off)
    subject_der = cert_der[subject_start:subject_end]
    if subject_end > tbs_end:
        raise ValueError("DER: subject extends past TBSCertificate")
    return issuer_der, subject_der


# --- trust bundle loading ---------------------------------------------------


def load_trust_bundle(path: Path) -> dict[bytes, bytes]:
    """Load a PEM trust bundle and return a dict mapping
    ``Subject DN DER`` → ``cert DER``. Multiple certs with the same
    Subject DN are deduplicated (the first wins; the bundle's order is
    the distro's choice).
    """
    text = path.read_text(encoding="utf-8")
    # Naive PEM splitter: anchor on the BEGIN CERTIFICATE / END
    # CERTIFICATE markers. We deliberately do not pull in `cryptography`
    # — this script is stdlib-only by policy.
    blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----",
        text,
        flags=re.DOTALL,
    )
    table: dict[bytes, bytes] = {}
    for b64 in blocks:
        try:
            der = base64.b64decode(re.sub(r"\s+", "", b64))
            _, subj = extract_issuer_and_subject_der(der)
        except (ValueError, IndexError, base64.binascii.Error):
            # Skip unparseable blocks rather than aborting — bundles
            # sometimes carry experimental shapes the parser stumbles on.
            continue
        table.setdefault(subj, der)
    return table


# --- chain assembly ---------------------------------------------------------


def der_to_pem_block(der: bytes) -> str:
    """Encode DER bytes as a single PEM CERTIFICATE block."""
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


def find_root_for_chain(
    intermediates: list[bytes],
    trust_bundle: dict[bytes, bytes],
) -> tuple[bytes, bool] | None:
    """Given the leaf-first intermediate chain returned by the log, find
    the trust-bundle root that anchors it. Returns ``(root_der, drop_last_inter)``
    or None if no root was found.

    Two cases:

    1. **Normal case.** The log's last intermediate is signed by a root not
       included in the log entry (RFC 6962 §4.6 standard form). We look up
       the trust bundle by the last intermediate's Issuer DN, append the
       found root, and tell the caller NOT to drop any intermediate.

    2. **Log-included root.** Some logs (e.g. Cloudflare Nimbus shards)
       include the trust root itself as the final intermediate. The "last
       intermediate" is a self-signed cert (subject == issuer). If the
       caller appended the trust-bundle copy of the same root on top of
       this self-signed last-intermediate, the resulting chain would have
       the root verifying its own self-signature inside the §6.1 walk —
       which surfaces as "signature invalid at chain index N" for any
       root signed with an algorithm pkix-path does not implement (most
       1998-era roots use sha1WithRSAEncryption). Detect this case,
       return the log-shipped self-signed cert as the root, and signal
       the caller to drop the duplicate from the intermediate list.

    Order assumption matches RFC 6962 §4.6: log returns
    ``[issuer-of-leaf, issuer-of-that, ...]``. So the LAST intermediate is
    either (1) the issuing CA whose own issuer (the root) is outside the
    log entry, or (2) the self-signed root itself.

    Edge case: if there are no intermediates the cert is its own root
    (self-signed leaf, vanishingly rare in CT logs). Return None so the
    chain is skipped.
    """
    if not intermediates:
        return None
    last_inter = intermediates[-1]
    try:
        issuer_of_last, subject_of_last = extract_issuer_and_subject_der(last_inter)
    except (ValueError, IndexError):
        return None
    if issuer_of_last == subject_of_last:
        # Case 2: log-included self-signed root. Use it AS the root only
        # if the trust bundle agrees that this cert is trusted (matching
        # by Subject DN). Returning the log's copy rather than the bundle
        # copy preserves bit-exact provenance — every byte of the chain
        # came from the log.
        if subject_of_last in trust_bundle:
            return last_inter, True
        # Self-signed but not in the bundle. Skip — not a trustable chain.
        return None
    # Case 1: standard form, look up the root in the trust bundle.
    root = trust_bundle.get(issuer_of_last)
    if root is None:
        return None
    return root, False


# --- entry-window fetcher ---------------------------------------------------


def fetch_sth(base_url: str) -> dict[str, Any]:
    """Fetch the log's current Signed Tree Head."""
    return json.loads(http_get(base_url.rstrip("/") + "/ct/v1/get-sth"))


def fetch_entries(
    base_url: str,
    start: int,
    end: int,
    timeout: float = 60.0,
) -> list[dict[str, Any]]:
    """Fetch a window of entries from ``start`` (inclusive) to ``end``
    (inclusive). RFC 6962 §4.6 permits the log to return FEWER entries
    than requested in a single call (logs cap at 256-1024 typically).
    Caller must loop on the returned count.
    """
    url = f"{base_url.rstrip('/')}/ct/v1/get-entries?start={start}&end={end}"
    resp = json.loads(http_get(url, timeout=timeout))
    return resp.get("entries", [])


# --- main -------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scrape an RFC 6962 CT log into a chain.pem tree.",
    )
    parser.add_argument(
        "--log-substring",
        default="Nimbus2026",
        help="case-insensitive description match for the log shard "
        "(default: Nimbus2026, the Cloudflare 2026 shard known good as of "
        "2026-05-11 from PKIX-baac.8 fixture work).",
    )
    parser.add_argument(
        "--sample",
        type=int,
        default=1000,
        help="number of x509_entry chains to scrape (default: 1000).",
    )
    parser.add_argument(
        "--start-index",
        type=int,
        default=None,
        help="explicit log index to start from. Default: a window ending "
        "near (tree_size - 16) so we sample recently-issued certs without "
        "racing the log head.",
    )
    parser.add_argument(
        "--out-dir",
        default=None,
        help="output directory for the chain.pem tree. Default: "
        "$PKIX_CT_CORPUS, or ~/PKIX-CT-CORPUS/<safe-log-description>/.",
    )
    parser.add_argument(
        "--trust-bundle",
        default="/etc/ssl/certs/ca-certificates.crt",
        help="path to a PEM trust bundle for root cert lookup "
        "(default: %(default)s).",
    )
    parser.add_argument(
        "--summary",
        default=None,
        help="path to write the scrape summary JSON. Default: "
        "<out-dir>/scrape-summary.json.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=256,
        help="entries to request per get-entries call (default: 256). "
        "Logs may return fewer.",
    )
    parser.add_argument(
        "--max-skips",
        type=int,
        default=None,
        help="abort after this many consecutive non-progress events "
        "(precert entries, root-not-in-bundle skips, parse failures). "
        "Default: 10 * sample.",
    )
    args = parser.parse_args()

    # Resolve output dir + trust bundle path.
    out_dir = args.out_dir or os.environ.get("PKIX_CT_CORPUS")
    if not out_dir:
        # Fall back to ~/PKIX-CT-CORPUS/<log-shard>/.
        out_dir = str(Path.home() / "PKIX-CT-CORPUS" / safe_id(args.log_substring))
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    trust_bundle_path = Path(args.trust_bundle)
    if not trust_bundle_path.is_file():
        sys.stderr.write(
            f"trust bundle not found at {trust_bundle_path}; "
            f"chains will be scraped but most will be skipped for "
            f"root-not-found. Pass --trust-bundle to choose another.\n"
        )
        trust_bundle: dict[bytes, bytes] = {}
    else:
        trust_bundle = load_trust_bundle(trust_bundle_path)
        sys.stderr.write(
            f"trust bundle: {trust_bundle_path} "
            f"({len(trust_bundle)} unique Subject DNs)\n"
        )

    # Resolve log.
    log_list = fetch_log_list()
    log = find_usable_log(log_list, args.log_substring)
    base_url = log["url"]
    description = log["description"]
    sys.stderr.write(
        f"log: {description}\n"
        f"     operator: {log['_operator']}\n"
        f"     url:      {base_url}\n"
    )

    sth = fetch_sth(base_url)
    tree_size = int(sth["tree_size"])
    sys.stderr.write(f"current tree_size: {tree_size}\n")

    # Window: end a bit behind the head so the entries are committed.
    if args.start_index is not None:
        start = args.start_index
    else:
        # Aim to sample roughly args.sample * 1.5 entries (we'll skip
        # precerts and root-not-in-bundle chains as we go).
        window_size = max(args.sample * 2, 1)
        head_margin = 16
        start = max(0, tree_size - head_margin - window_size)
    end_cap = tree_size - 1

    max_skips = args.max_skips if args.max_skips is not None else args.sample * 10

    counts = {
        "fetched": 0,
        "x509_entries": 0,
        "precert_entries": 0,
        "root_not_in_bundle": 0,
        "log_included_root": 0,
        "parse_failures": 0,
        "id_clash": 0,
        "written": 0,
    }
    consecutive_skips = 0
    written_ids: set[str] = set()

    cursor = start
    log_id_b64 = log.get("log_id", "")
    sys.stderr.write(f"scraping from index {cursor} (writing to {out})\n")

    while counts["written"] < args.sample and cursor <= end_cap:
        batch_end = min(cursor + args.batch_size - 1, end_cap)
        try:
            entries = fetch_entries(base_url, cursor, batch_end)
        except (urllib.request.HTTPError, urllib.request.URLError,
                TimeoutError, OSError) as e:
            sys.stderr.write(
                f"get-entries[{cursor}..{batch_end}] failed: {e}; "
                f"sleeping 5s and retrying once\n"
            )
            time.sleep(5)
            try:
                entries = fetch_entries(base_url, cursor, batch_end)
            except Exception as e2:
                sys.stderr.write(f"retry also failed: {e2}; aborting\n")
                break

        if not entries:
            sys.stderr.write(
                f"log returned 0 entries for [{cursor}..{batch_end}]; "
                f"aborting (likely past usable range)\n"
            )
            break

        for offset, entry in enumerate(entries):
            log_index = cursor + offset
            counts["fetched"] += 1
            try:
                leaf_input = base64.b64decode(entry["leaf_input"])
                extra_data = base64.b64decode(entry["extra_data"])
                parsed = decode_merkle_tree_leaf(leaf_input)
            except (ValueError, KeyError, base64.binascii.Error) as e:
                counts["parse_failures"] += 1
                consecutive_skips += 1
                sys.stderr.write(f"entry[{log_index}]: parse failed: {e}\n")
                continue

            if parsed["entry_type"] != "x509":
                counts["precert_entries"] += 1
                consecutive_skips += 1
                if consecutive_skips > max_skips:
                    sys.stderr.write(
                        f"abort: {consecutive_skips} consecutive non-progress "
                        f"events (max-skips={max_skips})\n"
                    )
                    cursor = end_cap + 1
                    break
                continue

            counts["x509_entries"] += 1
            try:
                intermediates = decode_x509_extra_data(extra_data)
            except (ValueError, IndexError) as e:
                counts["parse_failures"] += 1
                consecutive_skips += 1
                sys.stderr.write(
                    f"entry[{log_index}]: extra_data decode failed: {e}\n"
                )
                continue

            root_result = find_root_for_chain(intermediates, trust_bundle)
            if root_result is None:
                counts["root_not_in_bundle"] += 1
                consecutive_skips += 1
                if consecutive_skips > max_skips:
                    sys.stderr.write(
                        f"abort: {consecutive_skips} consecutive non-progress "
                        f"events (max-skips={max_skips})\n"
                    )
                    cursor = end_cap + 1
                    break
                continue
            root_der, drop_last_inter = root_result
            if drop_last_inter:
                counts["log_included_root"] += 1
                inters_for_chain = intermediates[:-1]
            else:
                inters_for_chain = intermediates

            # Reset consecutive-skip counter on a successful write.
            consecutive_skips = 0

            # Compose chain.pem: leaf, intermediates..., root.
            chain_pem_blocks: list[str] = [der_to_pem_block(parsed["leaf_der"])]
            for inter in inters_for_chain:
                chain_pem_blocks.append(der_to_pem_block(inter))
            chain_pem_blocks.append(der_to_pem_block(root_der))
            chain_pem = "".join(chain_pem_blocks)

            # Per-chain directory name: log index zero-padded so the
            # PemTreeCorpus iteration order matches log order.
            case_name = f"entry-{log_index:010d}"
            if case_name in written_ids:
                # Should not happen given the index is monotonic, but be
                # defensive in case the log returns duplicates.
                counts["id_clash"] += 1
                continue
            written_ids.add(case_name)

            case_dir = out / case_name
            case_dir.mkdir(exist_ok=True)
            (case_dir / "chain.pem").write_text(chain_pem, encoding="utf-8")
            (case_dir / "meta.json").write_text(
                json.dumps(
                    {
                        "log_index": log_index,
                        "log_id_b64": log_id_b64,
                        "log_description": description,
                        "timestamp_ms": parsed["timestamp_ms"],
                        "leaf_len": len(parsed["leaf_der"]),
                        "intermediates_count": len(inters_for_chain),
                        "intermediates_count_from_log": len(intermediates),
                        "log_included_root": drop_last_inter,
                        "captured_at_unix": int(time.time()),
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            counts["written"] += 1
            if counts["written"] >= args.sample:
                break

        cursor += len(entries)

    summary = {
        "log_description": description,
        "log_id_b64": log_id_b64,
        "log_operator": log["_operator"],
        "log_url": base_url,
        "log_tree_size_at_scrape": tree_size,
        "trust_bundle_path": str(trust_bundle_path),
        "trust_bundle_subject_count": len(trust_bundle),
        "scrape_started_at_unix": int(time.time()) - 1,  # close enough
        "scrape_finished_at_unix": int(time.time()),
        "scrape_window_start": start,
        "scrape_window_end_inclusive": cursor - 1 if cursor > start else start,
        "counts": counts,
        "sample_target": args.sample,
        "output_dir": str(out),
    }

    summary_path = (
        Path(args.summary) if args.summary else out / "scrape-summary.json"
    )
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    sys.stderr.write(
        f"wrote {counts['written']} chains to {out}\n"
        f"summary: {summary_path}\n"
    )

    # Exit code: 0 on success, 1 if no chains were written.
    return 0 if counts["written"] > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
