#!/usr/bin/env python3
"""Convert x509-limbo's `limbo.json` into a chain.pem tree consumable by
`pkix-difftest run pem-tree`.

This is a **demo path** that lets the existing PEM-tree corpus loader run
over the full x509-limbo corpus (9,773 testcases) without the structural
harness changes that PKIX-g9vc tracks (per-testcase validation_time,
expected-result threading, features-aware filtering). It uses only the
Python standard library so it can run from system Python without the
pyca venv.

Output layout:

    <output_dir>/
    ├── <safe_id_1>/
    │   ├── chain.pem      # leaf + intermediates + first trust anchor
    │   └── meta.json      # id, expected_result, validation_kind, validation_time, features
    ├── <safe_id_2>/
    │   └── ...
    ...

Filtering:

* Testcases whose `features` list contains anything in SKIP_FEATURES
  (currently just `has-crl`, since CRL revocation is out of v0.1 harness
  scope) are skipped at conversion time and counted in the summary.
* Testcases with no `trusted_certs` are skipped (the harness needs a
  trust anchor in the chain).
* Multi-root testcases use only `trusted_certs[0]` (the harness expects
  a single trust anchor as the last cert in the chain).

After conversion, run the harness:

    cargo run --release -p pkix-difftest -- run pem-tree <output_dir> \\
        --oracles pkix-path,openssl,pyca \\
        --output-md /tmp/limbo.md --output-json /tmp/limbo.json

Limitations of this demo path:

* `validation_time` is **ignored** — the harness uses the system clock
  for every chain. Testcases whose chain was valid only at a specific
  past time will appear expired and pile up in `Agreement(Fail)`.
* `expected_result` is **not threaded through** — the harness's
  PEM-tree loader yields `expected: None`. Cross-reference manually
  via `<output_dir>/<id>/meta.json`.
* Testcases whose first trust anchor is not self-signed (~2.5% of
  sampled testcases) will fail the harness's chain ordering
  auto-detection and surface as per-chain harness errors in the
  report.

These are exactly the problems PKIX-g9vc fixes; until then, this
script is the fastest way to see the harness exercise a large
real-world corpus.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# Limbo features that the harness cannot meaningfully process. Testcases
# tagged with any of these are skipped at conversion. See the limbo schema
# at https://github.com/C2SP/x509-limbo for the full feature taxonomy.
SKIP_FEATURES = {
    # CRL revocation is out of pkix-difftest v0.1 scope.
    "has-crl",
}

# Filename-safe-character pattern for the per-testcase directory name.
# Limbo IDs use `::` as a separator (e.g. `rfc5280::serial::zero`); we
# normalise that to a single underscore for filesystem use.
_NAME_SAFE = re.compile(r"[^a-zA-Z0-9._-]")


def safe_id(raw: str) -> str:
    return _NAME_SAFE.sub("_", raw)


def assemble_chain_pem(testcase: dict[str, Any]) -> str:
    """Concatenate leaf + intermediates + first trust anchor into a single
    leaf-first PEM string. Each block is normalised to end in a newline so
    the harness's PEM splitter sees clean BEGIN/END boundaries.
    """
    pieces: list[str] = []
    pieces.append(testcase["peer_certificate"])
    for inter in testcase.get("untrusted_intermediates", []):
        pieces.append(inter)
    # The harness expects a single trust anchor; use trusted_certs[0]. For
    # multi-root testcases this loses information, but it preserves the
    # canonical "last cert is the root" invariant.
    pieces.append(testcase["trusted_certs"][0])
    out: list[str] = []
    for p in pieces:
        s = p
        if not s.endswith("\n"):
            s += "\n"
        out.append(s)
    return "".join(out)


def build_metadata(testcase: dict[str, Any]) -> dict[str, Any]:
    """Capture per-testcase metadata that downstream analysis tools may
    cross-reference against the harness's verdict report. Only the fields
    that affect or describe verdict expectations are included; we omit the
    cert PEM blobs because they are already written to chain.pem.
    """
    return {
        "id": testcase.get("id"),
        "description": testcase.get("description"),
        "expected_result": testcase.get("expected_result"),
        "validation_kind": testcase.get("validation_kind"),
        "validation_time": testcase.get("validation_time"),
        "features": list(testcase.get("features", [])),
        "max_chain_depth": testcase.get("max_chain_depth"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Convert x509-limbo limbo.json into a chain.pem tree."
    )
    parser.add_argument("manifest", help="path to limbo.json")
    parser.add_argument(
        "output_dir", help="destination directory (will be created if missing)"
    )
    parser.add_argument(
        "--include-skipped-summary",
        action="store_true",
        help="print counts of skipped testcases by reason on stderr",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="stop after writing this many testcases (for ad-hoc smoke runs)",
    )
    args = parser.parse_args()

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    with open(args.manifest, encoding="utf-8") as f:
        data = json.load(f)
    testcases = data.get("testcases", [])

    written = 0
    skipped = {
        "feature_filter": 0,
        "no_trusted_cert": 0,
        "no_peer_certificate": 0,
        "id_clash": 0,
    }
    seen_ids: set[str] = set()

    for tc in testcases:
        if args.limit is not None and written >= args.limit:
            break

        feats = set(tc.get("features", []))
        if feats & SKIP_FEATURES:
            skipped["feature_filter"] += 1
            continue
        if not tc.get("trusted_certs"):
            skipped["no_trusted_cert"] += 1
            continue
        if not tc.get("peer_certificate"):
            skipped["no_peer_certificate"] += 1
            continue

        sid = safe_id(tc.get("id", "unknown"))
        if sid in seen_ids:
            skipped["id_clash"] += 1
            continue
        seen_ids.add(sid)

        case_dir = out / sid
        case_dir.mkdir(exist_ok=True)
        (case_dir / "chain.pem").write_text(
            assemble_chain_pem(tc), encoding="utf-8"
        )
        (case_dir / "meta.json").write_text(
            json.dumps(build_metadata(tc), indent=2), encoding="utf-8"
        )
        written += 1

    sys.stderr.write(f"Total testcases in manifest: {len(testcases)}\n")
    sys.stderr.write(f"Written: {written}\n")
    if args.include_skipped_summary or any(skipped.values()):
        sys.stderr.write("Skipped:\n")
        for reason, count in skipped.items():
            if count:
                sys.stderr.write(f"  {reason}: {count}\n")
    return 0 if written > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
