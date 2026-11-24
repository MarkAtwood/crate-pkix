#!/usr/bin/env bash
# Regenerates src/generated.rs from IANA's published DNSSEC root trust anchors.
#
# Provenance chain, verified on every run:
#
#   root-anchors.xml   the anchors themselves
#   root-anchors.p7s   IANA's detached PKCS#7 signature over that file
#   icannbundle.pem    the ICANN certificate the signature chains to
#
# The signature is checked BEFORE anything is generated, and the script
# exits non-zero if it does not verify. That check is the whole point:
# it is what makes the shipped anchors auditable rather than asserted.
# Reviewing an update means re-running this and diffing the result, not
# trusting whoever edited the constants.
#
# The three downloaded files are committed under iana/ alongside the
# generated source, so the provenance of a given release can be
# re-verified offline without trusting this script to have run honestly.
#
# Usage:  ./gen.sh            fetch from IANA, verify, generate
#         ./gen.sh --offline  verify and generate from the committed iana/ copies
#         ./gen.sh --check    fetch, verify, and report drift without writing
#
# --check is what detects an IANA key roll. It is deliberately part of this
# script rather than a separate one, so the IANA URLs and the signature
# verification exist in exactly one place; a checker that drifted from the
# generator would be worse than no checker. See PKIX-4bxy.
set -euo pipefail
cd "$(dirname "$0")"

BASE="https://data.iana.org/root-anchors"
MODE="${1:-}"

# --check compares a freshly fetched anchor set against the committed one
# without touching generated source. Run on a schedule: an IANA key roll is
# announced well in advance and happens on a multi-year cadence, so this is
# about never missing the announcement rather than about reacting quickly.
if [[ "$MODE" == "--check" ]]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  for f in root-anchors.xml root-anchors.p7s icannbundle.pem; do
    curl -sSf --max-time 60 -o "$tmp/$f" "$BASE/$f"
  done

  # Verify before comparing. An unsigned or badly signed fetch must not be
  # reported as drift, because drift implies the new value is trustworthy.
  if ! openssl smime -verify -inform DER -in "$tmp/root-anchors.p7s" \
       -content "$tmp/root-anchors.xml" -CAfile "$tmp/icannbundle.pem" \
       -out /dev/null 2>/dev/null; then
    echo "FATAL: IANA signature over the freshly fetched root-anchors.xml did not verify" >&2
    echo "This is not a key roll. Either the fetch was tampered with or" >&2
    echo "ICANN's signing certificate has changed; investigate before regenerating." >&2
    exit 2
  fi

  # Compare the fields that matter rather than the whole file: IANA rewrites
  # the TrustAnchor id attribute and reformats without changing any anchor,
  # and a byte comparison would cry wolf on that.
  summarise() {
    python3 -I -c '
import sys, xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
for kd in root.findall("KeyDigest"):
    print(
        kd.get("id", ""),
        (kd.findtext("KeyTag") or "").strip(),
        (kd.findtext("Algorithm") or "").strip(),
        (kd.findtext("DigestType") or "").strip(),
        (kd.findtext("Digest") or "").strip(),
        kd.get("validFrom", ""),
        kd.get("validUntil", "-"),
    )
' "$1" | sort
  }

  if diff -u <(summarise iana/root-anchors.xml) <(summarise "$tmp/root-anchors.xml"); then
    echo "no drift: the committed anchor set matches IANA"
    exit 0
  fi
  echo "" >&2
  echo "DRIFT: IANA's published anchors differ from the committed set." >&2
  echo "The diff above is '-' committed, '+' live." >&2
  echo "" >&2
  echo "If IANA has published or withdrawn a key-signing key, regenerate and" >&2
  echo "release this crate: ./gen.sh && cargo test -p pkix-dnssec-anchor." >&2
  echo "Consumers then pick it up with cargo update; they do not need a" >&2
  echo "pkix-dane-resolver release, which is why the anchors live here." >&2
  exit 1
fi

if [[ "$MODE" != "--offline" ]]; then
  for f in root-anchors.xml root-anchors.p7s icannbundle.pem; do
    curl -sSf --max-time 60 -o "iana/$f" "$BASE/$f"
    echo "fetched $f"
  done
fi

for f in root-anchors.xml root-anchors.p7s icannbundle.pem; do
  [[ -s "iana/$f" ]] || { echo "missing or empty: iana/$f" >&2; exit 1; }
done

# Fail closed. A trust anchor whose signature does not verify must never
# reach the generated source.
if ! openssl smime -verify -inform DER -in iana/root-anchors.p7s \
     -content iana/root-anchors.xml -CAfile iana/icannbundle.pem \
     -out /dev/null 2>/dev/null; then
  echo "FATAL: IANA signature over root-anchors.xml did not verify" >&2
  exit 1
fi
echo "IANA signature verified"

python3 -I gen.py iana/root-anchors.xml src/generated.rs
echo "wrote src/generated.rs"
