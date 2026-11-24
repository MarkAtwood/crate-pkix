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
set -euo pipefail
cd "$(dirname "$0")"

BASE="https://data.iana.org/root-anchors"

if [[ "${1:-}" != "--offline" ]]; then
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
