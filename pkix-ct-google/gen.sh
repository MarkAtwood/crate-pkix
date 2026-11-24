#!/usr/bin/env bash
#
# Regenerates src/generated.rs from Google's published CT log-list signing key.
#
#   ./gen.sh            fetch from Google, cross-verify, generate
#   ./gen.sh --offline  cross-verify and generate from the committed google/ copies
#   ./gen.sh --check    fetch, cross-verify, report drift, write nothing
#
# Provenance here is weaker than in pkix-dnssec-anchor, and the difference is
# worth stating plainly rather than glossing.
#
# IANA signs its trust-anchor file, so that generator verifies a detached
# signature and fails closed on a bad one. Google does not sign its *signing
# key* -- the key is the root of that trust, and nothing signs a root. Nor is
# the key published anywhere out of band: there is no fingerprint in a signed
# artifact and no copy in an independently distributed source tree. Chrome
# itself does not use this path; it receives log lists through the component
# updater's PKI Metadata component. The gstatic key and signature exist for
# third parties.
#
# What this script does instead is a cross-check that is still meaningful: it
# fetches the key, the log list, and Google's detached signature over that
# list, and verifies the signature using the fetched key. A key that verifies
# Google's current published list is Google's current signing key, or all
# three were substituted together. That rules out a stale key, a truncated or
# corrupted fetch, a wrong file at the URL, and a key from a different Google
# program.
#
# The residual risk is explicit and irreducible: the chain terminates at HTTPS
# to gstatic.com, which is to say in the Web PKI -- the thing Certificate
# Transparency exists to police. That circularity is inherent to bootstrapping
# CT from the network, and is documented in the crate docs rather than hidden
# here.

set -euo pipefail

cd "$(dirname "$0")"

MODE="generate"
case "${1-}" in
    --offline) MODE="offline" ;;
    --check) MODE="check" ;;
    "") ;;
    *)
        echo "usage: $0 [--offline|--check]" >&2
        exit 64
        ;;
esac

KEY_URL="https://www.gstatic.com/ct/log_list/v3/log_list_pubkey.pem"
LIST_URL="https://www.gstatic.com/ct/log_list/v3/log_list.json"
SIG_URL="https://www.gstatic.com/ct/log_list/v3/log_list.sig"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [[ "$MODE" == "offline" ]]; then
    cp google/log_list_pubkey.pem "$WORK/key.pem"
    cp google/sample-log_list.json "$WORK/list.json"
    cp google/sample-log_list.sig "$WORK/list.sig"
    echo "using committed copies under google/"
else
    echo "fetching from Google..."
    curl -sSf --max-time 60 -o "$WORK/key.pem" "$KEY_URL"
    curl -sSf --max-time 60 -o "$WORK/list.json" "$LIST_URL"
    curl -sSf --max-time 60 -o "$WORK/list.sig" "$SIG_URL"
fi

# Cross-verify before anything else. A key that does not verify Google's own
# list is not usable as this crate's contents, whatever else is true of it.
#
# RSA PKCS#1 v1.5 over SHA-256, which is what Google signs the list with and
# what pkix-ct's verified constructor expects.
if ! openssl dgst -sha256 -verify "$WORK/key.pem" \
    -signature "$WORK/list.sig" "$WORK/list.json" >/dev/null 2>&1; then
    cat >&2 <<'MSG'
FATAL: the fetched key does not verify Google's published log list.

This is not a key rotation. A rotation would leave the key and the list
consistent with each other, because Google publishes them together.

Inconsistency means one of:

  - the three artifacts were fetched at different times, across a rotation
  - a fetch was truncated, corrupted, or served from a stale cache
  - the URLs now serve something other than what they used to
  - the fetch was tampered with

Investigate before regenerating anything. Do not override this check.
MSG
    exit 2
fi
echo "cross-check ok: the key verifies Google's published log list"

openssl pkey -pubin -in "$WORK/key.pem" -outform DER -out "$WORK/key.der"
DIGEST="$(openssl dgst -sha256 -hex < "$WORK/key.der" | sed 's/.*= *//')"
BYTES="$(wc -c < "$WORK/key.der" | tr -d ' ')"

if [[ "$MODE" == "check" ]]; then
    COMMITTED="$(openssl dgst -sha256 -hex < google/log_list_pubkey.der | sed 's/.*= *//')"
    if [[ "$DIGEST" == "$COMMITTED" ]]; then
        echo "no drift: committed key matches Google's published key"
        echo "  sha256 $DIGEST"
        exit 0
    fi
    cat >&2 <<MSG

DRIFT: Google's log-list signing key has changed.

  committed  sha256 $COMMITTED
  published  sha256 $DIGEST

The published key verifies Google's current log list, so this looks like a
genuine key rotation rather than a bad fetch.

To update:

  cd pkix-ct-google
  ./gen.sh
  cargo test -p pkix-ct-google
  # then release pkix-ct-google

Consumers pick the new key up with 'cargo update'. They need no pkix-ct
release, and pkix-ct needs no change -- the key lives in its own crate
precisely so a rotation is a data update rather than a code release.
MSG
    exit 1
fi

# Keep the fetched artifacts as committed provenance. The sample list and its
# signature are kept so --offline and the crate's own tests can re-run the
# cross-check with no network access.
cp "$WORK/key.pem" google/log_list_pubkey.pem
cp "$WORK/key.der" google/log_list_pubkey.der
cp "$WORK/list.json" google/sample-log_list.json
cp "$WORK/list.sig" google/sample-log_list.sig

{
    cat <<'HDR'
// @generated by gen.sh -- do not edit by hand.
//
// Regenerate with `./gen.sh` (fetches from Google and cross-verifies the key
// against Google's published log list) or `./gen.sh --offline` (uses the
// committed copies under `google/`).

use crate::LogListKey;

HDR
    echo "/// SHA-256 over [\`GOOGLE\`]'s \`spki\`, as lowercase hex."
    echo "///"
    echo "/// Printed by \`gen.sh\` so a reviewer can check a release against"
    echo "/// Google's published key without parsing DER."
    echo "pub const GOOGLE_SPKI_SHA256_HEX: &str ="
    echo "    \"$DIGEST\";"
    echo
    echo "/// Google's Certificate Transparency log-list signing key."
    echo "pub const GOOGLE: LogListKey = LogListKey {"
    echo "    spki: SPKI,"
    echo "    source: \"$KEY_URL\","
    echo "    retrieved: \"$(date -u +%Y-%m-%d)\","
    echo "};"
    echo
    echo "/// The key as a DER \`SubjectPublicKeyInfo\`, $BYTES octets."
    echo "const SPKI: &[u8] = &["
    od -An -tx1 -v "$WORK/key.der" \
        | tr -s ' ' '\n' \
        | grep -E '^[0-9a-f]{2}$' \
        | sed 's/^/0x/; s/$/,/' \
        | paste -sd' ' - \
        | fold -s -w 72 \
        | sed 's/^/    /; s/ *$//'
    echo "];"
} > src/generated.rs

echo "wrote src/generated.rs"
echo "  key    $BYTES octets, sha256 $DIGEST"
echo "  source $KEY_URL"
