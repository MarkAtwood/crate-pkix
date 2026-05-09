#!/usr/bin/env bash
# Regenerate the fixture certificates used by pkix-revocation-http tests.
#
# These certs exist solely to exercise the CDP / AIA URL extraction helpers
# (PKIX-a1yc.2 and PKIX-a1yc.3). They are self-signed and not part of any
# trust chain. The point is the extension contents, not the cryptography.
#
# Independent oracle: re-run this script and compare extension text via
#   openssl x509 -in <fixture>.der -inform DER -text -noout
# against the expected URLs in extract::tests.
#
# Reproducibility note: openssl chooses a fresh serial number, validity
# window, and signature each invocation. The bytes change every run, but
# the *extension contents* — the inputs the helpers actually parse — are
# stable so long as the -addext arguments stay identical.

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cd "$TMP"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out k.pem >/dev/null 2>&1

# Fixture 1 — single HTTP CDP URI + AIA with OCSP and caIssuers (both HTTP).
openssl req -new -x509 -key k.pem -days 36500 \
  -subj "/CN=Test CDP and AIA HTTP" \
  -addext "crlDistributionPoints=URI:http://crl.example.com/test.crl" \
  -addext "authorityInfoAccess=OCSP;URI:http://ocsp.example.com/, caIssuers;URI:http://ca.example.com/ca.cer" \
  -outform DER -out "$DIR/cert-cdp-aia-http.der"

# Fixture 2 — mixed-scheme CDP and AIA. The helpers must keep http/https
# and discard everything else (ldap, ftp).
openssl req -new -x509 -key k.pem -days 36500 \
  -subj "/CN=Test CDP Mixed Schemes" \
  -addext "crlDistributionPoints=URI:http://crl.example.com/a.crl, URI:https://crl.example.com/b.crl, URI:ldap://ldap.example.com/c, URI:ftp://ftp.example.com/d.crl" \
  -addext "authorityInfoAccess=OCSP;URI:https://ocsp.example.com/, OCSP;URI:ldap://ocsp-ldap.example.com/, caIssuers;URI:http://ca.example.com/ca.cer" \
  -outform DER -out "$DIR/cert-cdp-aia-mixed-schemes.der"

# Fixture 3 — neither CDP nor AIA extension present. The helpers must
# return Ok(empty) without erroring.
openssl req -new -x509 -key k.pem -days 36500 \
  -subj "/CN=Test No Extensions" \
  -outform DER -out "$DIR/cert-no-extensions.der"

echo "wrote:"
ls -la "$DIR"/*.der
