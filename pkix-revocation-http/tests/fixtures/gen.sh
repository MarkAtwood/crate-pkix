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

# Fixtures 4-7 — CA + leaf for OCSP request encoding (PKIX-a1yc.4).
# We build a minimal CA-signs-leaf pair and let openssl ocsp -reqout produce
# reference OCSPRequest DER bytes for SHA-1 and SHA-256 CertID variants.
# These reference files are the independent oracle for build_ocsp_request.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$TMP/ca.key" >/dev/null 2>&1
openssl req -new -x509 -key "$TMP/ca.key" -days 36500 \
  -subj "/CN=Test OCSP CA" \
  -outform DER -out "$DIR/ca.der"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$TMP/leaf.key" >/dev/null 2>&1
openssl req -new -key "$TMP/leaf.key" -subj "/CN=Test OCSP Leaf" \
  -out "$TMP/leaf.csr"
openssl x509 -req -in "$TMP/leaf.csr" \
  -CAform DER -CA "$DIR/ca.der" -CAkey "$TMP/ca.key" -CAcreateserial \
  -days 36500 -outform DER -out "$DIR/leaf.der"

# openssl ocsp -reqout needs PEM input.
openssl x509 -in "$DIR/ca.der"   -inform DER -out "$TMP/ca.pem"
openssl x509 -in "$DIR/leaf.der" -inform DER -out "$TMP/leaf.pem"

# -no_nonce is critical: byte-stable output that build_ocsp_request can
# match exactly. The default request includes a random nonce extension.
openssl ocsp -no_nonce -issuer "$TMP/ca.pem" -cert "$TMP/leaf.pem" \
  -reqout "$DIR/req-sha1.der"
openssl ocsp -no_nonce -issuer "$TMP/ca.pem" -sha256 -cert "$TMP/leaf.pem" \
  -reqout "$DIR/req-sha256.der"

echo "wrote:"
ls -la "$DIR"/*.der
