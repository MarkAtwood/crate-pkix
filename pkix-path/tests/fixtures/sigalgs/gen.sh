#!/bin/sh
# Regenerates the signature-algorithm fixtures used by tests/sigalgs.rs.
#
# Each case is a self-signed CA (<name>-ca.der) and a leaf it signs
# (<name>-leaf.der), produced by the OpenSSL CLI (the independent oracle:
# `openssl verify -CAfile <name>-ca.pem <name>-leaf.pem` accepts every pair).
# Validity: 3650 days from generation (first generated 2026-11-20; the
# tests validate at 2027-01-01). OpenSSL 3.0 has no fixed-date option.
#
# Usage: sh gen.sh   (run from this directory; needs OpenSSL >= 3.0)
set -eu
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

ext_ca="basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash"
ext_leaf="basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectAltName=DNS:leaf.example
authorityKeyIdentifier=keyid"

# gen <name> <keygen args> <sign args>
gen() {
    name=$1; keyargs=$2; signargs=$3
    openssl genpkey $keyargs -out "$tmp/$name-ca.key" 2>/dev/null
    openssl genpkey $keyargs -out "$tmp/$name-leaf.key" 2>/dev/null
    printf '%s\n' "$ext_ca" > "$tmp/ca.ext"
    printf '%s\n' "$ext_leaf" > "$tmp/leaf.ext"
    openssl req -new -key "$tmp/$name-ca.key" -subj "/CN=sigalgs $name CA" -out "$tmp/ca.csr"
    openssl x509 -req -in "$tmp/ca.csr" -signkey "$tmp/$name-ca.key" $signargs \
        -days 3650 \
        -extfile "$tmp/ca.ext" -set_serial 1 -out "$tmp/$name-ca.pem" 2>/dev/null
    openssl req -new -key "$tmp/$name-leaf.key" -subj "/CN=leaf.example" -out "$tmp/leaf.csr"
    openssl x509 -req -in "$tmp/leaf.csr" -CA "$tmp/$name-ca.pem" -CAkey "$tmp/$name-ca.key" \
        $signargs -days 3650 \
        -extfile "$tmp/leaf.ext" -set_serial 2 -out "$tmp/$name-leaf.pem" 2>/dev/null
    openssl verify -CAfile "$tmp/$name-ca.pem" "$tmp/$name-leaf.pem" >/dev/null
    openssl x509 -in "$tmp/$name-ca.pem" -outform DER -out "$name-ca.der"
    openssl x509 -in "$tmp/$name-leaf.pem" -outform DER -out "$name-leaf.der"
}

gen p256-sha256 "-algorithm EC -pkeyopt ec_paramgen_curve:P-256" "-sha256"
gen p256-sha384 "-algorithm EC -pkeyopt ec_paramgen_curve:P-256" "-sha384"
gen p384-sha256 "-algorithm EC -pkeyopt ec_paramgen_curve:P-384" "-sha256"
gen p384-sha384 "-algorithm EC -pkeyopt ec_paramgen_curve:P-384" "-sha384"
gen p521-sha256 "-algorithm EC -pkeyopt ec_paramgen_curve:P-521" "-sha256"
gen p521-sha512 "-algorithm EC -pkeyopt ec_paramgen_curve:P-521" "-sha512"
gen rsa-pss-sha256 "-algorithm RSA -pkeyopt rsa_keygen_bits:2048" \
    "-sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sigopt rsa_mgf1_md:sha256"
gen rsa-pss-sha512 "-algorithm RSA -pkeyopt rsa_keygen_bits:2048" \
    "-sha512 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:64 -sigopt rsa_mgf1_md:sha512"
gen rsa-pss-key "-algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_pss_keygen_md:sha256 -pkeyopt rsa_pss_keygen_mgf1_md:sha256 -pkeyopt rsa_pss_keygen_saltlen:32" \
    "-sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sigopt rsa_mgf1_md:sha256"
gen ed25519 "-algorithm ED25519" ""
