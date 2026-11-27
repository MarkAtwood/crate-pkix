#!/bin/sh
# Generate a conforming RFC 5755 Attribute Authority certificate.
#
# Why this exists: the AC fixtures were originally signed by pkix-ct's
# precert-issuer, which is CA:TRUE with keyUsage "Certificate Sign, CRL
# Sign". RFC 5755 §4.5 forbids both for an AC issuer — "an AC issuer
# cannot be a CA as well", and keyUsage must not exclude
# digitalSignature — so those fixtures could never pass a conforming
# end-to-end validation, only the signature arithmetic in isolation.
#
# This creates an authority that can: cA=FALSE, keyUsage
# digitalSignature, issued by the same self-signed root, so that root
# stays the single trust anchor for both the holder and the authority.
#
# `openssl ca` rather than `openssl x509 -req`: this OpenSSL (3.0) has no
# -not_before/-not_after on x509, and fixture dates must be fixed rather
# than relative to the day the script ran.
set -eu
CT=../../../pkix-ct/tests/fixtures/sct-oracle
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

openssl x509 -in "$CT/precert-issuer.der" -inform DER -out "$WORK/root.pem"
cp "$CT/precert-issuer-key.pem" "$WORK/root-key.pem"

mkdir -p "$WORK/newcerts"
: > "$WORK/index.txt"
echo 01 > "$WORK/serial"

cat > "$WORK/ca.cnf" <<'CNF'
[ca]
default_ca = CA_default
[CA_default]
database         = $ENV::WORK/index.txt
new_certs_dir    = $ENV::WORK/newcerts
serial           = $ENV::WORK/serial
certificate      = $ENV::WORK/root.pem
private_key      = $ENV::WORK/root-key.pem
default_md       = sha256
policy           = policy_any
email_in_dn      = no
rand_serial      = no
unique_subject   = no
copy_extensions  = none
[policy_any]
commonName = supplied
[aa_ext]
basicConstraints     = critical,CA:FALSE
keyUsage             = critical,digitalSignature
subjectKeyIdentifier = hash
CNF

openssl ecparam -name prime256v1 -genkey -noout -out aa-key.pem
openssl req -new -key aa-key.pem -subj "/CN=pkix-ac attribute authority" -out "$WORK/aa.csr"

WORK="$WORK" openssl ca -batch -config "$WORK/ca.cnf" \
  -in "$WORK/aa.csr" -extensions aa_ext \
  -startdate 20250101000000Z -enddate 20350101000000Z \
  -out "$WORK/aa.pem" >/dev/null 2>&1

openssl x509 -in "$WORK/aa.pem" -out aa-cert.der -outform DER

echo "--- aa-cert.der ---"
openssl x509 -in aa-cert.der -inform DER -noout -subject -issuer -dates \
  -ext basicConstraints,keyUsage
