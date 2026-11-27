#!/usr/bin/env bash
# Fixtures for the PKIX-skxt composition hazard: a CA that constrains
# dNSName names, and a leaf that carries its name only in the Subject CN.
#
# The CN is deliberately OUTSIDE the permitted subtree. RFC 5280 §4.2.1.10
# applies dNSName constraints "only to the corresponding name type in
# subjectAltName", so a leaf with no SAN passes them vacuously -- and RFC 7672
# §3.2.3 would then match that CN. Together they let this CA vouch for
# evil.example despite being constrained to good.example.
#
# Both certificates carry FIXED validity dates via `openssl ca`, which is the
# only OpenSSL 3.0 entry point that can set them (`req -x509` and `x509 -req`
# have no -not_before). Regeneration must not move them: the tests pin a
# clock inside this window, and a notBefore of "whenever this was last run"
# would break them in a later year.
#
# Requires nothing but openssl 3.x and bash. DER only.
set -euo pipefail
cd "$(dirname "$0")"

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
export WORK
mkdir -p "$WORK/newcerts"; : > "$WORK/index.txt"; echo 01 > "$WORK/serial"

cat > "$WORK/ca.cnf" <<'CNF'
[req]
distinguished_name = dn
prompt             = no
[dn]
CN = PKIX-skxt constrained CA

[ca]
default_ca = CA_default
[CA_default]
dir              = $ENV::WORK
database         = $ENV::WORK/index.txt
new_certs_dir    = $ENV::WORK/newcerts
serial           = $ENV::WORK/serial
certificate      = $ENV::WORK/ca.pem
private_key      = $ENV::WORK/ca.key
default_md       = sha256
policy           = policy_any
email_in_dn      = no
rand_serial      = no
unique_subject   = no
copy_extensions  = none
[policy_any]
commonName = supplied

# Constrained to good.example. Critical, as RFC 5280 SHOULD.
[ca_ext]
basicConstraints = critical,CA:TRUE
keyUsage         = critical,keyCertSign
nameConstraints  = critical,permitted;DNS:good.example

# No subjectAltName at all: that omission is the point.
[leaf_ext]
basicConstraints = critical,CA:FALSE
keyUsage         = critical,digitalSignature
CNF

# The CA, self-signed through `openssl ca -selfsign` so the dates are fixed.
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/ca.key"
openssl req -new -key "$WORK/ca.key" -config "$WORK/ca.cnf" -out "$WORK/ca.csr"
openssl ca -batch -config "$WORK/ca.cnf" -selfsign -keyfile "$WORK/ca.key" \
  -in "$WORK/ca.csr" -extensions ca_ext \
  -startdate 20260101000000Z -enddate 20360101000000Z \
  -out "$WORK/ca.pem" >/dev/null 2>&1
openssl x509 -in "$WORK/ca.pem" -out ca-constrained.der -outform DER

# The leaf: CN=evil.example, outside the CA's permitted subtree, no SAN.
cat > "$WORK/leaf.cnf" <<'CNF'
[req]
distinguished_name = dn
prompt             = no
[dn]
CN = evil.example
CNF
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/leaf.key"
openssl req -new -key "$WORK/leaf.key" -config "$WORK/leaf.cnf" -out "$WORK/leaf.csr"
openssl ca -batch -config "$WORK/ca.cnf" -in "$WORK/leaf.csr" \
  -extensions leaf_ext \
  -startdate 20260101000000Z -enddate 20360101000000Z \
  -out "$WORK/leaf.pem" >/dev/null 2>&1
openssl x509 -in "$WORK/leaf.pem" -out leaf-cn-only.der -outform DER

for f in ca-constrained.der leaf-cn-only.der; do
  echo "== $f"
  openssl x509 -in "$f" -inform DER -noout -subject -dates | sed 's/^/  /'
  openssl x509 -in "$f" -inform DER -noout -text \
    | grep -A2 -E 'Name Constraints|Subject Alternative Name' | sed 's/^/  /' || true
done
