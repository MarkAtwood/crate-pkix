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

# ---------------------------------------------------------------------
# A second, deeper PKI: root -> intermediate -> {authority, holder}.
#
# Every pkix-chain wrapper test used one-element chains, so the
# composition had never been exercised at depth even though real
# deployments always have intermediates. These give it a chain to walk
# on both sides at once.
# ---------------------------------------------------------------------

cat >> "$WORK/ca.cnf" <<'CNF'
[ica_ext]
basicConstraints     = critical,CA:TRUE,pathlen:0
keyUsage             = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
CNF

openssl ecparam -name prime256v1 -genkey -noout -out ica-key.pem
openssl req -new -key ica-key.pem -subj "/CN=pkix-ac intermediate CA"   -out "$WORK/ica.csr"
WORK="$WORK" openssl ca -batch -config "$WORK/ca.cnf"   -in "$WORK/ica.csr" -extensions ica_ext   -startdate 20250101000000Z -enddate 20350101000000Z   -out "$WORK/ica.pem" >/dev/null 2>&1
openssl x509 -in "$WORK/ica.pem" -out ica-cert.der -outform DER

# Now issue the deep authority and holder FROM the intermediate, by
# pointing the same CA config at it.
sed -e "s|/root.pem|/ica.pem|" -e "s|/root-key.pem|/ica-key.pem|"     "$WORK/ca.cnf" > "$WORK/ica.cnf"
cp "$WORK/ica.pem" "$WORK/ica.pem.ca"
cp ica-key.pem "$WORK/ica-key.pem"
: > "$WORK/index.txt"
echo 20 > "$WORK/serial"

openssl ecparam -name prime256v1 -genkey -noout -out aa-deep-key.pem
openssl req -new -key aa-deep-key.pem   -subj "/CN=pkix-ac deep attribute authority" -out "$WORK/aad.csr"
WORK="$WORK" openssl ca -batch -config "$WORK/ica.cnf"   -in "$WORK/aad.csr" -extensions aa_ext   -startdate 20250101000000Z -enddate 20350101000000Z   -out "$WORK/aad.pem" >/dev/null 2>&1
openssl x509 -in "$WORK/aad.pem" -out aa-deep-cert.der -outform DER

cat >> "$WORK/ica.cnf" <<'CNF'
[holder_ext]
basicConstraints     = critical,CA:FALSE
keyUsage             = critical,digitalSignature
subjectKeyIdentifier = hash
CNF
openssl ecparam -name prime256v1 -genkey -noout -out holder-deep-key.pem
openssl req -new -key holder-deep-key.pem   -subj "/CN=pkix-ac deep holder" -out "$WORK/hd.csr"
WORK="$WORK" openssl ca -batch -config "$WORK/ica.cnf"   -in "$WORK/hd.csr" -extensions holder_ext   -startdate 20250101000000Z -enddate 20350101000000Z   -out "$WORK/hd.pem" >/dev/null 2>&1
openssl x509 -in "$WORK/hd.pem" -out holder-deep-cert.der -outform DER

# An authority whose keyUsage asserts only nonRepudiation. §4.5 forbids a
# keyUsage that "explicitly indicate[s] that the AC issuer's public key
# cannot be used to validate a digital signature", and per RFC 5280
# §4.2.1.3 nonRepudiation (contentCommitment) also denotes verifying
# signatures — so this authority is permitted. Requiring
# digitalSignature specifically refused it, and the test that was meant
# to cover the change used an authority asserting digitalSignature, so
# the nonRepudiation branch was never evaluated.
cat >> "$WORK/ca.cnf" <<'CNF'
[aa_nonrep_ext]
basicConstraints     = critical,CA:FALSE
keyUsage             = critical,nonRepudiation
subjectKeyIdentifier = hash
CNF
openssl ecparam -name prime256v1 -genkey -noout -out aa-nonrep-key.pem
openssl req -new -key aa-nonrep-key.pem   -subj "/CN=pkix-ac nonrepudiation authority" -out "$WORK/aanr.csr"
WORK="$WORK" openssl ca -batch -config "$WORK/ca.cnf"   -in "$WORK/aanr.csr" -extensions aa_nonrep_ext   -startdate 20250101000000Z -enddate 20350101000000Z   -out "$WORK/aanr.pem" >/dev/null 2>&1
openssl x509 -in "$WORK/aanr.pem" -out aa-nonrep-cert.der -outform DER

# An authority whose keyUsage asserts NEITHER digitalSignature nor
# nonRepudiation, and which is not a CA. §4.5 refuses it as
# IssuerCannotSign. Every existing negative test used a CA fixture,
# which trips IssuerIsACa first -- basicConstraints is tested before
# keyUsage -- so IssuerCannotSign was never produced by any test, and
# deleting the keyUsage rule outright left the whole suite green.
cat >> "$WORK/ca.cnf" <<'CNF'
[aa_nosign_ext]
basicConstraints     = critical,CA:FALSE
keyUsage             = critical,keyEncipherment
subjectKeyIdentifier = hash
CNF
openssl ecparam -name prime256v1 -genkey -noout -out aa-nosign-key.pem
openssl req -new -key aa-nosign-key.pem \
  -subj "/CN=pkix-ac non-signing authority" -out "$WORK/aans.csr"
WORK="$WORK" openssl ca -batch -config "$WORK/ca.cnf" \
  -in "$WORK/aans.csr" -extensions aa_nosign_ext \
  -startdate 20250101000000Z -enddate 20350101000000Z \
  -out "$WORK/aans.pem" >/dev/null 2>&1
openssl x509 -in "$WORK/aans.pem" -out aa-nosign-cert.der -outform DER

for f in aa-cert.der ica-cert.der aa-deep-cert.der holder-deep-cert.der \
         aa-nonrep-cert.der aa-nosign-cert.der; do
  echo "--- $f ---"
  openssl x509 -in "$f" -inform DER -noout -subject -issuer     -ext basicConstraints,keyUsage 2>/dev/null | sed 's/^/  /'
done
