#!/bin/sh
# Regenerate the self-issued key-rollover chain for
# tests/review_self_issued_rollover.rs (GitHub issue #11; x509-limbo
# rfc5280::nc::permitted-self-issued, rebuilt with the OpenSSL CLI).
#
#   root.der         CN=not-example.com, SAN not-example.com, critical
#                    NameConstraints permitted DNS example.com (trust anchor)
#   ica.der          same name as root (self-issued), new key, signed by root
#   leaf.der         empty subject, SAN example.com, serverAuth, signed by ica
#   forged-root.der  CN=not-example.com again, but a third, unrelated key
#
# Validity: 36500 days from generation; tests evaluate at 2027-01-01Z.
# Usage: sh gen.sh
set -eu
cd "$(dirname "$0")"
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
for k in root ica leaf forged; do
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$T/$k.key" 2>/dev/null
done
cat > "$T/ext.cnf" <<'CNF'
[ica]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
subjectAltName = DNS:not-example.com
[leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
subjectAltName = critical,DNS:example.com
extendedKeyUsage = serverAuth
CNF
N="/CN=not-example.com"
openssl req -new -x509 -key "$T/root.key" -subj "$N" -days 36500 -set_serial 1 -sha256 \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectAltName=DNS:not-example.com" \
    -addext "nameConstraints=critical,permitted;DNS:example.com" -outform DER -out root.der
openssl req -new -x509 -key "$T/forged.key" -subj "$N" -days 36500 -set_serial 1 -sha256 \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -outform DER -out forged-root.der
openssl req -new -key "$T/ica.key" -subj "$N" -out "$T/ica.csr"
openssl x509 -req -in "$T/ica.csr" -CA root.der -CAform DER -CAkey "$T/root.key" -set_serial 2 \
    -days 36500 -sha256 -extfile "$T/ext.cnf" -extensions ica -outform DER -out ica.der
openssl req -new -key "$T/leaf.key" -subj "/" -out "$T/leaf.csr"
openssl x509 -req -in "$T/leaf.csr" -CA ica.der -CAform DER -CAkey "$T/ica.key" -set_serial 3 \
    -days 36500 -sha256 -extfile "$T/ext.cnf" -extensions leaf -outform DER -out leaf.der

for f in root ica leaf forged-root; do openssl x509 -inform DER -in $f.der -out "$T/$f.pem"; done
openssl verify -x509_strict -CAfile "$T/root.pem" -untrusted "$T/ica.pem" "$T/leaf.pem"
# Must fail: the forged anchor shares the name but not the key.
if openssl verify -CAfile "$T/forged-root.pem" -untrusted "$T/ica.pem" "$T/leaf.pem" 2>/dev/null; then
    echo "forged anchor unexpectedly accepted" >&2; exit 1
fi
