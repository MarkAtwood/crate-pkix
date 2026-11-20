#!/bin/sh
# Regenerate miscellaneous review fixtures (tests/review_misc.rs).
# Validity: 36500 days from generation; tests evaluate at 2027-01-01Z.
# Usage: sh gen.sh
set -eu
cd "$(dirname "$0")"
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

ec()  { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$T/$1.key" 2>/dev/null; }
rsa() { openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:"$2" -out "$T/$1.key" 2>/dev/null; }
root() { # name subject
    openssl req -new -x509 -key "$T/$1.key" -subj "$2" -days 36500 -set_serial 1 \
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -sha256 -outform DER -out "$1.der"
}
issue() { # name subject issuer serial extsection
    openssl req -new -key "$T/$1.key" -subj "$2" -out "$T/$1.csr"
    openssl x509 -req -in "$T/$1.csr" -CA "$3.der" -CAform DER -CAkey "$T/$3.key" \
        -set_serial "$4" -days 36500 -extfile "$T/ext.cnf" -extensions "$5" -sha256 \
        -outform DER -out "$1.der"
}
cat > "$T/ext.cnf" <<'CNF'
[leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
[leaf_p]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
certificatePolicies = 1.3.6.1.4.1.55555.2.1
# Intermediate asserting P and mapping P->P then P->Q (order matters for the bug).
[ca_map_identity_first]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
certificatePolicies = 1.3.6.1.4.1.55555.2.1
policyMappings = 1.3.6.1.4.1.55555.2.1:1.3.6.1.4.1.55555.2.1,1.3.6.1.4.1.55555.2.1:1.3.6.1.4.1.55555.2.2
# Same mappings, opposite order (control).
[ca_map_identity_last]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
certificatePolicies = 1.3.6.1.4.1.55555.2.1
policyMappings = 1.3.6.1.4.1.55555.2.1:1.3.6.1.4.1.55555.2.2,1.3.6.1.4.1.55555.2.1:1.3.6.1.4.1.55555.2.1
# Base for the duplicate-basicConstraints intermediate; prepend_ext.py later
# inserts a second, critical CA:TRUE basicConstraints in front of this one.
[ca_dup_bc]
basicConstraints = critical,CA:FALSE
keyUsage = critical,keyCertSign,cRLSign
[ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
CNF

# --- RSA-8192 root signing an EC leaf (valid; rsa crate caps keys at 4096 bits).
rsa rsa8192-root 8192
root rsa8192-root "/CN=review rsa8192 root"
ec rsa8192-leaf
issue rsa8192-leaf "/CN=review rsa8192 leaf" rsa8192-root 2 leaf

# --- RSA-1024 trust anchor signing an RSA-2048 leaf (min_rsa_key_bits coverage).
rsa rsa1024-root 1024
root rsa1024-root "/CN=review rsa1024 root"
rsa rsa1024-leaf 2048
issue rsa1024-leaf "/CN=review rsa1024 leaf" rsa1024-root 2 leaf

# --- Policy mapping order: root -> CA (maps P->P, P->Q) -> leaf asserting P.
ec map-root
root map-root "/CN=review map root"
ec map-ca-first
issue map-ca-first "/CN=review map ca identity first" map-root 2 ca_map_identity_first
ec map-ca-last
issue map-ca-last "/CN=review map ca identity last" map-root 3 ca_map_identity_last
ec map-leaf-first
issue map-leaf-first "/CN=review map leaf" map-ca-first 4 leaf_p
ec map-leaf-last
issue map-leaf-last "/CN=review map leaf" map-ca-last 5 leaf_p

# --- Duplicate basicConstraints on an intermediate: root -> dupbc-ca -> leaf.
ec dupbc-root
root dupbc-root "/CN=review dupbc root"
ec dupbc-ca
issue dupbc-ca "/CN=review dupbc ca" dupbc-root 2 ca_dup_bc
# Extension ::= SEQ { 2.5.29.19, critical TRUE, OCTET STRING { SEQ { cA TRUE } } }
python3 -I prepend_ext.py dupbc-ca.der "$T/dupbc-root.key" 300f0603551d130101ff040530030101ff dupbc-ca.der
ec dupbc-leaf
issue dupbc-leaf "/CN=review dupbc leaf" dupbc-ca 3 leaf

# --- id-RSASSA-PSS subject keys (1024 and 2048 bits) on leaves under an EC
#     root: min_rsa_key_bits must treat RSASSA-PSS keys as RSA.
ec pss-root
root pss-root "/CN=review pss-key root"
openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:1024 -out "$T/pss1024-leaf.key" 2>/dev/null
issue pss1024-leaf "/CN=review pss1024 leaf" pss-root 2 leaf
openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -out "$T/pss2048-leaf.key" 2>/dev/null
issue pss2048-leaf "/CN=review pss2048 leaf" pss-root 3 leaf

# Sanity: OpenSSL accepts the well-formed chains ...
pem() { openssl x509 -inform DER -in "$1.der" -out "$T/$1.pem"; }
for f in rsa8192-root rsa8192-leaf rsa1024-root rsa1024-leaf map-root map-ca-first \
         map-ca-last map-leaf-first map-leaf-last dupbc-root dupbc-ca dupbc-leaf \
         pss-root pss1024-leaf pss2048-leaf; do pem $f; done
openssl verify -CAfile "$T/rsa8192-root.pem" "$T/rsa8192-leaf.pem"
openssl verify -CAfile "$T/rsa1024-root.pem" "$T/rsa1024-leaf.pem"
openssl verify -CAfile "$T/pss-root.pem" "$T/pss1024-leaf.pem" "$T/pss2048-leaf.pem"
openssl verify -explicit_policy -policy 1.3.6.1.4.1.55555.2.1 -CAfile "$T/map-root.pem" \
    -untrusted "$T/map-ca-first.pem" "$T/map-leaf-first.pem"
openssl verify -explicit_policy -policy 1.3.6.1.4.1.55555.2.1 -CAfile "$T/map-root.pem" \
    -untrusted "$T/map-ca-last.pem" "$T/map-leaf-last.pem"
# ... and rejects the duplicate-extension intermediate (expected to print an error).
openssl verify -CAfile "$T/dupbc-root.pem" -untrusted "$T/dupbc-ca.pem" "$T/dupbc-leaf.pem" || true
