#!/bin/sh
# Regenerate the policy-tree blow-up chain for tests/review_policy_blowup.rs
# (CVE-2023-0464-style exponential valid_policy_tree growth).
#
#   root.der           self-signed P-256 trust anchor (no policy extensions)
#   ca1.der .. caL.der intermediates; ca<d> asserts K policies
#                      1.3.6.1.4.1.55555.1.<d>.<j> and maps every one of them
#                      to every level-(d+1) policy (K*K mappings)
#   leaf.der           asserts the K level-(L+1) policies
#
# RFC 5280's literal tree then has K^d nodes at depth d (K^(L+1) at the
# leaf).  Defaults K=10, L=4 -> 100000 leaf-depth nodes from a 6-cert chain
# whose certificates are each < 3.5 KiB.
#
# Validity: 36500 days from generation; tests evaluate at 2027-01-01Z.
# Usage: sh gen.sh [K] [L]
set -eu
cd "$(dirname "$0")"
K=${1:-10}
L=${2:-4}
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
ARC=1.3.6.1.4.1.55555.1

pols() { # level
    out=""; j=1
    while [ $j -le "$K" ]; do out="$out${out:+,}$ARC.$1.$j"; j=$((j+1)); done
    echo "$out"
}
maps() { # from-level
    out=""; j=1
    while [ $j -le "$K" ]; do
        l=1
        while [ $l -le "$K" ]; do
            out="$out${out:+,}$ARC.$1.$j:$ARC.$(($1+1)).$l"; l=$((l+1))
        done
        j=$((j+1))
    done
    echo "$out"
}
key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$T/$1.key" 2>/dev/null; }

key root
openssl req -new -x509 -key "$T/root.key" -subj "/CN=blowup root" -days 36500 -set_serial 1 \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -sha256 -outform DER -out root.der

issuer=root
d=1
while [ $d -le "$L" ]; do
    key "ca$d"
    cat > "$T/ca$d.cnf" <<CNF
[x]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
certificatePolicies = $(pols $d)
policyMappings = $(maps $d)
CNF
    openssl req -new -key "$T/ca$d.key" -subj "/CN=blowup ca$d" -out "$T/ca$d.csr"
    openssl x509 -req -in "$T/ca$d.csr" -CA "$issuer.der" -CAform DER -CAkey "$T/$issuer.key" \
        -set_serial $((d+1)) -days 36500 -extfile "$T/ca$d.cnf" -extensions x -sha256 \
        -outform DER -out "ca$d.der"
    issuer=ca$d
    d=$((d+1))
done

key leaf
cat > "$T/leaf.cnf" <<CNF
[x]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
certificatePolicies = $(pols $((L+1)))
CNF
openssl req -new -key "$T/leaf.key" -subj "/CN=blowup leaf" -out "$T/leaf.csr"
openssl x509 -req -in "$T/leaf.csr" -CA "$issuer.der" -CAform DER -CAkey "$T/$issuer.key" \
    -set_serial 100 -days 36500 -extfile "$T/leaf.cnf" -extensions x -sha256 \
    -outform DER -out leaf.der

# Sanity check signatures/linkage (OpenSSL >= 3.0.9 bounds policy-tree size).
for f in ca*.der; do openssl x509 -inform DER -in "$f"; done > "$T/chain.pem"
openssl x509 -inform DER -in root.der -out "$T/root.pem"
openssl x509 -inform DER -in leaf.der -out "$T/leaf.pem"
openssl verify -CAfile "$T/root.pem" -untrusted "$T/chain.pem" "$T/leaf.pem" || true
ls -l ./*.der
