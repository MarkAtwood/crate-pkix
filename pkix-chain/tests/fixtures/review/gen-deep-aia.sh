#!/usr/bin/env bash
# Fixtures for the AIA depth-cap boundary in review_aia.rs.
#
# A chain that can only be assembled by fetching each hop in sequence:
# every intermediate's issuer is discoverable solely from the caIssuers
# URI of the certificate below it, so resolving the chain takes exactly
# as many fetch rounds as there are intermediates. That makes the
# AIA_MAX_DEPTH boundary observable — the fifth fetch is the one that
# completes the chain, and it only helps if a build attempt runs after
# it.
#
#   deep-root               anchor
#   └── deep-i5             signed by root; its issuer IS the anchor
#       └── deep-i4         caIssuers -> deep-i5.der
#           └── deep-i3     caIssuers -> deep-i4.der
#               └── deep-i2 caIssuers -> deep-i3.der
#                   └── deep-i1     caIssuers -> deep-i2.der
#                       └── deep-leaf  caIssuers -> deep-i1.der
#
# Supplying only deep-leaf therefore needs 5 sequential fetches.
# All keys P-256, ecdsa-with-SHA256, 36500 days (NOW_UNIX = 1_900_000_000).
#
# Run from anywhere:  bash pkix-chain/tests/fixtures/review/gen-deep-aia.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
cd "$W"

key() { openssl ecparam -name prime256v1 -genkey -noout -out "$1.key" 2>/dev/null; }
mk() {
  local name=$1 subj=$2 issuer=$3 ext=$4
  [ -f "$name.key" ] || key "$name"
  openssl req -new -key "$name.key" -subj "$subj" -out "$name.csr" 2>/dev/null
  if [ "$issuer" = self ]; then
    openssl x509 -req -in "$name.csr" -signkey "$name.key" -days 36500 -sha256 \
      -set_serial "0x$(openssl rand -hex 8)" -extfile "$ext" -out "$name.pem" 2>/dev/null
  else
    openssl x509 -req -in "$name.csr" -CA "$issuer.pem" -CAkey "$issuer.key" -days 36500 -sha256 \
      -set_serial "0x$(openssl rand -hex 8)" -extfile "$ext" -out "$name.pem" 2>/dev/null
  fi
  openssl x509 -in "$name.pem" -outform DER -out "$name.der"
}

# A CA extension file whose caIssuers URI points at $1 (empty for none).
ca_ext() {
  {
    printf 'basicConstraints=critical,CA:TRUE\n'
    printf 'keyUsage=critical,keyCertSign,cRLSign\n'
    printf 'subjectKeyIdentifier=hash\n'
    printf 'authorityKeyIdentifier=keyid\n'
    if [ -n "$1" ]; then
      printf 'authorityInfoAccess=caIssuers;URI:http://aia.test/%s.der\n' "$1"
    fi
  } > "ca-$2.ext"
}

ca_ext "" root
mk deep-root "/CN=Deep Root" self ca-root.ext

# i5's issuer is the anchor itself, so it needs no caIssuers URI.
ca_ext "" i5
mk deep-i5 "/CN=Deep I5" deep-root ca-i5.ext

ca_ext deep-i5 i4; mk deep-i4 "/CN=Deep I4" deep-i5 ca-i4.ext
ca_ext deep-i4 i3; mk deep-i3 "/CN=Deep I3" deep-i4 ca-i3.ext
ca_ext deep-i3 i2; mk deep-i2 "/CN=Deep I2" deep-i3 ca-i2.ext
ca_ext deep-i2 i1; mk deep-i1 "/CN=Deep I1" deep-i2 ca-i1.ext

cat > leaf.ext <<X
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
authorityInfoAccess=caIssuers;URI:http://aia.test/deep-i1.der
X
mk deep-leaf "/CN=deep-leaf.review.test" deep-i1 leaf.ext

for f in deep-root deep-i5 deep-i4 deep-i3 deep-i2 deep-i1 deep-leaf; do
  cp "$f.der" "$HERE/$f.der"
done
echo "wrote deep-root deep-i{1..5} deep-leaf to $HERE"
