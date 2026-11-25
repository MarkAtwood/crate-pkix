#!/usr/bin/env bash
# Fixtures for the "NoValidPath" AIA-recovery case in review_aia.rs.
#
# Distinct from gen.sh's `bogus*` certs, which are SELF-issued: those give
# no topological path to the anchor at all, so the path builder reports
# NoPathFound and the AIA seam runs. The case that needs its own fixtures
# is the one where topology DOES complete to the anchor and only the
# signature is wrong, because that is what makes build_first_valid_path
# report NoValidPath instead.
#
# Hierarchy (all keys P-256, ecdsa-with-SHA256, 36500 days so NOW_UNIX =
# 1_900_000_000 is inside the window):
#
#   nvp-root            anchor
#   ├── nvp-int         CN=NVP Int, signed by root  — the correct one
#   └── nvp-int-wrong   CN=NVP Int, signed by root, DIFFERENT key
#       └── nvp-leaf    signed by nvp-int, caIssuers -> http://aia.test/nvp-int.der
#
# Both intermediates share a subject DN and both chain to the anchor, so a
# pool holding only the wrong one yields a topologically complete chain
# that fails on signature.
#
# Run from anywhere:  bash pkix-chain/tests/fixtures/review/gen-novalidpath.sh
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

cat > ca.ext <<X
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
X
cat > int.ext <<X
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
X
cat > leaf.ext <<X
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
authorityInfoAccess=caIssuers;URI:http://aia.test/nvp-int.der
X

mk nvp-root  "/CN=NVP Root" self     ca.ext
mk nvp-int   "/CN=NVP Int"  nvp-root int.ext
# Same subject DN, same issuer, its own key. `mk` generates a key only when
# one is absent, so the distinct name gives a distinct key.
mk nvp-int-wrong "/CN=NVP Int" nvp-root int.ext
mk nvp-leaf  "/CN=nvp-leaf.review.test" nvp-int leaf.ext

for f in nvp-root nvp-int nvp-int-wrong nvp-leaf; do
  cp "$f.der" "$HERE/$f.der"
done
echo "wrote nvp-root.der nvp-int.der nvp-int-wrong.der nvp-leaf.der to $HERE"
