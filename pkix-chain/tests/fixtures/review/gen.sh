#!/usr/bin/env bash
# Generate DER fixtures for review_*.rs tests in pkix-chain and
# pkix-path-builder. Oracle: OpenSSL CLI (>= 3.0). All keys P-256,
# signatures ecdsa-with-SHA256, validity = generation time + 36500 days
# (tests use NOW_UNIX = 1_900_000_000, 2030-03-17).
#
# Run from anywhere:  bash pkix-chain/tests/fixtures/review/gen.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PB="$HERE/../../../../pkix-path-builder/tests/fixtures/review"
mkdir -p "$PB"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
cd "$W"

key() { openssl ecparam -name prime256v1 -genkey -noout -out "$1.key" 2>/dev/null; }
# mk NAME SUBJ ISSUER_NAME(or self) EXTFILE  -> NAME.pem / NAME.der
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
cat > leaf.ext <<X
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
authorityInfoAccess=caIssuers;URI:http://aia.test/int.der
X

# --- Basic 3-tier hierarchy -------------------------------------------------
mk root "/CN=Review Root" self ca.ext
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > int.ext
mk int "/CN=Review Int" root int.ext
mk leaf "/CN=leaf.review.test" int leaf.ext
# certs-only PKCS#7 (RFC 5280 4.2.2.1 / RFC 2797) wrapping int.der
openssl crl2pkcs7 -nocrl -certfile int.pem -outform DER -out int.p7c

# --- Leaf with many caIssuers URIs (AIA fan-out) ----------------------------
{
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
  printf 'authorityInfoAccess='
  for i in $(seq 0 63); do
    [ "$i" -gt 0 ] && printf ','
    printf 'caIssuers;URI:http://aia.test/fan/%d.der' "$i"
  done
  printf '\n'
} > fan.ext
mk leaf-fan64 "/CN=fan.review.test" int fan.ext

# --- AIA fan-out relays ------------------------------------------------------
# relay-I (I = 0..63): non-CA cert issued by an unpublished "CN=Missing CA",
# carrying 64 distinct caIssuers URIs http://aia.test/r/I/J. Served by the
# test fetcher in answer to http://aia.test/fan/I (leaf-fan64's URIs).
mk missing "/CN=Missing CA" self ca.ext
for i in $(seq 0 63); do
  {
    printf 'basicConstraints=critical,CA:FALSE\nauthorityInfoAccess='
    for j in $(seq 0 63); do
      [ "$j" -gt 0 ] && printf ','
      printf 'caIssuers;URI:http://aia.test/r/%d/%d' "$i" "$j"
    done
    printf '\n'
  } > relay.ext
  mk "relay-$i" "/CN=Relay $i" missing relay.ext
  cp "relay-$i.der" "$HERE/"
done

# --- Path-builder adversarial pool -----------------------------------------
# N self-issued CA certs, subject = issuer = "CN=Review Int", all with the
# SAME SubjectKeyIdentifier as the real `int` (SKI is attacker-chosen
# bytes), each with its own key. Signed by their own key (garbage w.r.t.
# chain validation). The real `int` (signed by root) is appended last.
INT_SKI=$(openssl x509 -in int.pem -noout -ext subjectKeyIdentifier | tail -1 | tr -d ' ')
for i in $(seq 0 39); do
  printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\nsubjectKeyIdentifier=%s\n' "$INT_SKI" > bogus.ext
  mk "bogus$i" "/CN=Review Int" self bogus.ext
  cp "bogus$i.der" "$PB/bogus-int-$i.der"
done

# --- GitHub #11: key rollover under a same-name anchor --------------------
# roll-root: anchor "CN=Review Roll" (key R). roll-ica: same name, new key
# I, signed by R (self-issued). roll-leaf: issued by roll-ica (key I).
mk roll-root "/CN=Review Roll" self ca.ext
mk roll-ica "/CN=Review Roll" roll-root int.ext
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nauthorityKeyIdentifier=keyid\n' > rleaf.ext
mk roll-leaf "/CN=roll.review.test" roll-ica rleaf.ext
cp roll-root.der roll-ica.der roll-leaf.der "$PB/"

cp root.der int.der leaf.der int.p7c leaf-fan64.der "$HERE/"
cp root.der int.der leaf.der "$PB/"
echo "ok"
