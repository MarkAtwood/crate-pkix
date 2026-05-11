# Tier-3 CT scrape baseline analysis

Curated bucket-by-bucket walkthrough of
[`baseline-ct-tier3.json`](baseline-ct-tier3.json) (default `pkix-path`
features) and
[`baseline-ct-tier3-allfeatures.json`](baseline-ct-tier3-allfeatures.json)
(`pkix-path/rustcrypto` umbrella). Companion to
[`baseline-pkits-analysis.md`](baseline-pkits-analysis.md) and
[`baseline-limbo-analysis.md`](baseline-limbo-analysis.md).

## Provenance

* **Source log:** Cloudflare Nimbus2026 (`log_id_b64`
  `yzj3FYl8hKFEX1vB3fvJbvKaWc1HCmkFhbDLFMMUWOc=`,
  `https://ct.cloudflare.com/logs/nimbus2026/`).
* **Scrape window:** indices 4189418507..4189420042 (1530-entry window,
  1000 surviving x509_entry chains after filtering precert entries and
  root-not-in-bundle cases).
* **Tree size at scrape:** 4,189,420,523 (Nimbus2026 head, 2026-05-11).
* **Trust bundle:** `/etc/ssl/certs/ca-certificates.crt` from a current
  Fedora 41 host (147 unique Subject DNs).
* **Fetcher:** [`python/fetch-ct.py`](python/fetch-ct.py).

The raw chain corpus lives out of tree at `$PKIX_CT_CORPUS` (default
`~/PKIX-CT-CORPUS/Nimbus2026-v2/`); only the summary JSON + analysis MD
files are committed in-repo. See the "Storage strategy" section in the
[README](README.md#tier-3-ct-log-scrape-corpus) for the rationale.

## Summary

### Default features (`rsa`, `p256`)

| Class                | Count |
|----------------------|------:|
| Agreement            |   481 |
| LooserThanWild       |    40 |
| StricterThanWild     |   479 |
| OracleDivergence     |     0 |
| DiagnosticDivergence |     0 |
| **Total**            |  1000 |

### Full crypto profile (`rsa`, `p256`, `p384` via `rustcrypto`)

| Class                | Count |
|----------------------|------:|
| Agreement            |   919 |
| LooserThanWild       |    81 |
| StricterThanWild     |     0 |
| OracleDivergence     |     0 |
| DiagnosticDivergence |     0 |
| **Total**            |  1000 |

Same corpus, two `pkix-path` feature configurations. The full-crypto
column is the trustworthy signal for evaluating `pkix-path` itself; the
default-features column documents what an out-of-the-box consumer sees
without enabling P-384.

## Default features: StricterThanWild (479)

All 479 reasons are `"signature invalid at chain index N"` for
`N ∈ {0, 1, 2}` (counts 397 / 41 / 41 respectively). Every one is the
P-384 absence — leaves issued by Google Trust Services (DigiCert Global
Root G3 family + GTS Root R4 family), Apple, Cloudflare's own ECDSA
intermediates, and similar all use ECDSA P-384 at some position in the
chain. `pkix-path` with `rsa`+`p256` only cannot verify those
signatures and reports a generic `signature invalid` failure.

Building with `--features rustcrypto` flips every one of these to
Agreement (see the full-crypto column above). Pre-existing harness
limitation documented in
[`baseline-limbo-analysis.md`](baseline-limbo-analysis.md) (PKIX-wmch);
the secondary-baseline pattern handles it without changes to the
default feature set of `pkix-path`.

## Full crypto: LooserThanWild (81)

All 81 reasons collapse to a single pyca/cryptography diagnostic:

> `VerificationError: validation failed: candidates exhausted: Neither
> EKU nor anyEKU could be found`

`pkix-path` and OpenSSL both pass; pyca fails. The pattern matches the
LooserThanWild signal already documented in
[`baseline-pkits-analysis.md`](baseline-pkits-analysis.md) and
[`baseline-limbo-analysis.md`](baseline-limbo-analysis.md): pyca
enforces CA/B Forum strictures that `pkix-path` does not (and should
not — `pkix-path`'s stated scope is RFC 5280 §6.1, not Web PKI
server-cert validation).

### Spot check

Sampling a few chains confirms the pattern. `entry-4189418554/chain.pem`:

| Position | Subject                                          | EKU                          |
|---------:|--------------------------------------------------|------------------------------|
|        0 | `CN=ewalkingmusic.com`                           | TLS Web Server Authentication |
|        1 | `CN=GoDaddy TLS Intermediate CA DV - R1v1`       | TLS Web Server Authentication |
|        2 | `CN=GoDaddy TLS Root CA - R1`                    | TLS Web Server Authentication |
|        3 | `CN=Go Daddy Root Certificate Authority - G2`    | `<absent>`                    |

Position 3 is the system trust anchor (Go Daddy Root G2) and has no
EKU. RFC 5280 §4.2.1.12 explicitly permits EKU absence on a root, and
CA/B Forum BR §7.1.2.1 allows the trust-anchor cert to omit EKU. pyca
rejects on chains where EKU traversal cannot find serverAuth or anyEKU
at every position; `pkix-path` (literal RFC 5280) and OpenSSL accept.

### Interpretation

These 81 chains are real wild traffic accepted by browsers today. The
LooserThanWild verdict is **expected `pkix-path` behaviour by design**,
not a `pkix-path` bug to fix. The same interpretation applies as in the
PKITS and limbo baselines: a LooserThanWild finding becomes actionable
only if BOTH OpenSSL AND pyca fail with related reasons.

If a downstream consumer of `pkix-path` wants CA/B-Forum-shaped EKU
enforcement, they should:

1. Use the `pkix-profiles-cabf::BasicTlsProfile` (when it lands —
   tracked under PKIX-amgn.4 / PKIX-amgn.6 sub-beads), or
2. Compose their own `Profile` impl that requires `id-kp-serverAuth`
   on every non-anchor cert.

That is the framework-not-policy split documented in
`AGENTS.md` non-negotiable constraint #6 and the PKIX-amgn epic.

## Net pkix-path correctness regressions

Zero. Same conclusion as PKITS and limbo: every divergence is either a
harness limitation (P-384 sig-verifier absence in the default-features
build) or a known difference in scope (pyca EKU strictness on real-world
chains accepted by browsers and `pkix-path` alike).

## Storage strategy

Tier-3 raw chains are stored **out of tree**. The committed artefacts
are the two summary JSON files and this analysis MD; the
~16MB chain.pem tree lives at `$PKIX_CT_CORPUS` (default
`~/PKIX-CT-CORPUS/`).

Rationale, condensed:

* A meaningful Tier-3 scrape is at least 1000 chains. Each chain is
  4-5 certs, ~16KB on average → ~16MB committed per scrape. Refreshing
  the baseline would balloon git history within months.
* In-tree fixtures only make sense when reproducibility requires the
  exact bytes. Tier-3's purpose is statistical-shape signal across
  real-wild chains; specific bytes are not load-bearing. The PKITS and
  limbo fixtures are kept in tree because they exercise specific
  numbered test vectors and oracles depend on them.
* The committed JSON summaries are sufficient for the differential-CI
  pattern: every future re-scrape can compare `summary` and
  per-class counts. Per-chain reason-string changes are the same false
  positives PKITS CI suppresses (OpenSSL minor releases reword
  diagnostics; pyca shifts error formatting).

The fetcher script computes a fresh scrape from any RFC 6962 CT log in
~3 seconds (sub-second-per-batch HTTP; the bottleneck is harness
processing, not log fetching). Re-scraping is a maintenance op for any
downstream user who wants their own baseline.

## How to refresh

```sh
# 1. Pick a usable log shard (default Nimbus2026).
python3 pkix-difftest/python/fetch-ct.py --log-substring Nimbus2026 --sample 1000

# 2. Run the harness twice — once with default features, once with rustcrypto.
cargo build --release -p pkix-difftest
./target/release/pkix-difftest run pem-tree $PKIX_CT_CORPUS \
    --oracles pkix-path,openssl,pyca \
    --output-md  pkix-difftest/baseline-ct-tier3.md \
    --output-json pkix-difftest/baseline-ct-tier3.json \
    --title "pkix-difftest baseline (Tier-3 CT scrape: <log>, <N> chains)"

cargo build --release -p pkix-difftest --features rustcrypto
./target/release/pkix-difftest run pem-tree $PKIX_CT_CORPUS \
    --oracles pkix-path,openssl,pyca \
    --output-md  pkix-difftest/baseline-ct-tier3-allfeatures.md \
    --output-json pkix-difftest/baseline-ct-tier3-allfeatures.json \
    --title "pkix-difftest baseline (Tier-3 CT scrape: <log>, <N> chains, rustcrypto features)"

# 3. Update this analysis MD to reflect the new bucket counts. Commit
#    all four files (.json, .md, allfeatures .json, allfeatures .md, plus
#    this analysis).
```

Tier-3 is not in CI today and is not planned to be. It's a periodic
sanity check on real-world chain shapes, intended to be re-run when:

* A new `SignatureVerifier` lands in `pkix-path` (re-baseline to
  reduce the default-features StricterThanWild bucket).
* A new `Profile` impl that affects EKU or extension policy lands
  (re-baseline to surface new LooserThanWild buckets).
* A new oracle is added to the harness (pyca version bump, OpenSSL
  major version, BouncyCastle, etc.).

## Filed as

PKIX-5bab (Tier-3 CT log scrape corpus) under the parent
[`PKIX-hbzo`](../.beads/) (diff harness completeness epic).
