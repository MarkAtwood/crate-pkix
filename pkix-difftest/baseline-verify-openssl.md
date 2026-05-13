# `verify_*` wrapper differential — OpenSSL baseline

Per-purpose pass-rate baseline for `pkix_chain::verify_*` against
`openssl verify -purpose ...` for the umbrella bead **PKIX-fmtv.18**.

Companion: **PKIX-fmtv.19 → `baseline-verify-pyca.md`** (pyca/cryptography
oracle, TLS-only). OpenSSL is the broader-coverage oracle because its
`-purpose ...` set spans every `verify_*` wrapper the workspace ships.

## Scope by canonical purpose

| Wrapper | OpenSSL invocation | Subbead | Status |
|---|---|---|---|
| `verify_tls_server` | `-purpose sslserver -verify_hostname/-verify_ip X` | PKIX-fmtv.18.2 | shipped |
| `verify_tls_client_dns` | `-purpose sslclient -verify_hostname X` | PKIX-fmtv.18.3 | shipped |
| `verify_smime_signer` | `-purpose smimesign -verify_email X` | PKIX-fmtv.18.4 | open |
| `verify_smime_recipient` | `-purpose smimeencrypt -verify_email X` | PKIX-fmtv.18.4 | open |
| `verify_code_signer` | `-purpose codesign` | PKIX-fmtv.18.5 | open |
| `verify_time_stamper` | `-purpose timestampsign` | PKIX-fmtv.18.6 | open |
| `verify_ocsp_responder` | `-purpose ocsphelper` | PKIX-fmtv.18.7 | open |

OpenSSL version: tracked at run time — `openssl verify` is invoked from
`$PATH` (or `$PKIX_DIFFTEST_OPENSSL_BIN`). Reproducing this baseline
captures the version in stderr-via-oracle prelude logging; the row
tables are version-stable for OpenSSL ≥ 3.0.

## Oracle configuration

`pkix-difftest/src/oracles/openssl.rs` exposes
`VerifyArgs { purpose, verify_hostname, verify_email, verify_ip }` and
`verify_with_args(chain, &args)` alongside the chain-shape `verify`.
Each wrapper test passes the matching `-purpose ...` and the matching
identity flag.

OpenSSL's `-purpose ...` enforces EKU at the verifier level — unlike
pyca's `permit_all` EE policy, OpenSSL does NOT need a permissive
extension policy to surface EKU/SAN binding correctly. This makes
OpenSSL a more direct comparison surface than pyca for every wrapper.

OpenSSL also does NOT require `authorityKeyIdentifier` on the leaf
under `-purpose sslserver` (unlike pyca's `webpki_defaults_ee`), so
the minimal-extension corpus from `pkix-chain/tests/fixtures/` can be
consumed directly.

## TLS server (PKIX-fmtv.18.2)

**23 / 23 cases produced a verdict on both sides.**
**23 / 23 in agreement** (100%). **0 Rust-looser, 0 Rust-stricter.**

| # | Case | Rust | OpenSSL | Agreement |
|---|---|---|---|---|
| 1 | `exact_match` | Ok | pass | Agree |
| 2 | `exact_mismatch` | NoMatchingSan | fail | Agree |
| 3 | `exact_parent_does_not_match` | NoMatchingSan | fail | Agree |
| 4 | `wildcard_matches_single_label` | Ok | pass | Agree |
| 5 | `wildcard_parent_rejected` | NoMatchingSan | fail | Agree |
| 6 | `wildcard_deeper_rejected` | NoMatchingSan | fail | Agree |
| 7 | `wildcard_partial_label_rejected` | NoMatchingSan | fail | Agree |
| 8 | `wildcard_internal_rejected` | NoMatchingSan | fail | Agree |
| 9 | `wildcard_public_suffix_rejected` | NoMatchingSan | fail | Agree |
| 10 | `case_san_upper_target_lower` | Ok | pass | Agree |
| 11 | `case_san_lower_target_upper` | Ok | pass | Agree |
| 12 | `idn_alabel_san_alabel_target` | Ok | pass | Agree |
| 13 | `ipv4_san_matches_ipv4_target` | Ok | pass | Agree |
| 14 | `ipv4_san_mismatch` | NoMatchingSan | fail | Agree |
| 15 | `ipv6_san_matches_ipv6_target` | Ok | pass | Agree |
| 16 | `ipv6_san_mismatch` | NoMatchingSan | fail | Agree |
| 17 | `ipv4_san_v6_target_rejected` | NoMatchingSan | fail | Agree |
| 18 | `dns_san_ip_target_rejected` | NoMatchingSan | fail | Agree |
| 19 | `multi_san_first_matches` | Ok | pass | Agree |
| 20 | `multi_san_middle_matches` | Ok | pass | Agree |
| 21 | `multi_san_wildcard_matches` | Ok | pass | Agree |
| 22 | `multi_san_none_match` | NoMatchingSan | fail | Agree |
| 23 | `missing_san_rejected` | MissingSan | fail | Agree |

### Notable case-by-case alignment

- **Case 9 (`wildcard_public_suffix_rejected`)**: OpenSSL refuses
  `*.com` SAN against `foo.com` — matches the pkix-identity
  conservative public-suffix-shape policy. Pyca's `ServerVerifier`
  accepts this case (see `baseline-verify-pyca.md`); OpenSSL is the
  stronger oracle here.

- **Cases 17, 18 (cross-type SAN rejection)**: OpenSSL refuses an IPv4
  SAN against an IPv6 target, and a DNS SAN against an IP target.
  Same behavior as pkix-identity.

- **Case 12 (`idn_alabel_san_alabel_target`)**: A-label SAN matching
  an A-label target works directly under `-verify_hostname`. U-label
  client-side normalization is intentionally not exercised by this
  case (the target string is already in A-label form).

## TLS client (PKIX-fmtv.18.3)

**7 / 7 cases produced a verdict on both sides.**
**7 / 7 in agreement** (100%). **0 Rust-looser, 0 Rust-stricter.**

Corpus: `leaf-clientauth-dns.der`, `leaf-clientauth-mailbox.der`,
`host-exact-foo.der` (serverAuth-only, used for negative EKU cases),
all from `pkix-chain/tests/fixtures/`. Profiles exercised:
`Rfc5280Profile` (no EKU enforcement) and `BasicTlsClientProfile`
(id-kp-clientAuth required).

| # | Case | Profile | Hostname | Rust | OpenSSL | Agreement |
|---|---|---|---|---|---|---|
| 1 | `match_under_rfc5280` | Rfc5280 | `client.example.com` | Ok | pass | Agree |
| 2 | `match_under_basic_client` | BasicClient | `client.example.com` | Ok | pass | Agree |
| 3 | `san_mismatch` | Rfc5280 | `other.example.com` | NoMatchingSan | fail | Agree |
| 4 | `eku_mismatch_basic_client` | BasicClient | `foo.example.com` | Path | fail | Agree |
| 5 | `mailbox_leaf_dns_binding_rejected` | Rfc5280 | `client.example.com` | NoMatchingSan | fail | Agree |
| 6 | `no_binding_clientauth_ok` | Rfc5280 | (none) | Ok | pass | Agree |
| 7 | `no_binding_eku_rejected` | BasicClient | (none) | Path | fail | Agree |

### Why OpenSSL is the strong oracle here

Unlike pyca's `build_client_verifier()` (which does not bind subject
and does not enforce EKU under `permit_all` EE policy), OpenSSL's
`-purpose sslclient -verify_hostname X` enforces:

- **id-kp-clientAuth EKU** — case 4 (serverAuth-only leaf) and case 7
  (no-binding, serverAuth-only) both reject under `-purpose
  sslclient` with "unsuitable certificate purpose". Matches what
  `BasicTlsClientProfile` enforces.

- **dNSName SAN binding** — case 3 (mismatched hostname) and case 5
  (mailbox-only leaf, no dNSName SAN) both reject with "hostname
  mismatch". Matches `verify_tls_client_dns(..., Some(name))`.

`baseline-verify-pyca.md` records 3/5 client agree (2 expected
pyca-weaker) on a strict subset of these cases; the OpenSSL 7/7
result here is the canonical client-mode comparison.

## S/MIME signer / recipient (PKIX-fmtv.18.4)

_Open. Will populate when the subbead lands._

## Code signing (PKIX-fmtv.18.5)

_Open. Will populate when the subbead lands._

## Time stamping (PKIX-fmtv.18.6)

_Open. Will populate when the subbead lands._

## OCSP responder (PKIX-fmtv.18.7)

_Open. Pending PKIX-fmtv.13.3 design clarification._

## Hard invariants enforced by the tests

Each per-purpose integration test asserts:

1. Every Rust outcome matches the row table's `expected_rust`. The
   table is the in-test ground truth; expected outcomes for the same
   corpus row line up 1:1 with `verify_wrapper_pyca.rs`.

2. **Zero `Rust-looser` cases.** A Rust-looser divergence is "OpenSSL
   refused while our verifier passed" — a strong signal of a Rust
   bug. The assertion will fire if we ever regress.

The tests do NOT assert on `Rust-stricter` cases; those are recorded
in the per-section table as documented semantic differences. The
TLS-server section has zero such cases against OpenSSL on the
current corpus.

## Reproducing

```sh
# Each per-purpose test invokes openssl verify directly. Tests panic
# loudly when openssl is missing — install openssl ≥ 3.0 or pin via
# $PKIX_DIFFTEST_OPENSSL_BIN.
cargo test -p pkix-difftest --test verify_wrapper_openssl_server -- --nocapture
# (Once shipped:)
# cargo test -p pkix-difftest --test verify_wrapper_openssl_client -- --nocapture
# cargo test -p pkix-difftest --test verify_wrapper_openssl_smime -- --nocapture
# cargo test -p pkix-difftest --test verify_wrapper_openssl_codesign -- --nocapture
# cargo test -p pkix-difftest --test verify_wrapper_openssl_timestamp -- --nocapture
# cargo test -p pkix-difftest --test verify_wrapper_openssl_ocsp -- --nocapture
```

The per-case agreement matrix prints to stderr when run with
`--nocapture`. If the row table in a test file is updated, the
corresponding section of this document is updated in the same commit.
