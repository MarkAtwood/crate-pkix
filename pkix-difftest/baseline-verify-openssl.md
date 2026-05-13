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
| `verify_smime_signer` | `-purpose smimesign -verify_email X` | PKIX-fmtv.18.4 | shipped |
| `verify_smime_recipient` | `-purpose smimeencrypt -verify_email X` | PKIX-fmtv.18.4 | shipped |
| `verify_code_signer` | `-purpose codesign` | PKIX-fmtv.18.5 | open |
| `verify_time_stamper` | `-purpose timestampsign` | PKIX-fmtv.18.6 | shipped (1 known divergence) |
| `verify_ocsp_responder` | `-purpose ocsphelper` | PKIX-fmtv.18.7 | shipped (chain-only) |

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

**19 cases × 2 roles = 38 verdicts produced on both sides.**
**38 / 38 in agreement** (100%). **0 Rust-looser, 0 Rust-stricter.**

The two wrappers `verify_smime_signer` and `verify_smime_recipient`
share byte-identical bodies (per `mailbox_corpus.rs`) and the OpenSSL
purposes `smimesign` / `smimeencrypt` produce identical verdicts on
this corpus. Listed once for both roles:

| # | Case | Fixture | Target | Rust | OpenSSL | Agreement |
|---|---|---|---|---|---|---|
| 1 | `rfc822_exact_match` | `mailbox-rfc822-user-example.der` | `user@example.com` | Ok | pass | Agree |
| 2 | `rfc822_local_part_mismatch` | `mailbox-rfc822-user-example.der` | `other@example.com` | NoMatchingSan | fail | Agree |
| 3 | `domain_case_insensitive_san_to_target` | `mailbox-rfc822-user-EXAMPLE.der` | `user@example.com` | Ok | pass | Agree |
| 4 | `domain_case_insensitive_target_to_san` | `mailbox-rfc822-user-example.der` | `user@EXAMPLE.com` | Ok | pass | Agree |
| 5 | `local_part_case_sensitive_strict` | `mailbox-rfc822-User-example.der` | `user@example.com` | NoMatchingSan | fail | Agree |
| 6 | `local_part_case_sensitive_strict_inv` | `mailbox-rfc822-user-example.der` | `User@example.com` | NoMatchingSan | fail | Agree |
| 7 | `smtputf8_only_i18n_match` | `mailbox-smtputf8-only.der` | `用户@example.com` | Ok | pass | Agree |
| 8 | `smtputf8_only_ascii_target_rejected` | `mailbox-smtputf8-only.der` | `user@example.com` | NoMatchingSan | fail | Agree |
| 9 | `mixed_san_ascii_target_matches_rfc822` | `mailbox-mixed.der` | `user@example.com` | Ok | pass | Agree |
| 10 | `mixed_san_i18n_target_matches_smtputf8` | `mailbox-mixed.der` | `用户@example.com` | Ok | pass | Agree |
| 11 | `mixed_san_unrelated_target_rejected` | `mailbox-mixed.der` | `stranger@example.com` | NoMatchingSan | fail | Agree |
| 12 | `multi_rfc822_first_match` | `mailbox-multi-rfc822.der` | `alpha@example.com` | Ok | pass | Agree |
| 13 | `multi_rfc822_middle_match` | `mailbox-multi-rfc822.der` | `beta@example.com` | Ok | pass | Agree |
| 14 | `multi_rfc822_last_match` | `mailbox-multi-rfc822.der` | `gamma@example.com` | Ok | pass | Agree |
| 15 | `multi_rfc822_no_match` | `mailbox-multi-rfc822.der` | `delta@example.com` | NoMatchingSan | fail | Agree |
| 16 | `dns_only_san_rejects_mailbox_under_rfc5280` | `mailbox-dns-only.der` | `user@example.com` | NoMatchingSan | fail | Agree |
| 17 | `missing_san_extension` | `leaf-no-san.der` | `user@example.com` | MissingSan | fail | Agree |
| 18 | `rfc822_san_without_at_sign_is_not_a_match` | `mailbox-rfc822-malformed-no-at.der` | `user@example.com` | NoMatchingSan | fail | Agree |
| 19 | `smtputf8_malformed_utf8_is_not_a_match` | `mailbox-smtputf8-bad-utf8.der` | `用户@example.com` | NoMatchingSan | fail | Agree |

### Notable case-by-case alignment

- **Cases 5, 6 (RFC 5321 §2.4 local-part case sensitivity)**: OpenSSL
  rejects `User@example.com` vs `user@example.com` — matches our
  strict-byte-equal local-part policy (per
  `mailbox_corpus_baseline.md`'s RFC 5321 decision). pyca/cryptography
  and webpki agree. This is the cross-implementation invariant.

- **Cases 7, 8 (RFC 8398 SmtpUTF8Mailbox)**: OpenSSL's `-verify_email`
  handles SmtpUTF8 SAN entries — accepts a UTF-8 target against an
  internationalized SAN, rejects an ASCII target against the same.
  Matches our implementation exactly.

- **Case 18 (malformed-no-at rfc822Name)**: OpenSSL refuses an
  rfc822Name SAN that lacks `@`. Matches our matcher's structural
  validation. (pyca presumably does the same; not differentially
  tested here.)

- **Case 19 (malformed UTF-8 in SmtpUTF8 SAN)**: OpenSSL surfaces the
  malformed encoding (`asn1 encoding routines: invalid utf8string`
  in stderr) and reports email mismatch. Matches our `MailboxName`
  parser's behaviour of declining to bind a malformed SAN value.

## Code signing (PKIX-fmtv.18.5)

_Open. Will populate when the subbead lands._

## Time stamping (PKIX-fmtv.18.6)

**4 / 4 cases produced a verdict on both sides.**
**3 / 4 in agreement** (75%). **1 known Rust-looser divergence, 0 Rust-stricter.**

| # | Case | Fixture | Time | Rust | OpenSSL | Agreement |
|---|---|---|---|---|---|---|
| 1 | `happy_path_rfc3161_ku_violation` | `leaf-timestamping.der` | NOW | Ok | fail | **LooserThanOpenssl** (known) |
| 2 | `eku_not_critical` | `leaf-timestamping-not-critical.der` | NOW | ProfileViolation | fail | Agree |
| 3 | `eku_not_sole` | `leaf-timestamping-not-sole.der` | NOW | ProfileViolation | fail | Agree |
| 4 | `before_not_before` | `leaf-timestamping.der` | 0 | Path | fail | Agree |

### Recorded divergence: case 1 (RFC 3161 §2.3 KeyUsage shape)

- **OpenSSL behaviour**: `-purpose timestampsign` strictly enforces
  RFC 3161 §2.3 — the TSA cert's KeyUsage MUST contain ONLY
  `digitalSignature` and/or `nonRepudiation`. Other bits
  (`keyEncipherment`, `keyAgreement`, etc.) trigger "unsuitable
  certificate purpose" rejection. Verified empirically against a
  hand-issued TSA cert: `digitalSignature` alone passes,
  `nonRepudiation` alone passes, `digitalSignature + nonRepudiation`
  passes, `digitalSignature + keyEncipherment` fails.

- **pkix-chain behaviour**: `verify_time_stamper` /
  `BasicTimeStampingProfile` enforce EKU shape (presence, criticality,
  sole) but do NOT check KeyUsage shape.

- **Fixture state**: `leaf-timestamping.der` (authored by pyca's
  gen.py for the in-crate smoke surface) carries
  `digitalSignature + keyEncipherment` in KU. Validates under
  pkix-chain, rejects under OpenSSL.

- **Follow-up**: tracked in **PKIX-7cac** — "verify_time_stamper
  should enforce RFC 3161 §2.3 KeyUsage shape". When that bead ships,
  the diff harness's `known_divergence` flag is removed and the row
  flips to Agree.

## OCSP responder (PKIX-fmtv.18.7)

**3 / 3 cases produced a verdict on both sides.**
**3 / 3 in agreement** (100%). **0 Rust-looser, 0 Rust-stricter.**

| # | Case | Fixture | Time | Rust | OpenSSL | Agreement |
|---|---|---|---|---|---|---|
| 1 | `happy_path` | `leaf-ocsp-responder.der` | NOW | Ok | pass | Agree |
| 2 | `happy_path_with_nocheck` | `leaf-ocsp-responder-nocheck.der` | NOW | Ok | pass | Agree |
| 3 | `before_not_before` | `leaf-ocsp-responder.der` | 0 | Path | fail | Agree |

### Why the diff is intrinsically narrow

OpenSSL's `-purpose ocsphelper` is **chain-only**. Empirically verified
against OpenSSL 3.0.13:

- It does NOT enforce `id-kp-OCSPSigning` EKU on the leaf
  (`host-exact-foo.pem` with serverAuth-only EKU validates fine).
- It has no CLI flag for RFC 6960 §4.2.2.2 delegation DN matching.
- It has no notion of RFC 6960 §4.2.2.2.1 `id-pkix-ocsp-nocheck`
  bypass (and `openssl verify` does not run OCSP checks itself
  without `-CRLfile` plumbing).

`verify_ocsp_responder` enforces all three semantics (EKU via
`BasicOcspResponderProfile`, delegation via wrapper-level check, nocheck
via revocation-checker shim). The OpenSSL oracle therefore covers
**chain validity only** for this wrapper — anchor binding, signature
chain, validity period.

Negative cases that fall outside `-purpose ocsphelper`'s surface
(wrong-issuer DN mismatch → `Error::OcspDelegation`, EKU-mismatch
under the profile → `Error::Path`) are exercised in
`pkix-chain/tests/verify_ocsp_responder.rs` and not duplicated here
because OpenSSL provides no oracle for them.

### Pending design clarification

PKIX-fmtv.13.3 has an open design clarification for the wrapper's
`issuer` argument shape. The diff harness here intentionally avoids
exercising that surface so the test stays valid across both possible
resolutions.

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
