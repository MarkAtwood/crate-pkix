# PKIX 1.0 release notes

RFC 5280 X.509 for Rust, done right from the start. 12 crates shipping
at 1.0; the adjacent ecosystem continues at independent 0.x cadence.

The 1.0 promise is **semver stability**: the public APIs in the crates
listed below are frozen. Future breaking changes require a major bump.

This document accompanies the per-crate `CHANGELOG.md` files. The
authoritative per-crate change record lives there; this document is
the one-page overview.

## What's included

The 1.0 scope is the **narrow** set chosen per PKIX-wlsr.1: the
RFC 5280 path-validation core, its direct dependencies, and the
RFC-baseline and pre-empted-future-integration crates that complete
the surface. Twelve crates total.

### Core path-validation crates

| Crate                          | Purpose |
|--------------------------------|---------|
| [`pkix-path`]                  | RFC 5280 §6 path validation; pluggable crypto via the `SignatureVerifier` trait. `no_std`. |
| [`pkix-revocation`]            | Certificate revocation checking (CRL, OCSP) over caller-supplied response bytes. |
| [`pkix-chain`]                 | Umbrella combining `pkix-path` + `pkix-revocation` with the `Verifier` struct and use-case wrappers (`verify_tls_server`, `verify_smime_signer`, etc.). |
| [`pkix-path-builder`]          | RFC 4158 path building from unordered cert bundles. |
| [`pkix-truststore`]            | PEM / DER trust anchor loading. No compiled-in CA bundle; no platform integration. |
| [`pkix-identity`]              | Cert-side identity matching (RFC 6125 hostname, RFC 5280 §4.2.1.6 + RFC 8398 mailbox, IP literal). |

### Profile and lint crates

| Crate                          | Purpose |
|--------------------------------|---------|
| [`pkix-profiles`]              | RFC-baseline certificate profile policies (RFC 5280, RFC 6125, RFC 8551). |
| [`pkix-profiles-cabf`]         | Reference (not authoritative) CA/B Forum profile types (TLS BR, S/MIME BR, Code Signing BR). |
| [`pkix-lint`]                  | Advisory lint engine; RFC-conformance lint bundle. |
| [`pkix-lint-cabf`]             | Reference (not authoritative) CA/B Forum lint bundle. |

### Pre-empted future integration

| Crate                          | Purpose |
|--------------------------------|---------|
| [`pkix-revocation-http`]       | Online CRL and OCSP fetching for `pkix-revocation`. |
| [`pkix-aia`]                   | Authority Information Access fetcher trait + `NoAiaFetcher` default. The trait and types ship at 1.0 so the `pkix-chain::Verifier` 3-generic surface (`A: AiaFetcher = NoAiaFetcher`) is frozen; the real HTTP transport ships in the sibling [`pkix-aia-http`] crate (0.0.0, post-1.0 cadence). |

## What's not included

The following sibling crates are real ecosystem value but are
**additive** to the 1.0 promise rather than part of it. Each continues
at its own 0.x cadence post-1.0. Crates marked *planned* do not yet
have source in the workspace.

- **AIA online fetching** — `pkix-aia-http` ships the real HTTP
  transport (sync `ureq` backend) that plugs into the 1.0
  `pkix-chain::Verifier` 3-generic surface. The crate is in-tree
  at 0.0.0; reaching it from `pkix-chain` requires the chain-build
  integration tracked under PKIX-zkjb.7 (post-1.0).
- **Attribute Certificates** — [`pkix-ac`] (RFC 5755 skeleton; tracked
  as PKIX-ng0x).
- **Certificate Transparency** — [`pkix-ct`] (RFC 6962 / RFC 9162 SCT
  verification skeleton; tracked as PKIX-baac).
- **DANE** — `pkix-dane` and `pkix-dane-resolver` (planned, PKIX-j32w)
  for TLSA record parsing and DNSSEC-validating resolution.
- **Composite signatures** — [`pkix-composite`] (PQC + classical
  composite signature verification skeleton).
- **Platform trust stores** — [`pkix-truststore-system`] (OS-native
  trust stores: macOS, Windows, iOS, Android; PKIX-8h87) and
  [`pkix-truststore-pkcs11`] (PKCS#11 / HSM / smart card; PKIX-p8vz).
- **Comprehensive CA/B Forum policy coverage** — [`pkix-policy-zlint`]
  (thin `Lint` adapter over the full zlint catalog via
  [`pkix-zlint-bridge`]; PKIX-jy95.10) and the planned
  `pkix-policy-pkilint` (PKIX-jy95.8). The hand-authored
  `pkix-lint-cabf` reference set covers a small curated subset of
  marquee predicates; predicate-comprehensive coverage is
  `pkix-policy-zlint`'s job.

The `pkix-difftest` harness (PKITS + x509-limbo differential testing
against OpenSSL and pyca/cryptography) ships as a dev tool, not a
published crate.

## Quick start

Add the umbrella crate to your `Cargo.toml`:

```toml
[dependencies]
pkix-chain = "1.0"
```

Verify a TLS server certificate chain with hostname binding:

```rust
use pkix_chain::{verify_tls_server, NoRevocation, ServerName, TrustAnchor};
use pkix_profiles::BasicTlsProfile;
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

// Parse your certificates (leaf first)
let leaf = Certificate::from_der(leaf_der)?;
let root = Certificate::from_der(root_der)?;

let chain = [leaf];
let anchors = [TrustAnchor::from_cert(root)];
let name = ServerName::dns_name("www.example.com")?;

// Validate path + bind hostname against the SAN in one call
let validated = verify_tls_server(
    &chain,
    &anchors,
    &name,
    &BasicTlsProfile,
    1_780_272_000,    // now, seconds since Unix epoch
    &NoRevocation,
)?;
println!("chain depth: {}", validated.depth);
```

The `Profile` argument selects the policy. Other use-case wrappers
live alongside `verify_tls_server`:

- `verify_tls_client_dns` / `verify_tls_client_mailbox` — TLS client
  auth with optional DNS- or mailbox-name binding.
- `verify_smime_signer` / `verify_smime_recipient` — RFC 5280
  §4.2.1.6 + RFC 8398 mailbox-identity binding.
- `verify_code_signer` — RFC 5280 `id-kp-codeSigning` baseline.
- `verify_time_stamper` — RFC 3161 TSA leaf with critical-and-sole
  `id-kp-timeStamping` EKU.
- `verify_ocsp_responder` — RFC 6960 §4.2.2.2 delegated OCSP
  responder validation, including `id-pkix-ocsp-nocheck` handling.

For full chain validation without identity binding, use
`verify_chain` directly. See the per-crate rustdoc for the
non-wrapper API surface (`Verifier::new` / `verify_batch`,
`pkix-path::validate_path`, etc.).

## Stability promise

The 12 crates listed above commit to **semver stability** at 1.0. The
public APIs are frozen; future breaking changes require a major
version bump.

Specifically frozen:

- All public types, traits, methods, free functions, and re-exports
  on the listed crates' public surfaces.
- The `Profile` and `LintProfile` trait shapes.
- The `Verifier` struct's 3-generic shape
  (`Verifier<'a, V: SignatureVerifier, R: RevocationChecker, A:
  AiaFetcher = NoAiaFetcher>`).
- The MSRV: Rust 1.73 (pinned via workspace `rust-version`).

Specifically *not* frozen:

- The `# Limitations` rustdoc sections describe currently-shipped
  behavior, not API contracts. Limitations shrink as features land.
- Optional features (`crl`, `ocsp`, `serde`, `rustcrypto`, `oscal`,
  …) may grow new opt-in capabilities non-breakingly.
- Adjacent crates (`pkix-ac`, `pkix-ct`, `pkix-dane`, `pkix-aia-http`,
  `pkix-policy-zlint`, etc.) continue at independent 0.x cadence
  and reserve the right to break.

The framework-not-policy stance encoded in [`AGENTS.md`][AGENTS]
non-negotiable #5 remains binding: the workspace does not transcribe
industry-forum or vendor policy into the core crates. The `-cabf`
reference crates are an explicit, scoped exception.

## Acknowledgments

The 1.0 release rests on substantial upstream and reference work:

- **RustCrypto formats** — `x509-cert`, `der`, `spki`, `x509-ocsp`,
  `pkcs1`, `pkcs8`, and the supporting algorithm crates
  (`p256`, `p384`, `rsa`, `sha2`, `signature`, etc.) provide the
  parser and primitive-verifier substrate the workspace builds on.
- **NIST PKITS** — the Public Key Interoperability Test Suite is the
  Tier-1 integration-test bar. Pass-rate analysis lives in
  [`pkix-difftest/baseline-pkits-analysis.md`].
- **x509-limbo** — the C2SP corpus is the Tier-2 differential-test
  bar. Analysis lives in
  [`pkix-difftest/baseline-limbo-analysis.md`].
- **OpenSSL** and **pyca/cryptography** — the two independent
  differential-test oracles in `pkix-difftest`.
- **BetterTLS** — the `pathbuilding` fixtures imported into
  `pkix-path-builder/tests/`.
- **idna**, **base64ct**, and other RustCrypto-family or
  RustCrypto-adjacent foundational crates that the workspace
  depends on at the workspace pins.

## Per-crate details

Every public-surface change between 0.x and 1.0 is enumerated in the
crate's `CHANGELOG.md`:

- [`pkix-path/CHANGELOG.md`](pkix-path/CHANGELOG.md)
- [`pkix-revocation/CHANGELOG.md`](pkix-revocation/CHANGELOG.md)
- [`pkix-chain/CHANGELOG.md`](pkix-chain/CHANGELOG.md)
- [`pkix-path-builder/CHANGELOG.md`](pkix-path-builder/CHANGELOG.md)
- [`pkix-truststore/CHANGELOG.md`](pkix-truststore/CHANGELOG.md)
- [`pkix-identity/CHANGELOG.md`](pkix-identity/CHANGELOG.md)
- [`pkix-profiles/CHANGELOG.md`](pkix-profiles/CHANGELOG.md)
- [`pkix-profiles-cabf/CHANGELOG.md`](pkix-profiles-cabf/CHANGELOG.md)
- [`pkix-lint/CHANGELOG.md`](pkix-lint/CHANGELOG.md)
- [`pkix-lint-cabf/CHANGELOG.md`](pkix-lint-cabf/CHANGELOG.md)
- [`pkix-revocation-http/CHANGELOG.md`](pkix-revocation-http/CHANGELOG.md)
- [`pkix-aia/CHANGELOG.md`](pkix-aia/CHANGELOG.md)

The unified workspace [`CHANGELOG.md`](CHANGELOG.md) carries the
detailed per-change history; the per-crate files are the rollup view.

[AGENTS]: ./AGENTS.md
[`pkix-path`]: pkix-path/
[`pkix-revocation`]: pkix-revocation/
[`pkix-chain`]: pkix-chain/
[`pkix-path-builder`]: pkix-path-builder/
[`pkix-truststore`]: pkix-truststore/
[`pkix-identity`]: pkix-identity/
[`pkix-profiles`]: pkix-profiles/
[`pkix-profiles-cabf`]: pkix-profiles-cabf/
[`pkix-lint`]: pkix-lint/
[`pkix-lint-cabf`]: pkix-lint-cabf/
[`pkix-revocation-http`]: pkix-revocation-http/
[`pkix-aia`]: pkix-aia/
[`pkix-aia-http`]: pkix-aia-http/
[`pkix-ac`]: pkix-ac/
[`pkix-ct`]: pkix-ct/
[`pkix-composite`]: pkix-composite/
[`pkix-truststore-system`]: pkix-truststore-system/
[`pkix-truststore-pkcs11`]: pkix-truststore-pkcs11/
[`pkix-policy-zlint`]: pkix-policy-zlint/
[`pkix-zlint-bridge`]: pkix-zlint-bridge/
[`pkix-difftest/baseline-pkits-analysis.md`]: pkix-difftest/baseline-pkits-analysis.md
[`pkix-difftest/baseline-limbo-analysis.md`]: pkix-difftest/baseline-limbo-analysis.md
