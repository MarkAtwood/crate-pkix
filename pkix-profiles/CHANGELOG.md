# Changelog

All notable changes to `pkix-profiles` are documented here. The crate
follows [Keep a Changelog](https://keepachangelog.com/) headings and
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `BasicTlsClientProfile` + `basic_tls_client_policy` — RFC 5280
  §4.2.1.12 EKU baseline (`id-kp-clientAuth`). Unlike `BasicTlsProfile`
  this does NOT require a SAN at the path layer; client-auth
  deployments commonly carry the identity in the Subject DN, and the
  wrapper layer (`verify_tls_client_dns` / `verify_tls_client_mailbox`
  in `pkix-chain`) handles caller-supplied SAN binding independently.
  (PKIX-uuiz.)
- `BasicCodeSigningProfile` + `basic_code_signing_policy` — RFC 5280
  EKU baseline (`id-kp-codeSigning` only, no SAN requirement).
  (PKIX-fmtv.13.1.)
- `BasicTimeStampingProfile` + `basic_time_stamping_policy` —
  RFC 3161 §2.3 EKU baseline (`id-kp-timeStamping`). The
  critical-and-sole EKU rule is enforced at the wrapper layer
  (`verify_time_stamper` in `pkix-chain`) rather than in the
  profile. (PKIX-fmtv.13.2.)
- `BasicOcspResponderProfile` + `basic_ocsp_responder_policy` —
  RFC 6960 §4.2.2.2 baseline requiring `id-kp-OCSPSigning`. Paired
  with `verify_ocsp_responder` in `pkix-chain` for delegated responder
  validation. (PKIX-fmtv.13.3.)
- `BasicTlsProfile` and `BasicSmimeProfile` now implement
  `pkix_lint::LintProfile` alongside `Profile`, exposing canonical
  RFC-baseline lint sets (PKIX-9vnx.9.2):
  - `BasicTlsProfile` bundles six RFC 5280 / 6125 lints
    (`Rfc6125TlsServerSanLint`, `Rfc5280EkuServerAuthLint`,
    `Rfc5280BasicConstraintsCaLeafLint`,
    `Rfc5280SanRequiredWhenSubjectEmptyLint`,
    `Rfc5280SignatureAlgorithmMatchLint`,
    `Rfc5280MaxSerialLengthLint`).
  - `BasicSmimeProfile` bundles five RFC 8551 / 8398 / 5280 lints
    (`Rfc8398SmimeSanLint`, `Rfc8551EkuEmailProtectionLint`,
    `Rfc8398SmimeMailboxEquivalenceLint`,
    `Rfc5280SignatureAlgorithmMatchLint`,
    `Rfc5280MaxSerialLengthLint`).
- `check_basic_tls_shape(cert, now_unix) -> Result<(), Vec<Finding>>`
  and `check_basic_smime_shape(cert, now_unix) -> Result<(),
  Vec<Finding>>` — one-line shape-check convenience functions over
  `pkix_lint::check_shape`. RFC baseline only (no CA/B Forum
  overlay; `pkix-profiles-cabf` ships the CA/B Forum overlay
  aliases). (PKIX-9vnx.9.2.)
- Runtime deps: `pkix-lint` and `x509-cert` added at the workspace
  pins. (PKIX-9vnx.9.2.)

## [0.3.0] — 2026-05-11

### Changed (breaking)

CA/Browser Forum-specific profile content moved to the sibling
`pkix-profiles-cabf` crate per the framework-not-policy workspace
stance (PKIX-amgn.4 / AGENTS.md non-negotiable #5).

Moved out of this crate:

- `WebPkiProfile`, `SmimeProfile`, `CodeSigningProfile`, and their
  `web_pki_policy` / `smime_policy` / `code_signing_policy` aliases.
- `sc081_validity_cap()` (CA/B Forum SC-081 phased validity).
- `CABF_TLS_BR_ALLOWED_ALGS`, `CABF_SMIME_BR_ALLOWED_ALGS`,
  `CABF_CS_BR_ALLOWED_ALGS` (the latter two were crate-private in
  0.2.x; they are now `pub` in `pkix-profiles-cabf`).

Migration:

```rust
// Before (pkix-profiles 0.2.x):
use pkix_profiles::{WebPkiProfile, web_pki_policy, sc081_validity_cap};

// After (pkix-profiles-cabf 0.2.x):
use pkix_profiles_cabf::{WebPkiProfile, web_pki_policy, sc081_validity_cap};
```

### Added

- `BasicTlsProfile` + `basic_tls_policy` — RFC 5280 + RFC 6125
  baseline with `id-kp-serverAuth` EKU. No CA/B Forum overlay.
- `BasicSmimeProfile` + `basic_smime_policy` — RFC 8551 §3 baseline:
  `id-kp-emailProtection` EKU + `rfc822Name` SAN. No CA/B Forum overlay.
- Deprecated `pub use` re-exports of the moved CA/B Forum types from
  `pkix-profiles-cabf` (`WebPkiProfile`, `SmimeProfile`,
  `CodeSigningProfile`, `web_pki_policy`, `smime_policy`,
  `code_signing_policy`, `sc081_validity_cap`). Existing
  `use pkix_profiles::WebPkiProfile;` imports continue to compile
  with a deprecation warning. The re-exports drop in `0.4.0`.

## [0.2.1] — 2026-05-07

Documentation and lint adjustments. No public API changes.

## [0.2.0] — 2026-05-06

Initial substantive release. Provides the `Profile` trait + `Rfc5280Profile`
RFC-baseline profile and the original CA/B Forum-shaped profiles
(`WebPkiProfile`, `SmimeProfile`, `CodeSigningProfile`) — the CA/B Forum
content later moved out to `pkix-profiles-cabf` in `0.3.0` per the
framework-not-policy split (PKIX-amgn).

## Pre-history

Initial scaffold landed under `9b0995eb` (`feat: add stub crates,
specs, and READMEs`); the first substantive `web_pki` / `smime` /
`code_signing` policy implementations landed in `16777565`
(`feat(pkix-profiles): implement web_pki, smime, code_signing
policies`) and stabilized through the `0.2.x` cycle.
