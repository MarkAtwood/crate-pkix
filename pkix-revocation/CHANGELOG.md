# Changelog

All notable changes to `pkix-revocation` are documented here. The crate
follows [Keep a Changelog](https://keepachangelog.com/) headings and
[Semantic Versioning](https://semver.org/).

## [Unreleased]

_Nothing yet._

## [1.0.0] — TBD

First stable release.

### Changed (breaking)

- `pkix-revocation::DerError` is now a re-export of
  `pkix_path::DerError` rather than an independent type with identical
  shape. The variant was renamed/restructured: callers matching on the
  inner error type or constructing via the former tuple syntax
  `DerError(e)` must update their match arms and use
  `DerError::new(e)` instead.

### Added

- Optional `serde` feature deriving `Serialize` / `Deserialize` on
  `Error` and `OutOfScopeReason` (PKIX-2l0v.1). `Option<CrlReason>`
  wire form uses the RFC 5280 §5.3.1 numeric codes
  (`KeyCompromise = 1`, etc.).
- Path-level CRL signer discovery per RFC 5280 §6.3.3(f) (PKIX-cqwt).
  New public API for locating a CRL's signer in a caller-supplied
  bundle without inverting the workspace's one-way dep direction
  (`pkix-chain` → `pkix-revocation` → `pkix-path`):
  - Free helper `pkix_revocation::discover_crl_signer(bundle, &crl)
    -> Option<&Certificate>`. AKI / SKI walk per RFC 5280 §4.2.1.1 /
    §4.2.1.2 with issuer-DN fallback. No signature verification —
    discovery only.
  - Constructor `CrlChecker::new_with_signer_discovery(crl_der,
    bundle, cert_to_check, now, verifier)`. Runs discovery, gates
    the result on `cRLSign` in `KeyUsage` per §6.3.3(f), and
    performs a structural anchor-reachability walk (the discovered
    signer must reach a self-signed cert by repeated AKI/SKI or
    issuer-DN steps within the bundle).
  - New `Error` variants `CrlSignerNotFound` and `CrlSignerNotTrusted`.
    `Error` is `#[non_exhaustive]`, so this is additive.

  The structural anchor-reachability check is intentionally lenient:
  it does NOT verify signatures along the signer's chain. Full RFC 5280
  §6.1 validation of the signer's path remains the responsibility of
  higher-layer composers such as `pkix-chain`. Tradeoff stance
  tracked as PKIX-yi7k.1.
- `Send + Sync` compile-time assertion on `Error` (PKIX-2l0v.2).
- Top-level `# Limitations` rustdoc section (PKIX-wlsr.6).

## [0.3.2] — 2026-05-08

### Added

- `Error::RevocationFetchFailed { description: String }` variant
  (PKIX-a1yc.5). Returned by network-fetching adapters
  (`pkix-revocation-http`'s `HttpCrlFetcher` / `HttpOcspFetcher`,
  future LDAP / out-of-band adapters) when every URL extracted from
  the certificate failed either at the transport layer (network,
  TLS, HTTP error) or at the response layer (DER parse, signature,
  validity). Distinct from `Revoked`, `OcspStatusUnknown`, and
  `OutOfScope`. Hard-fail callers MUST reject the chain on this
  variant; soft-fail callers MAY treat it permissively.

  `Error` is `#[non_exhaustive]`, so adding the variant is
  non-breaking. Callers that exhaustively match on `Error` should
  add an arm (or use `_`) to be forward-compatible.

## [0.3.1] — 2026-05-08

### Added

- `OutOfScopeReason::CrlIdpDistributionPointMismatch` variant
  (PKIX-zg9y). Returned by `CrlChecker::check_revocation` and
  `check_revocation_against_anchor` when the CRL's
  `IssuingDistributionPoint.distributionPoint` does not match
  (or is incompatible with) any of the certificate's
  `cRLDistributionPoints` extension entries (RFC 5280 §6.3.3(b)(1)).
  `OutOfScopeReason` is `#[non_exhaustive]`, so adding the variant
  is non-breaking.

### Changed (non-breaking)

- `CrlChecker` now performs RFC 5280 §6.3.3(b)(1) distribution-point
  name matching as part of the existing IDP scope check. Both
  `DistributionPointName::FullName` and
  `DistributionPointName::NameRelativeToCRLIssuer` forms are supported,
  with `NameRelativeToCRLIssuer` resolved by appending the relative
  RDN to the appropriate base DN (the certificate's issuer for the
  cert's CDP, the CRL signer's subject for the CRL's IDP). Cross-form
  matching works: a cert whose CDP uses `NameRelativeToCRLIssuer`
  matches a CRL whose IDP uses `FullName` when both resolve to the
  same DN. `DirectoryName` entries compare via
  `pkix_path::names_match` (RFC 4518 DN equivalence). PKITS §4.14.3,
  §4.14.8, and §4.14.9 — the three previously-`#[ignore]`'d tests
  for CDP/IDP name matching — now pass; PKITS §4.14.4 (cross-form
  match) continues to pass.

  Limitations: the per-`DistributionPoint` `cRLIssuer` field is not
  honored when resolving the cert's CDP base DN; the certificate's
  own issuer is always used. The reasons-subset check
  (`onlySomeReasons` on IDP) is not implemented.

## [0.3.0] — 2026-05-08

### Changed (breaking)

- `Error::OutOfScope(OutOfScopeReason)` variant added and is now
  returned at six previously-`Ok(())` sites in
  `CrlChecker::check_revocation` and
  `CrlChecker::check_revocation_against_anchor` corresponding to the
  three `IssuingDistributionPoint` scope-flag mismatches in RFC 5280
  §5.2.5 (`onlyContainsAttributeCerts`, `onlyContainsUserCerts`,
  `onlyContainsCACerts`) (PKIX-qwzx.11).

  The pre-0.3.0 API documented `Ok(())` as having "dual semantics" —
  it could mean either "verified not-revoked" OR "no determination
  made (out of scope)". Hard-fail callers had no programmatic way
  to distinguish.

  Under 0.3.0, `Ok(())` is unambiguous "verified not-revoked"; "not
  covered" surfaces as `Err(Error::OutOfScope(reason))` for CRL or
  `Err(Error::OcspStatusUnknown)` for OCSP.

  Migration: callers that used `match` on `pkix_revocation::Error`
  MUST add a match arm for `Error::OutOfScope(_)` (the enum is
  `#[non_exhaustive]`, so this is a warning rather than a compile
  error, but the behavior change is silent without the new arm).
  Hard-fail revocation policies should treat `Error::OutOfScope` as
  a failure. Soft-fail callers can match on the specific
  `OutOfScopeReason` (`CrlOnlyAttributeCerts`, `CrlOnlyUserCerts`,
  `CrlOnlyCaCerts`) and decide which scopes to tolerate.

### Added

- `OutOfScopeReason` enum with variants `CrlOnlyAttributeCerts`,
  `CrlOnlyUserCerts`, `CrlOnlyCaCerts`. Derives `Clone`, `Copy`,
  `Debug`, `PartialEq`, `Eq`, `Hash`. `Display` impl.
  `#[non_exhaustive]`.
- `Error::OutOfScope(OutOfScopeReason)` variant.
- RFC 5280 §5.2.6 indirect CRL support (PKIX-8zxm). New constructors
  `CrlChecker::new_with_crl_issuer` and
  `CrlChecker::with_delta_and_crl_issuer` take the `cRLIssuer` cert
  explicitly. Per-entry `certificateIssuer` extension (RFC 5280
  §5.3.3) is honored. New `#[non_exhaustive]` `Error` variants
  including `IndirectCrlIssuerMissing` for constructor/IDP-flag
  mismatches.
- RFC 6960 §4.2.2.2 delegated OCSP responder support (PKIX-53kt).
  `OcspChecker` now resolves signature key from both direct
  (ResponderId matches issuer) and delegated (scan response's
  `certs` field for a delegate cert; validate same-CA issuance,
  `id-kp-OCSPSigning` EKU, validity at `producedAt`, CA's signature
  on its TBS) cases. New `#[non_exhaustive]` `Error` variants:
  `OcspResponderEkuMissing`, `OcspResponderEkuMalformed`,
  `OcspResponderCertNotIssuedByCa`, `OcspResponderCertExpired`,
  `OcspResponderCertSigInvalid`.
- PKITS §4.5 revocation suite committed under
  `pkix-revocation/tests/pkits_4_5.rs`.

### Documentation

- `RevocationChecker::check_revocation` trait doc rewritten to
  remove the "dual semantics" warning and to document the new
  `OutOfScope` / `OcspStatusUnknown` distinction between CRL and
  OCSP "not covered" paths.

## [0.2.0] — 2026-05-06

Initial substantive release alongside workspace stabilization.
`CrlChecker` and `OcspChecker` covering RFC 5280 §5 CRLs (including
delta CRLs and `IssuingDistributionPoint` scope flags) and RFC 6960
basic OCSP. `RevocationChecker` trait + `NoRevocation` zero-cost
default for callers who want the path layer without revocation. Lives
behind the one-way `pkix-chain → pkix-revocation → pkix-path` dep flow.

## Pre-history

Initial public types landed under `ca81fb83`
(`feat(pkix-revocation): expand Error enum with CRL/OCSP variants`)
and `fdffdba9` (`feat(pkix-revocation): add CrlChecker and
OcspChecker`); policy validation, delta CRLs, and IDP checking
landed under `6276e4e3` (`feat: policy validation, delta CRLs, IDP
checking`).
