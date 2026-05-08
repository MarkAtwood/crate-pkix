# Changelog

All notable changes to the workspace crates are documented here. The workspace
follows [Keep a Changelog](https://keepachangelog.com/) headings and
[Semantic Versioning](https://semver.org/) for each crate independently.

## [unreleased]

### `pkix-revocation` — CDP/IDP `distributionPoint` matching (RFC 5280 §6.3.3(b)(1))

#### Added

- `OutOfScopeReason::CrlIdpDistributionPointMismatch` variant. Returned by
  `CrlChecker::check_revocation` and `check_revocation_against_anchor` when
  the CRL's `IssuingDistributionPoint.distributionPoint` does not match (or
  is incompatible with) any of the certificate's `cRLDistributionPoints`
  extension entries. `Error` and `OutOfScopeReason` are both
  `#[non_exhaustive]`, so adding this variant is **non-breaking** for
  callers using `match` arms.

#### Changed (non-breaking)

- `CrlChecker` now performs RFC 5280 §6.3.3(b)(1) distribution-point name
  matching as part of the existing IssuingDistributionPoint scope check.
  Both `DistributionPointName::FullName` and
  `DistributionPointName::NameRelativeToCRLIssuer` forms are supported,
  with `NameRelativeToCRLIssuer` resolved by appending the relative RDN to
  the appropriate base DN (the certificate's issuer for the cert's CDP,
  the CRL signer's subject for the CRL's IDP). Cross-form matching works:
  a cert whose CDP uses `NameRelativeToCRLIssuer` matches a CRL whose IDP
  uses `FullName` when both resolve to the same DN.

  `GeneralName::DirectoryName` entries compare via `pkix_path::names_match`
  (proper RFC 4518 DN equivalence including the new BMPString support).
  Other `GeneralName` variants (URI, dNSName, rfc822Name, IP address, OID,
  etc.) compare via byte-exact DER encoding equality.

  PKITS §4.14.3, §4.14.8, and §4.14.9 — the three `#[ignore]`d tests for
  CDP/IDP name matching — now pass with assertions tightened to expect
  `Err(OutOfScope(CrlIdpDistributionPointMismatch))` specifically. PKITS
  §4.14.4 (cross-form match: cert `NameRelativeToCRLIssuer`, CRL
  `FullName`) continues to pass.

  Limitations:
  - The per-`DistributionPoint` `cRLIssuer` field is not honored when
    resolving the cert's CDP base DN; the certificate's own issuer is
    always used. This is correct for the common case (RFC 5280 §4.2.1.13
    requires conforming CAs to omit `cRLIssuer` when the cert issuer also
    issues the CRL) and is sufficient for all PKITS §4.14 fixtures.
  - The reasons-subset check (`onlySomeReasons` on IDP must cover the
    reasons the cert's CDP asks to be checked) is not implemented. PKITS
    §4.14 fixtures do not exercise it. Tracked as future work; a separate
    `OutOfScopeReason` variant will be added at that time.

  Tracked as PKIX-zg9y in the project beads.

### `pkix-path` — `BMPString` AVA values are now compared after UCS-2-BE → UTF-8 transcoding

#### Changed (non-breaking)

- `names_match` (and the underlying `ava_values_match`) now decodes
  `BMPString`-tagged `AttributeTypeAndValue` content from UCS-2 big-endian
  to UTF-8 before applying the existing ASCII case-fold and
  insignificant-whitespace normalization. As a result, two AVAs that
  encode the same Unicode code points using different DER string types
  (`BMPString` vs `UTF8String`/`PrintableString`/`IA5String`/`VisibleString`)
  now compare equal where they previously fell through to raw DER byte
  comparison and compared unequal.

  Behaviour change for adversarial / malformed input: a `BMPString` with
  odd-length content bytes or 16-bit units in the UTF-16 surrogate range
  (U+D800..=U+DFFF) is now rejected by `any_to_str_bytes` (returns
  `None`); the dispatcher in `ava_values_match` then returns `false` for
  any comparison involving the malformed value (fail-closed). Previously
  malformed `BMPString` values fell through to raw DER byte comparison,
  so two byte-identical malformed values would have compared equal.
  Real-world certificates with malformed `BMPString` content do not
  exist in the PKITS corpus or any other in-tree fixture; the change is
  cosmetic for non-adversarial input.

  `UniversalString` AVAs continue to be parser-rejected upstream by
  `der` 0.7 (tag 0x1C is absent from `der::Tag::try_from`) and never
  reach this comparator. `TeletexString` continues to fall through to
  raw DER byte comparison (deferred pending a clear interoperability
  target — see PKIX-l63j.3).

  No new dependencies. `no_std` preserved. `pkix-path` stays at 0.2.x.

  Tracked as PKIX-l63j.1 (subset of the PKIX-l63j RFC 4518 epic) in the
  project beads. NFKC and full RFC 4518 prep for non-ASCII Unicode is
  tracked separately as PKIX-l63j.2.

### `pkix-path-builder` — skip-not-fail on malformed `BasicConstraints`

#### Changed (non-breaking)

- `build_path`, `build_path_with_config`, and the `PathCandidates` iterator
  now silently **skip** candidate intermediates whose `BasicConstraints`
  extension is present but cannot be DER-decoded, rather than aborting the
  search with `Error::MalformedIntermediate`. This matches the existing
  treatment of candidates with `cA = FALSE` or no `BasicConstraints` at all.

  Rationale: real-world certificate pools (notably CMS
  `SignedData.certificates` bags) routinely include unsolicited or corrupt
  certs the verifier did not request — for other recipients in a
  multi-recipient encrypted message, intermediates from unrelated CAs that
  rode along, or expired/corrupt artefacts from someone's pipeline. One bad
  cert in the bag must not poison verification of an otherwise-valid chain.

  When skipping all malformed candidates would leave no path to a trust
  anchor, `build_path` returns `Error::NoPathFound` (as it would for any
  other no-path scenario). The `Error::MalformedIntermediate` variant is
  retained because `Error` is `#[non_exhaustive]` and may be repurposed by
  a future diagnostic mode.

  Tracked as PKIX-qgw1 in the project beads.

## [0.3.0 / 0.2.1] — 2026-05-07

This release groups three concurrent crate versions:

- `pkix-revocation 0.3.0`, `pkix-chain 0.3.0`, `pkix-chain-simple 0.3.0` — semver-breaking.
- `pkix-path 0.2.1`, `pkix-path-builder 0.2.1`, `pkix-profiles 0.2.1` — additive.
- `pkix-lint 0.2.0` — first publish.

### `pkix-revocation 0.3.0` — BREAKING

#### Changed (breaking)

- **`Error::OutOfScope(OutOfScopeReason)` variant added** and is now returned at
  six previously-`Ok(())` sites in `CrlChecker::check_revocation` and
  `CrlChecker::check_revocation_against_anchor` corresponding to the three
  `IssuingDistributionPoint` scope-flag mismatches in RFC 5280 §5.2.5
  (`onlyContainsAttributeCerts`, `onlyContainsUserCerts`, `onlyContainsCACerts`).

  The pre-0.3.0 API documented `Ok(())` as having "dual semantics" — it could
  mean either "verified not-revoked" OR "no determination made (out of scope)".
  Hard-fail callers had no programmatic way to distinguish.

  Under 0.3.0, `Ok(())` is unambiguous "verified not-revoked"; "not covered"
  surfaces as `Err(Error::OutOfScope(reason))` for CRL or
  `Err(Error::OcspStatusUnknown)` for OCSP.

  **Migration**: callers that used `match` on `pkix_revocation::Error` MUST
  add a match arm for `Error::OutOfScope(_)` (the enum is `#[non_exhaustive]`,
  so this is a warning rather than a compile error, but the behavior change
  is silent without the new arm). Hard-fail revocation policies should treat
  `Error::OutOfScope` as a failure. Soft-fail callers can match on the
  specific `OutOfScopeReason` (`CrlOnlyAttributeCerts`, `CrlOnlyUserCerts`,
  `CrlOnlyCaCerts`) and decide which scopes to tolerate.

  Tracked as PKIX-qwzx.11 in the project beads.

#### Added

- `pub enum OutOfScopeReason` with variants `CrlOnlyAttributeCerts`,
  `CrlOnlyUserCerts`, `CrlOnlyCaCerts`. Derives `Clone`, `Copy`, `Debug`,
  `PartialEq`, `Eq`, `Hash`. Has a `Display` impl. `#[non_exhaustive]`.
- `Error::OutOfScope(OutOfScopeReason)` variant. `Display` formats as
  `"revocation source out of scope: {reason}"`.

#### Documentation

- `RevocationChecker::check_revocation` trait doc rewritten to remove the
  "dual semantics" warning and to document the new `OutOfScope` /
  `OcspStatusUnknown` distinction between CRL and OCSP "not covered" paths.

### `pkix-chain 0.3.0` — transitively breaking

Re-exports `pkix-revocation::Error` via `Error::Revocation(_)`. The
`OutOfScope` variant change above propagates: cases that previously surfaced
as `Ok(())` from `verify_chain` / `verify_chain_default` now surface as
`Err(Error::Revocation(Error::OutOfScope(_)))`. No `pkix-chain` API
surface changes beyond the dependency bump.

### `pkix-chain-simple 0.3.0` — transitively breaking

Same rationale as `pkix-chain 0.3.0`.

### `pkix-path 0.2.1`

#### Added

- `pub fn cert_is_ca(cert: &Certificate) -> Result<bool, DerError>` — RFC 5280
  §4.2.1.9 `BasicConstraints` decode helper. Returns `Ok(true)` if the cert
  has `cA = TRUE`, `Ok(false)` if absent or `cA = FALSE`, `Err(DerError)` if
  the extension is present but malformed (fail-closed). Shared by
  `pkix-path-builder` and `pkix-revocation::crl` to avoid duplicate
  RFC 5280 §4.2.1.9 decoders.

### `pkix-path-builder 0.2.1`

#### Added

- `PathBuilderConfig` and `build_path_with_config` (originally landed in
  earlier 0.2 work; full surface stable in 0.2.1).

#### Changed (non-breaking)

- `cert_is_ca` is now a thin wrapper over `pkix_path::cert_is_ca` with
  `.map_err(|_| Error::MalformedIntermediate)`. Behavior unchanged.
- `Error::DepthExceeded` doc and `Display` no longer hardcode "(10)";
  reference `PathBuilderConfig::max_depth` and `DEFAULT_MAX_DEPTH`.

### `pkix-profiles 0.2.1`

Documentation and lint adjustments. No public API changes.

### `pkix-lint 0.2.0` — first publish

First crates.io release. Lint engine for X.509 certificates with structured
soft-fail and advisory results. CABF TLS Baseline Requirements lints,
deviation tracking, OSCAL-style reports.

#### Notable

- `serial_lex_ge` / `serial_lex_le` consolidated into `serial_cmp` returning
  `core::cmp::Ordering`. Internal change; not on the public API surface.

### Stub crates

The following crates remain at `0.0.0` placeholder versions and are NOT
published in this release:

- `pkix-revocation-http` (online CRL/OCSP fetching — not yet implemented)
- `pkix-ct` (Certificate Transparency SCT verification — not yet implemented)
- `pkix-composite` (composite classical+PQC signatures — not yet implemented)
- `pkix-ac` (RFC 5755 attribute certificates — not yet implemented)

The 0.1.1 versions of these stubs on crates.io are placeholder releases that
predate the 0.0.0 reset; consumers should not depend on them.

## [0.2.0] — 2026-05-06

Initial 0.2 release. Workspace structure stabilized; PKITS happy-path subset
green; `pkix-path` `chain_walk` implements RFC 5280 §6.1 across signature
verification, validity period, name constraints (with `nameConstraints`
intersection/union and `nc_constrained_types` tracking), policy tree
(including `PolicyMappings` and `InhibitAnyPolicy`), and the §6.1.5 wrap-up.

## [0.1.x] — 2026-05-05 and earlier

Pre-release iteration. See git log for details.
