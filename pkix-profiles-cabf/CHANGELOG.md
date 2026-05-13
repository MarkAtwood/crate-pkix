# Changelog

All notable changes to `pkix-profiles-cabf` are documented here. The crate
follows [Keep a Changelog](https://keepachangelog.com/) headings and
[Semantic Versioning](https://semver.org/).

## [Unreleased]

_Nothing yet._

## [1.0.0] — TBD

First stable release.

### Added

- **`WebPkiProfile` now implements `pkix_lint::LintProfile`.** The
  trait impl bundles the six CA/B Forum TLS BR lints from
  `pkix_lint_cabf::cabf_tls_br` (`ValidityMaxLint`,
  `Sha1ProhibitedLint`, `RsaMinKeySizeLint`, `SanRequiredLint`,
  `EkuServerAuthLint`, `BcCaFlagLint`). Callers can now write
  `WebPkiProfile.lint_runner()` to obtain a ready-to-use
  `pkix_lint::LintRunner` for end-entity TLS certificate linting. The
  lint slice from `WebPkiProfile::lints()` is backed by a
  lazily-initialized `static OnceLock`. (PKIX-9vnx.9.2.2.)

  This replaces the former `pkix_lint_cabf::cabf_tls_br::CabfTlsBrProfile`,
  which has been removed from `pkix-lint-cabf`. The architectural
  invariant going forward: Profile types live in `-profiles*` crates;
  Lint types live in `-lint*` crates; dep flow is one-way,
  `-profiles*` → `-lint*`. See `pkix-lint-cabf`'s CHANGELOG entry for
  the matching breaking-removal entry.

- New `pkix-lint = { workspace = true }` and
  `pkix-lint-cabf = { workspace = true }` runtime dependencies, gating
  the `LintProfile` impl. The new edges complete the trust-domain
  surface that was previously prevented by the
  `pkix-lint-cabf → pkix-profiles-cabf` cycle. (PKIX-9vnx.9.2.2.)

- Integration test suite `tests/web_pki_profile_lints.rs` cross-
  validates `WebPkiProfile`'s `LintProfile` output against
  `pkix_lint_cabf::cabf_tls_br::all_lints` (the canonical lint-list
  constructor used as an independent oracle). Includes the
  webpki-self-signed-365d.der pass-on-pre-SC-081 fixture test moved
  from `pkix-lint-cabf/tests/cabf_tls_br_tests.rs`. (PKIX-9vnx.9.2.2.)

- Rustdoc annotations linking each Profile and CABF_*_ALLOWED_ALGS
  constant to its canonical CA/B Forum BR source URL on GitHub. The
  crate-level rustdoc gains a `# Reporting divergences` section
  inviting community-contributed citation and behavior fixes.
  Per-Profile and free-function rustdoc tables include section anchors
  pointing into the upstream BR documents. Pure documentation; no
  behavior change. (PKIX-wrkm.)

### Breaking

- Removed `max_path_len` enforcement from `WebPkiProfile` (was `2`),
  `SmimeProfile` (was `1`), and `CodeSigningProfile` (was `1`). Audit
  against current CA/B Forum specs (TLS BR 2.2.6, S/MIME BR 1.0.14,
  CS BR 3.10.0) confirmed that no current BR imposes a numeric
  chain-depth cap on the entire chain; each spec only constrains the
  `pathLenConstraint` extension on individual CA certificates in their
  `basicConstraints` tables (e.g. TLS BR §7.1.2.10.4). The
  workspace's pre-existing `max_path_len` values were workspace-added
  defense, not a BR requirement. Per-cert `pathLenConstraint`
  enforcement (RFC 5280 §4.2.1.9) in `pkix-path` remains unchanged.

  **Behavior change:** chains of depth 3–10 will now pass
  `WebPkiProfile` validation that previously failed
  (`SmimeProfile` / `CodeSigningProfile`: chains of depth 2–10). The
  shared `ValidationPolicy` default of 10 still applies, so chains
  deeper than 10 are still rejected by default. Callers who require
  the previous defensive caps can opt in by setting
  `policy.max_path_len = N` on the returned `ValidationPolicy`
  themselves. (PKIX-d5rh.)

### Changed (citations and metadata, no behavior impact)

- `WebPkiProfile::version()` returns `"2.2.6"` (was `"SC-081"`). The
  ballot label is replaced by the dotted spec version of the document
  this profile was last refreshed against. `version()` is documented as
  advisory metadata; consumers may log or audit it. (PKIX-d5rh.)
- `SmimeProfile::version()` returns `"1.0.14"` (was `"1.0"`). Same
  rationale. (PKIX-d5rh.)
- `CodeSigningProfile::version()` returns `"3.10.0"` (was `"3.0"`).
  Same rationale. (PKIX-d5rh.)
- TLS BR SAN-required citation refreshed from §7.1.4.2 to §7.1.2.7.12
  (Subscriber Certificate Subject Alternative Name) to match the
  current spec layout after ballot SC65 (RFC 3647 format conversion).
  Source-level rustdoc and inline policy-construction comments
  updated. (PKIX-d5rh.)
- TLS BR EKU `id-kp-serverAuth` citation refreshed from §7.1.2.7.3 to
  §7.1.2.7.10 (Subscriber Certificate Extended Key Usage). Same
  rationale. (PKIX-d5rh.)
- S/MIME BR `id-kp-emailProtection` citation refreshed from §7.3 to
  §7.1.2.3(f) (Subscriber certificates / extKeyUsage) to match the
  current S/MIME BR layout. (PKIX-d5rh.)
- CS BR `id-kp-codeSigning` citation clarified to §7.1.2.3(f) in the
  rustdoc table (the inline comment already cited §7.1.2.3 correctly).
  (PKIX-d5rh.)

### Removed

- `smime_policy_max_path_len_is_1` and `code_signing_policy_max_path_len_is_1`
  unit tests, pinning the dropped behavior. The remaining tests cover the
  invariants this crate is responsible for.

## [0.2.0]

Initial published version.
