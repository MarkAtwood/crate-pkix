# Changelog

All notable changes to `pkix-lint-cabf` are documented here. The crate
follows [Keep a Changelog](https://keepachangelog.com/) headings and
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Removed (breaking)

- **`cabf_tls_br::CabfTlsBrProfile` has been deleted.** The
  `pkix_lint::LintProfile` bundling of the six CA/B Forum TLS BR lints
  has moved to `pkix_profiles_cabf::WebPkiProfile`'s `LintProfile`
  impl. This breaks any caller that named `CabfTlsBrProfile` directly;
  replace `use pkix_lint_cabf::cabf_tls_br::CabfTlsBrProfile;` with
  `use pkix_profiles_cabf::WebPkiProfile;`. The individual Lint impls
  (`ValidityMaxLint`, `Sha1ProhibitedLint`, `RsaMinKeySizeLint`,
  `SanRequiredLint`, `EkuServerAuthLint`, `BcCaFlagLint`) and the
  canonical `all_lints()` constructor remain in
  `pkix_lint_cabf::cabf_tls_br` unchanged.

  Architectural rationale: Profile types live in `-profiles*` crates;
  Lint types live in `-lint*` crates. Dep flow must be one-way:
  `-profiles*` → `-lint*`. Hosting a Profile type in `pkix-lint-cabf`
  created the back-edge `pkix-lint-cabf → pkix-profiles-cabf` and
  blocked the natural `pkix-profiles-cabf → pkix-lint-cabf` edge
  needed for `WebPkiProfile::lints()`. (PKIX-9vnx.9.2.2.)

### Changed (internal)

- `ValidityMaxLint::check_cert` now uses a `pub(crate)` inlined copy
  of the SC-081 phased-validity-cap math (formerly called
  `pkix_profiles_cabf::sc081_validity_cap`). The public function in
  `pkix-profiles-cabf` is unchanged; the two copies are cross-validated
  by tests in this crate (dev-dep on `pkix-profiles-cabf`) and by
  `pkix_profiles_cabf::WebPkiProfile`'s integration tests. Removing
  the runtime dep edge is what enables the cycle-break above.
  (PKIX-9vnx.9.2.2.)

- `pkix-profiles-cabf` moved from `[dependencies]` to
  `[dev-dependencies]`. The runtime crate no longer depends on
  `pkix-profiles-cabf`; the integration tests still do (for cross-
  validating SC-081 cap math). (PKIX-9vnx.9.2.2.)

### Added

- Rustdoc annotations linking each Lint to its canonical CA/B Forum
  TLS BR source URL on GitHub. The crate-level rustdoc gains a
  `## Reporting divergences` section inviting community-contributed
  citation and behavior fixes. The `cabf_tls_br` module-level lint
  table includes section anchors pointing into the upstream BR
  document. Pure documentation; no behavior change. (PKIX-wrkm.)

### Fixed

- Pre-existing broken intra-doc-link `[pkix_path::Profile]` in
  `CabfTlsBrProfile` rustdoc rewritten to `[pkix_lint::Profile]` (the
  same type via re-export, resolvable from this crate's dependency
  graph). `cargo doc -p pkix-lint-cabf --no-deps` now warns clean.
  (PKIX-wrkm.)

### Changed (citations and metadata, no behavior impact)

- `SanRequiredLint` citation refreshed from TLS BR §7.1.4.2 to
  §7.1.2.7.12 (Subscriber Certificate Subject Alternative Name) to
  match the current spec layout after ballot SC65 (RFC 3647 format
  conversion). `citation()` returns the new string; `spec_section_id()`
  returns `"cabf-tls-br-7.1.2.7.12"`. Module-level rustdoc table and
  per-lint rustdoc updated. (PKIX-d5rh.)
- `EkuServerAuthLint` citation refreshed from TLS BR §7.1.2.7.3 to
  §7.1.2.7.10 (Subscriber Certificate Extended Key Usage). Same
  rationale. `spec_section_id()` returns `"cabf-tls-br-7.1.2.7.10"`.
  (PKIX-d5rh.)
- `BcCaFlagLint` citation refreshed from TLS BR §7.1.2.5 (Technically
  Constrained TLS Subordinate CA Certificate Profile) to §7.1.2.10.4
  (CA Certificate Basic Constraints). §7.1.2.10.4 is the umbrella
  section cross-referenced by every per-CA-type Sub CA profile
  (§7.1.2.2 Cross-Cert, §7.1.2.3 Tech-Constrained Non-TLS,
  §7.1.2.5 Tech-Constrained TLS, §7.1.2.6 TLS), and the lint's
  `applies_to = IntermediateCa` scope covers them all. The pre-refresh
  citation only covered one of those CA flavors and was structurally
  too narrow. `spec_section_id()` returns
  `"cabf-tls-br-7.1.2.10.4"`. (PKIX-d5rh.)
- Lint behavior is unchanged — only citation strings, `spec_section_id`
  return values, and rustdoc text are affected. Test oracles in
  `tests/cabf_tls_br_tests.rs` were updated to match.

## [0.2.0]

Initial substantive version: `cabf_tls_br` module migrated from
`pkix-lint` (PKIX-amgn.5).
