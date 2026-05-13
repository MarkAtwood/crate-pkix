# Changelog

All notable changes to `pkix-lint-cabf` are documented here. The crate
follows [Keep a Changelog](https://keepachangelog.com/) headings and
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
