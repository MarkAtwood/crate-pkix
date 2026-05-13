# Changelog

All notable changes to this crate are documented here. Follows
[Keep a Changelog](https://keepachangelog.com/) headings and
[Semantic Versioning](https://semver.org/).

## [0.0.0] - 2026-05-13

### Added

First release: thin `pkix-lint::Lint` adapter wrapping
`pkix-zlint-bridge`. Each zlint check the bridge enumerates is exposed
as a `Lint` impl via `pkix_policy_zlint::all_lints(bridge)`, so callers
can mix zlint findings into a `pkix_lint::LintRunner` alongside the
workspace's own RFC-conformance and `-cabf` reference lints.

Per AGENTS.md non-negotiable #5 (three-mode policy-class model) and the
spec-taxonomy principle (`PKIX-mzsk`), this crate is the principled path
for **predicate-comprehensive** CA/B Forum coverage. The hand-authored
`pkix-lint-cabf` reference set covers a small curated subset of marquee
BR predicates; `pkix-policy-zlint` covers the whole catalog (~400
checks).

Public API:

- `pkix_policy_zlint::ZlintLint` — one `Lint` per zlint check, holding
  a `&'static ZlintLintInfo` and `Arc<ZlintBridge>`.
- `pkix_policy_zlint::all_lints(bridge) -> Result<Vec<Box<dyn Lint>>, BridgeError>`
  — enumerate zlint's catalog and wrap each check.

Design notes:

- `Lint::id()` and `Lint::citation()` return `&'static str`. The bridge's
  `ZlintLintInfo` is `String`-typed (runtime catalog), so `all_lints`
  leaks each `ZlintLintInfo` once at construction time via `Box::leak`.
  Bounded leak (~400 small records, one-time at startup).
- Verdict mapping is fixed: `NotApplicable` → `LintResult::NotApplicable`,
  `Pass` → `LintResult::Pass`, `Notice` and `Warn` → `LintResult::Warn`,
  `Error` → `LintResult::Error`, `Fatal` → `LintResult::Fatal`. The
  `Notice` vs. `Warn` split is preserved at the `Severity` metadata
  level via `ZlintLintInfo::severity`.
- All wrapped lints report `Scope::Certificate` and `SubjectKind::Any`;
  zlint determines per-cert applicability internally and returns
  `Verdict::NotApplicable` when a rule does not fire.

Tracked as [PKIX-jy95.10].

[PKIX-jy95.10]: https://github.com/MarkAtwood/crate-pkix  "pkix-policy-zlint adapter"
