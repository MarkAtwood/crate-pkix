# Changelog

All notable changes to `pkix-zlint-bridge` are documented here. The
crate follows [Keep a Changelog](https://keepachangelog.com/) headings
and [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Scaffold release: public type surface for the zlint subprocess
  bridge. `Verdict`, `ZlintLintInfo`, `BridgeError`, `PerCertError`,
  `BridgeConfig`, `ZlintBridge` (constructor only; no subprocess
  invocation yet). All result/error types are
  `Clone + Debug + PartialEq + Eq + Send + Sync + non_exhaustive`,
  with `serde::Serialize` / `serde::Deserialize` derives gated on the
  `serde` cargo feature. `Verdict` is `Hash + Ord`. Send/Sync
  compile-time assertions follow the `PKIX-2l0v.2` const-block
  pattern. (PKIX-jy95.7.1.)
- Crate-level rustdoc explains the framework-not-policy positioning
  and cites the four design decisions inherited from the parent epic:
  per-check granularity (`.1`), severity mapping (`.2`), multi-file
  batch shape (`.3`), and bridge-vs-per-cert error discrimination
  (`.4`).
- `BridgeConfig::default()` returns `{ zlint_path: "zlint", timeout:
  60s }`. `ZlintBridge::new` accepts any config and is currently
  infallible (scaffold); the fallible signature is in place so
  binary-existence and version-pinning checks can land additively.
- `ZlintBridge::enumerate_lints()` spawns
  `<zlint_path> -list-lints-json` and returns
  `Vec<ZlintLintInfo>` from the line-delimited JSON output.
  Severity is derived from the check name prefix (`e_*` →
  `Severity::Error`, `w_*` → `Warn`, `n_*` → `Notice`); any other
  prefix surfaces as `BridgeError::OutputParseError` so a silent
  upstream catalog-shape change cannot mis-label findings. Optional
  fields (`description`, `citation`, `source`) default to the empty
  string when missing — zlint's catalog has several entries (CRL
  checks, community-source checks) that omit `citation`, and being
  strict here would refuse to enumerate the real catalog. Subprocess
  plumbing drains stdout/stderr on dedicated reader threads to avoid
  the classic pipe-buffer deadlock. Best-effort timeout enforcement
  via `try_wait` + sleep poll using
  [`BridgeConfig::timeout`]. (PKIX-jy95.7.2.)

### Not yet shipped

- `run_on_cert()` with per-cert SHA-256 verdict cache —
  PKIX-jy95.7.3.
- `run_on_certs()` batch via multi-file zlint invocation —
  PKIX-jy95.7.4.
