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

### Not yet shipped

- `enumerate_lints()` against `zlint -list-lints-json` —
  PKIX-jy95.7.2.
- `run_on_cert()` with per-cert SHA-256 verdict cache —
  PKIX-jy95.7.3.
- `run_on_certs()` batch via multi-file zlint invocation —
  PKIX-jy95.7.4.
