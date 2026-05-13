# Changelog

All notable changes to `pkix-truststore` are documented here. The crate
follows [Keep a Changelog](https://keepachangelog.com/) headings and
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Initial Tier-1 PEM/DER trust anchor loading (PKIX-lhm4). Bytes-in,
  `Vec<TrustAnchor>`-out plumbing for `pkix-path`. RFC 7468 strict
  PEM parsing via `x509-cert::load_pem_chain`, with the crate's own
  UTF-8 BOM handling and empty-input guard (works around a
  subtract-with-overflow panic in `x509-cert 0.2.5`; tracked as
  PKIX-wzmg and fixed upstream in `x509-cert 0.3.0-rc.2`, see
  PKIX-rb6n for the workaround-removal follow-up).
- Public API: `from_pem`, `from_der`, `from_der_iter` (the canonical
  adapter entry point for HSM / OS-keychain / cloud-KMS sources),
  `from_pem_file`, `from_der_file`, `Error` (`#[non_exhaustive]`),
  and re-exported `pkix_path::TrustAnchor`.
- Real-world integration fixtures: Debian `ca-certificates.crt`
  (147 anchors) committed alongside Alpine and Fedora ca-bundle
  fixtures (PKIX-zydl). `openssl` is used as the PEM <-> DER oracle.
  Fixture-refresh procedure (image digest, package version, fetch
  date, anchor-by-anchor cross-check against the source distribution)
  is recorded in `tests/fixtures.rs`.
- `Send + Sync` compile-time assertion on `Error` (PKIX-2l0v.2). The
  `pkix_path::TrustAnchor` re-export is covered by the `pkix-path`
  assertion.
- Optional `serde` feature deriving `Serialize` / `Deserialize` on
  `Error` and the new `IoFailure` type (PKIX-2l0v.1). The wire form
  is format-adaptive: human-readable serializers (JSON, TOML, YAML)
  emit base64-encoded DER for fields backed by foreign DER types;
  binary serializers (postcard, bincode, MessagePack) emit raw DER
  bytes. Selection driven by `serde::Serializer::is_human_readable`.
- Top-level `# Limitations` rustdoc section documenting the project
  stance — no compiled-in CA bundle, no baked-in trust source, no
  platform integration in this crate (PKIX-wlsr.6). Platform-,
  HSM-, and cloud-KMS-specific adapters live in sibling crates
  (`pkix-truststore-system` per PKIX-8h87, `pkix-truststore-pkcs11`
  per PKIX-p8vz).

### Changed (breaking)

- `Error::Io` payload type changes from `std::io::Error` to a new
  `IoFailure { kind: std::io::ErrorKind, message: String }` struct
  (PKIX-2l0v.1). Pattern matches that bind the inner value need to
  update; matches that bind `_` are unaffected. The OS error code
  is dropped (low value for cache-replay use cases); `io::ErrorKind`
  and the rendered message are preserved. The change is required
  because `std::io::Error` is not `Clone + Eq + Serialize`, which
  AGENTS.md non-negotiable #6 requires of load-bearing result types.
- `Error::Pem` and `Error::Der` payload type changes from
  `der::Error` to the re-exported `pkix_path::DerError`
  (PKIX-2l0v.1). Same breaking-change classification.

### Notes

- Crate is at `0.0.0` placeholder version pending first crates.io
  release. The `0.1.1` version of the name on crates.io is a
  pre-reset placeholder predating this implementation and should
  not be depended on. The 1.0 release will be the first substantive
  publish. See the [Stub crates] note in the workspace-level
  [`CHANGELOG.md`].

[`CHANGELOG.md`]: ../CHANGELOG.md
