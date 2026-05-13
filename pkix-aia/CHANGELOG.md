# Changelog

All notable changes to `pkix-aia` are documented here. The crate
follows [Keep a Changelog](https://keepachangelog.com/) headings and
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Initial scaffold (PKIX-zkjb.2). Workspace member; `no_std + alloc`
  by default; `forbid(unsafe_code)`.
- Public type:
  - `AiaError` — `#[non_exhaustive]` enum with variants
    `FetchingDisabled`, `HttpStatus(u16)`,
    `ResponseTooLarge { limit, actual }`,
    `MalformedCertificate(String)`, `Timeout`,
    `UriUnsupported(String)`, and (under `std`)
    `IoFailure { kind: std::io::ErrorKind, message: String }`.
- Feature flags:
  - `std` — enables `std::error::Error` impl on `AiaError` and
    unlocks the `IoFailure` variant.
  - `serde` — derives `Serialize` / `Deserialize` on `AiaError`.
    With `std + serde`, the `IoFailure` variant's `kind` field
    round-trips through a stable string label via a crate-private
    helper (`std::io::ErrorKind` is not serde-aware upstream).
    Unknown labels deserialize to `ErrorKind::Other` for forward
    compatibility with future stdlib variants.
- Compile-time assertion that `AiaError: Send + Sync`, per AGENTS.md
  non-negotiable #6 and the workspace convention recorded in memory
  `send-sync-invariant-in-pkix-workspace-pkix-2l0v`.
- Integration test `round_trip` (gated on `serde + std`) pins the
  JSON wire form for every variant and verifies bytewise round-trip
  identity. Forward-compat for `IoFailure.kind` covered: a label
  the helper does not recognize deserializes to `ErrorKind::Other`
  rather than failing.
- Inline unit tests cover `Display` for every variant, `Clone +
  PartialEq + Eq` invariants, and the `io_error_kind_serde` label
  round-trip table.

### Not yet shipped

- `AiaFetcher` trait — PKIX-zkjb.3.
- `NoAiaFetcher` zero-cost default — PKIX-zkjb.4.
- `pkix-aia-http` HTTP adapter — PKIX-zkjb.5.
- `pkix-chain::Verifier` 3-generic `A: AiaFetcher` API freeze — PKIX-zkjb.9.

These are tracked under the PKIX-zkjb umbrella epic. PKIX-zkjb.2 is
the foundation; the rest land in subsequent point releases.
