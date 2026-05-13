# Changelog

All notable changes to `pkix-aia` are documented here. The crate
follows [Keep a Changelog](https://keepachangelog.com/) headings and
[Semantic Versioning](https://semver.org/).

## [Unreleased]

_Nothing yet._

## [1.0.0] — TBD

First stable release.

### Added

- Initial scaffold (PKIX-zkjb.2). Workspace member; `no_std + alloc`
  by default; `forbid(unsafe_code)`.
- Public types:
  - `AiaError` — `#[non_exhaustive]` enum with variants
    `FetchingDisabled`, `HttpStatus(u16)`,
    `ResponseTooLarge { limit, actual }`,
    `MalformedCertificate(String)`, `Timeout`,
    `UriUnsupported(String)`, and (under `std`)
    `IoFailure { kind: std::io::ErrorKind, message: String }`.
  - `AiaFetcher` trait (PKIX-zkjb.3) with required method
    `fetch(&self, uri: &str) -> Result<Vec<u8>, AiaError>` and
    default-impl `batch_fetch(&self, uris: &[&str]) ->
    Vec<Result<Vec<u8>, AiaError>>` that iterates `fetch`. `&self`
    receiver admits caching wrappers via interior mutability;
    rustdoc carries a worked caching-wrapper doctest using
    `alloc::collections::BTreeMap` + `core::cell::RefCell` so the
    pattern is demonstrable on `no_std + alloc` targets. Synchronous
    only — async adapters live in separate crates. Returns raw DER
    bytes; certificate parsing is the caller's responsibility. No
    timeout parameter (per-adapter construction concern).
  - `NoAiaFetcher` (PKIX-zkjb.4) — zero-sized unit struct,
    `#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]`,
    `impl AiaFetcher` returning `AiaError::FetchingDisabled` for
    every URI. `batch_fetch` uses the trait default-impl, so a
    batch of N URIs returns a `Vec` of N `FetchingDisabled` errors.
    Designed as the placeholder for
    `pkix-chain::Verifier<'a, V, R, A = NoAiaFetcher>` (PKIX-zkjb.9,
    planned) so callers who don't want AIA fetching wired up keep
    the historical "caller supplies the complete chain" semantics.
    Compile-time asserted `Send + Sync` alongside `AiaError`.
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

### Companion crate status

The 1.0 surface in this crate (`AiaError` + `AiaFetcher` +
`NoAiaFetcher`) is complete; the `pkix-chain::Verifier` 3-generic
`A: AiaFetcher` integration shipped via PKIX-zkjb.9. The
sync HTTP transport `pkix-aia-http` shipped via PKIX-zkjb.5 at
0.0.0 (post-1.0 cadence). Reaching it from `pkix-chain` requires
the chain-build integration tracked under PKIX-zkjb.7 (post-1.0).
