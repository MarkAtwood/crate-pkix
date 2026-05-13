# Changelog

All notable changes to `pkix-aia-http` are documented here. The crate
follows [Keep a Changelog](https://keepachangelog.com/) headings and
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Initial `HttpFetcher` synchronous HTTP transport implementing
  `pkix_aia::AiaFetcher` over `ureq` (PKIX-zkjb.5). Mirrors
  `pkix-revocation-http`'s `UreqFetcher` shape:
  - `HttpFetcher::new()` constructor with sensible defaults
    (10-second timeout, 1 MiB body cap, `ureq`'s default agent).
  - `HttpFetcher::with_agent(agent)` for callers who need a
    pre-configured `ureq::Agent` (custom TLS config, proxies,
    additional timeouts).
  - `HttpFetcher::with_max_response_size(n)` builder method.
  - `HttpFetcher::agent()` accessor for sharing connection pools
    with sibling fetchers (e.g.
    `pkix_revocation_http::UreqFetcher`).
- `DEFAULT_MAX_RESPONSE_SIZE` constant (1 MiB) and
  `DEFAULT_TIMEOUT` constant (10 seconds).
- `AiaFetcher` impl:
  - Validates URI scheme before any network I/O. Non-`http://` /
    non-`https://` URIs return `AiaError::UriUnsupported`
    synchronously.
  - Maps HTTP `4xx` / `5xx` status to `AiaError::HttpStatus(code)`.
  - Maps `ureq` timeouts to `AiaError::Timeout`.
  - Maps other transport failures (DNS, TLS handshake, body
    decode) to `AiaError::IoFailure { kind: ErrorKind::Other,
    message }`.
  - Enforces the response-size cap via `take(limit + 1)` so
    "exactly limit" and "more than limit" are distinguishable;
    overflow surfaces as `AiaError::ResponseTooLarge { limit,
    actual }`.
- Integration test suite in `tests/integration.rs` against a
  `mockito::Server`:
  - Happy path (2xx body verbatim, with and without Content-Type
    header).
  - Status mapping (404 / 500 / 503).
  - Body cap enforcement (oversized body rejected; under-cap body
    passes through verbatim).
  - URI scheme rejection (`ldap://`, `ftp://`, `file://`) short-
    circuits before any network I/O.
  - `batch_fetch` default-impl preserves per-URI order and per-URI
    results.
- `Send + Sync` compile-time assertion on `HttpFetcher`
  (PKIX-2l0v.2).

### Notes

- Crate is at `0.0.0` placeholder version. The first crates.io
  release will land alongside the `pkix-chain` chain-build
  integration (PKIX-zkjb.7) that makes `HttpFetcher` reachable
  through the `Verifier` 3rd generic.
