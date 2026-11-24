# Changelog

All notable changes to `pkix-aia-http` are documented here. The crate
follows [Keep a Changelog](https://keepachangelog.com/) headings and
[Semantic Versioning](https://semver.org/).

## [Unreleased]

Planned release: **0.3.0**.

### Added

Async fetcher family, behind two new off-by-default features.

- `async` — `AsyncAiaFetcher`, the async analogue of
  `pkix_aia::AiaFetcher`; `NoAsyncAiaFetcher`; and `SyncAsAsync`, a
  bridge for a sync fetcher that genuinely does no I/O. The traits live
  here, not in the `no_std` `pkix-aia` core, so that crate takes on no
  async machinery — the same Option C placement `pkix-revocation-http`
  uses.
- `client-reqwest-async` — `AsyncHttpFetcher`, the `reqwest`-backed
  reference implementation, plus `GuardedAsyncResolver`. Separate from
  `async` so a consumer on hyper or isahc implements the trait without
  reqwest in their graph.
- `AsyncAiaFetcher::batch_fetch` runs requests **concurrently** by
  default, where the sync trait's default loops. AIA chain reassembly
  can have several candidate URIs per certificate, and that difference
  is the reason the async family is worth having.

### Fixed

- The `PKIX-zkjb.5.1` tracking reference in `src/lib.rs`, `Cargo.toml`
  and `README.md` pointed at a bead that was never filed, so a reader
  following it found nothing. Removed along with the "deferred until
  consumer demand surfaces" framing, which the workspace's own
  decision-framing rules reject.

### Security

**The async fetcher's first implementation had an SSRF hole, found by
its own tests before release.** `GuardedAsyncResolver` filters
non-public addresses at DNS resolution, mirroring the sync
`GuardedResolver` — but `reqwest` does not consult a custom resolver
when the URI host is an IP **literal**, because there is nothing to
resolve. So `http://127.0.0.1/`, `http://10.0.0.1/` and
`http://169.254.169.254/` reached the connector untouched while
`http://localhost/` was correctly refused.

`AsyncHttpFetcher::fetch` now checks a literal host before issuing the
request. Checking a literal up front is sound where checking a *name*
would not be: a literal cannot change between check and connect, so
there is no rebinding window, while names still go through the resolver
where the filter applies to the addresses actually connected to.

The lesson is general: a second implementation of a security policy is
where the policy diverges, and documenting parity is not evidence of it.
`tests/async_ssrf.rs` mirrors `tests/review_ssrf.rs` case for case for
that reason.

### Parity with the sync fetcher

`AsyncHttpFetcher` matches `HttpFetcher` on everything that bears on
safety: destination policy at resolution time plus the literal check,
redirects not followed, a per-request timeout, a hard response-size cap
enforced while streaming rather than after buffering, and non-HTTP
schemes reported as `UriUnsupported` before any I/O.



Planned release: **0.2.0** (breaking behaviour).

### Changed

- `HttpFetcher::new()` follows no redirects, ignores proxy environment
  variables, and refuses loopback, private, link-local, ULA, multicast
  and other internal destinations after DNS resolution
  (`AiaError::DestinationNotAllowed`). `allow_private_destinations()`
  opts out. The filter (`GuardedResolver`) uses ureq's `unversioned`
  resolver API.

### Fixed

- AIA fetching was an SSRF vector: caIssuers URIs from unvalidated
  certificates were fetched from any address, and redirects were
  followed without re-checking.

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
