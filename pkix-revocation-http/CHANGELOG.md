# Changelog

All notable changes to `pkix-revocation-http` are documented here. The
crate follows [Keep a Changelog](https://keepachangelog.com/) headings
and [Semantic Versioning](https://semver.org/).

## [Unreleased]

_Nothing yet._

## [1.0.0] — TBD

First stable release.

### Added

- CDP and AIA HTTP URL extraction helpers that walk a certificate's
  `cRLDistributionPoints` and `authorityInfoAccess` extensions and
  return the `http://` / `https://` URIs in declaration order
  (PKIX-a1yc.1 / .2).
- OCSP request DER encoding via `x509-ocsp`'s `builder` sub-feature
  (PKIX-a1yc.4). The optional `ocsp` feature pulls in `x509-ocsp`,
  `sha1`, and `sha2` so the builder can populate `CertID.hashAlgorithm`
  from a `Digest` impl's `AssociatedOid`.
- `RevocationFetcher` trait widened to express OCSP POST semantics
  alongside CRL GET (PKIX-a1yc.3). Sync, object-safe; the crate
  supplies one transport-layer concern (URI -> bytes) and stays out
  of the async runtime business.
- `HttpCrlFetcher` — `RevocationChecker` impl that walks the
  certificate's CDP URIs, fetches the first one that returns a parseable
  CRL, and delegates to `pkix_revocation::CrlChecker`. First-success-wins
  with fall-through on transport / parse failures; aggregates
  whole-cert failure into `pkix_revocation::Error::RevocationFetchFailed`
  (PKIX-a1yc.5).
- `HttpOcspFetcher` — `RevocationChecker` impl that builds an OCSP
  request, POSTs it to the cert's AIA OCSP URLs, and delegates the
  response to `pkix_revocation::OcspChecker`. Same first-success-wins /
  fall-through / aggregation contract as the CRL fetcher
  (PKIX-a1yc.6).
- `UreqFetcher` — reference synchronous HTTP client using `ureq`
  behind the optional `client-ureq` feature (PKIX-a1yc.8). Pulls in
  rustls for HTTPS. Consumers can write their own `RevocationFetcher`
  impl against any sync HTTP library instead.
- Async parallel of the sync fetcher family behind the optional
  `async` and `client-reqwest-async` features (PKIX-a1yc.10):
  - `AsyncRevocationFetcher` and `AsyncRevocationChecker` traits via
    `async-trait`.
  - `AsyncHttpCrlFetcher` and `AsyncHttpOcspFetcher` wrapper types
    that port the sync algorithm one-for-one (only the URL fetch is
    awaited; CRL / OCSP parse and signature verification stay sync).
  - Reference reqwest-backed async client when `client-reqwest-async`
    is enabled. Async consumers bring their own runtime; the crate
    does not.

  The async trait lives in `pkix-revocation-http`, not in
  `pkix-revocation` core. The core revocation crate stays sync-only
  and free of `async-trait` / `tokio` / `Send` bounds. Mirrors
  reqwest's own `Client` (async) / `blocking::Client` (sync) split.
- `RevocationCache` trait + in-memory reference impl, plus
  `CachedHttpCrlFetcher` / `CachedHttpOcspFetcher` wrappers that
  compose with the un-cached fetchers (PKIX-a1yc.7). CRL keys are
  `(issuer_dn_der, distribution_point_uri)` so partitioned CRLs at
  different URIs do not collide; `CRLNumber` is freshness metadata,
  not key material. OCSP keys are `(cert_serial, issuer_key_hash,
  responder_url)`. The wrapper rejects CRL rollback on refresh per
  RFC 5280 §5.2.3 via a pure `is_rollback()` decision function.
- Mock-server integration test suite under `tests/` using `mockito`
  (sync) and `wiremock` (async) (PKIX-a1yc.9). Both are dev-deps;
  they do not propagate to consumers.
- Top-level `# Limitations` rustdoc section documenting the crate's
  current shipped surface and what is intentionally out of scope
  (no bundled HTTP client, no retry / backoff, async runtime is
  caller-supplied, the in-memory cache is unbounded by design)
  (PKIX-wlsr.6).

### Notes

- Crate is at `0.0.0` placeholder version pending first crates.io
  release. The `0.1.1` version of the name on crates.io is a
  pre-reset placeholder predating this implementation and should not
  be depended on. The 1.0 release will be the first substantive
  publish.

## Pre-history

- `9b0995eb` (`feat: add stub crates, specs, and READMEs`) — Initial
  stub crate scaffolding alongside `pkix-ct`, `pkix-composite`, and
  `pkix-ac`. No functional code; spec references and README only.
- `8f148eff` (`chore: bump to 0.2.0; pin stub crates at 0.1.1`) — Pinned
  at `0.1.1` placeholder version during the 0.2.0 workspace release.
  Subsequently reset to `0.0.0`; see the [Stub crates] note in the
  workspace-level [`CHANGELOG.md`].

[`CHANGELOG.md`]: ../CHANGELOG.md
