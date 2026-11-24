# Changelog

All notable changes to `pkix-dane-resolver` are documented here. The
crate follows [Keep a Changelog](https://keepachangelog.com/) headings
and [Semantic Versioning](https://semver.org/).

## [Unreleased]

Planned release: **0.2.0**. Breaking relative to 0.1.0 only in the sense
that 0.1.0 had no public API at all.

### Added

DNSSEC-validating resolution of DANE TLSA records, built on
`hickory-resolver` 0.26.

- `AsyncTlsaResolver` — the async analogue of `pkix_dane::TlsaResolver`,
  living here rather than in the `no_std` core so that crate takes on no
  async machinery. `batch_resolve` joins concurrently by default, which
  is the point of the async family: the sync trait's equivalent can only
  loop. Implemented for `Arc<T>` so a resolver can be shared.
- `HickoryTlsaResolver` — the reference implementation. `new` discovers
  upstream servers; `with_upstream` takes them directly.
- `NoAsyncTlsaResolver` — the zero-cost null implementation, for wiring
  the seam without enabling DANE.
- `UpstreamConfig` and `upstream_from_environment` — upstream discovery:
  the `PKIX_DANE_RESOLVER` variable if set, otherwise system
  configuration. No hardcoded public resolvers.
- `ResolverError` — construction failures, distinct from `DaneError`'s
  resolution and matching failures.

### Design notes

- **Async only, no sync facade.** Hickory is async. A synchronous facade
  would have to call `block_on` — which panics from inside a Tokio
  runtime — or own a background thread running its own runtime, hiding
  an executor behind a signature that reads as an ordinary blocking
  call. Neither is acceptable, so the sync path takes records as data
  instead: `pkix-dane`'s matching functions are pure over
  `(certificate, TlsaResponse)`, so resolution and verification were
  always separable.
- **The trust anchor is the caller's.** No anchor ships here and
  `new` requires one. IANA's live in `pkix-dnssec-anchor`, versioned
  independently so a KSK roll is a `cargo update`. A resolver built with
  no anchor is refused at construction rather than silently never
  validating.
- **Validation happens here, not upstream.** An upstream resolver's `AD`
  bit is a claim by a host on the network path. Signatures are verified
  locally, which means the upstream needs no DNSSEC capability — only
  the willingness to return `RRSIG`, `DNSKEY` and `DS` records
  unmangled.
- **The weakest proof in an answer wins.** Each record carries its own
  DNSSEC proof; the response takes the weakest across the set, with
  `Bogus` weakest of all. An attacker who can inject one unvalidated
  record into an otherwise-secure RRset must not get the set treated as
  secure.

### Known gaps

- **No cache.** TLSA records carry TTLs and caching them is an expected
  deployment pattern. The trait is shaped to admit a wrapper — `&self`
  receivers, a `Clone + PartialEq` response type — but none ships:
  AGENTS.md non-negotiable #6 requires the workspace to admit caches,
  not build them. Hickory's own response cache still applies underneath.
- **Negative answers report `Indeterminate`, not `Secure`.** A signed
  `NODATA` or `NXDOMAIN` is an authenticated denial and should be
  reported `Secure` so `TlsaResponse::is_authenticated_denial` can see
  it. Doing so needs the SOA's proof off hickory's negative-response
  error, which this release does not reach into. `Indeterminate` is the
  fail-closed reading and permits PKIX fallback under the opportunistic
  policy, which is correct handling — just less informative than it
  could be.
- **No MX-derived lookup**, so SMTP-DANE (RFC 7672) is not supported
  here. That needs a DNSSEC-validated MX step; tracked separately.

### Testing

22 tests. The live tests reach real signed zones and skip with an
actionable message where the environment cannot support them.

Note for anyone running them: `systemd-resolved`'s stub listener on
`127.0.0.53`, which `/etc/resolv.conf` points at on most modern Linux
desktops, validates internally and **strips DNSSEC records from client
answers**. A validating client behind it sees every answer as
unvalidatable. That is the upstream-mangling case `PKIX_DANE_RESOLVER`
exists for. Set `PKIX_DANE_RESOLVER_TEST_UPSTREAM` to a
DNSSEC-transparent resolver to run the end-to-end validation test, which
asserts a signed zone comes back `Secure` and an unsigned one does not.
That pair is what proves validation is real rather than assumed.

`good.dane.huque.com` is the signed test target. `dns.google` was tried
first and publishes no TLSA records at all.
