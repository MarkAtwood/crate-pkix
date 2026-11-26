# pkix-aia-http

**Synchronous HTTP fetcher for [`pkix-aia`](../pkix-aia)'s `AiaFetcher`
trait, per [RFC 5280
§4.2.2.1](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.2.1).**

AIA (Authority Information Access) is the certificate extension that
carries `caIssuers` URIs pointing at the certificate's issuer.
Chain-build code can follow these URIs to fetch missing intermediate
certificates when the caller-supplied chain is incomplete. This crate
plugs an HTTP transport into the `AiaFetcher` trait so the
chain-build flow in `pkix-chain` can resolve `caIssuers` URIs whose
scheme is `http://` or `https://`.

## Quick start

```rust
use pkix_aia::AiaFetcher;
use pkix_aia_http::HttpFetcher;

let fetcher = HttpFetcher::new();
let der_bytes = fetcher.fetch("http://ca.example/intermediate.crt")?;
println!("fetched {} bytes", der_bytes.len());
# Ok::<(), pkix_aia::AiaError>(())
```

The default fetcher carries a 10-second timeout and a 1 MiB response
body cap, does not follow redirects, ignores environment proxies, and
refuses destinations that do not resolve to a public address
(`AiaError::DestinationNotAllowed`), because caIssuers URIs come from
not-yet-validated certificates (SSRF). What counts as non-public is
`pkix-net-guard`'s decision, not a list kept here: besides loopback,
private, link-local, ULA, multicast and unspecified addresses it covers
RFC 6598 shared space and the IPv4-mapped, IPv4-compatible and NAT64
forms, which are the usual way an address filter is slipped past.
Override the size cap via `with_max_response_size`, the destination
filter via `allow_private_destinations`, or everything by injecting a
pre-configured `ureq::Agent` via `with_agent` (which then owns redirect
and destination policy).

## Design parallel: `pkix-revocation-http`

This crate intentionally mirrors `pkix-revocation-http`'s
`UreqFetcher` shape: the same `ureq` dependency (`features =
["rustls"]` for HTTPS), the same response-size cap pattern, the same
"construct once, fetch many times" idiom. Callers running both crates
in the same process can configure a custom `ureq::Agent` once and
pass it to both fetchers via the `with_agent` builders, sharing
connection pools.

**The mirroring stops at destination policy, and that is the one place it
matters.** This crate refuses non-public destinations by default;
`pkix-revocation-http` applies no destination policy at all, leaving it to
the caller's fetcher. Both choices are deliberate — this crate owns its
transport and so can own a policy, while that crate's transport is a
caller-supplied trait — but a reader who has absorbed how similar the two
crates are is exactly the reader who will assume the defaults match. They
do not. If you learnt here that AIA fetching is SSRF-safe out of the box,
revocation fetching is not.

The one-callback-per-crate split (`pkix-revocation-http` for
CRL / OCSP, `pkix-aia-http` for AIA) follows the workspace's
trust-domain seam convention. The revocation and AIA seams in
`pkix-chain` are independent: a caller can use AIA without
revocation, revocation without AIA, or both.

## What's fetched

`HttpFetcher::fetch` issues a synchronous HTTP `GET` against the
supplied URI. The response body is returned verbatim as `Vec<u8>`;
parsing the bytes as a DER X.509 certificate is the caller's
responsibility (typically delegated to `pkix-path-builder` or
`pkix-chain`).

Non-HTTP URI schemes (`ldap://`, `ftp://`, `file://`, …) return
`AiaError::UriUnsupported` immediately, before any network I/O.

## Limitations

- The async family is off by default. `AsyncAiaFetcher` ships behind
  the `async` feature and the `reqwest`-backed `AsyncHttpFetcher`
  behind `client-reqwest-async`, so a synchronous consumer pays
  nothing for either. Its `batch_fetch` runs requests concurrently,
  unlike the sync default, which loops.
- No LDAP transport. Could ship as a sibling `pkix-aia-ldap` crate
  if demand surfaces.
- No retry, no backoff, no caching. These are caller-side concerns
  — wrap `HttpFetcher` with the patterns documented in `pkix-aia`'s
  rustdoc (`CachingFetcher` worked example).

## Status

Initial release: synchronous `HttpFetcher` over `ureq`. Real
end-to-end use through `pkix-chain::Verifier`'s 3rd generic
parameter is unlocked by the PKIX-zkjb.7 chain-build integration
work; the trait surface this crate implements (`AiaFetcher`) is
frozen at `pkix-aia 1.0`.

## License

Apache-2.0 OR MIT
