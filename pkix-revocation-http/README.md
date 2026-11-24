# pkix-revocation-http

Online CRL and OCSP fetching for `pkix-revocation`.

**Status: implemented, unpublished.** CRL and OCSP fetching, a sync and an
async fetcher family, two reference HTTP clients (`ureq`, `reqwest`), and a
pluggable cache, behind the feature flags described below.

## Security: this crate applies no destination policy

Revocation URLs are not configuration. A `CRLDistributionPoints` or
`AuthorityInfoAccess` extension is a field of the certificate being
validated, read before that certificate's signature has been checked — so
whoever presents a certificate chooses the URLs this process fetches. A
certificate carrying `http://169.254.169.254/latest/meta-data/` will have it
fetched, by default, without complaint.

What is guaranteed: HTTP and HTTPS schemes only, same-origin redirects only
(so a URL you vet cannot be redirected past your vetting), bounded response
bodies, and a 30-second default timeout. Those bound what an attacker can do
*through* a fetch, not *where* a fetch goes.

What you must do: enforce a destination policy in your `RevocationFetcher` /
`AsyncRevocationFetcher`, or vet the URL before calling. Prefer filtering at
DNS resolution — a hostname check before connecting can be defeated by a name
that resolves publicly when checked and to loopback when connected.

**Note the asymmetry with `pkix-aia-http`,** which fetches equally untrusted
URLs for chain building but *does* refuse non-public destinations by default.
The two crates ship opposite defaults for the same threat. Do not carry an
assumption from one to the other.


## What this does

[`pkix-revocation`] requires the caller to supply pre-fetched DER bytes for
CRL and OCSP checking. This crate extends it with automatic fetching from
URLs found in certificates:

- **CRL Distribution Points** (RFC 5280 §4.2.1.13) — fetch the CRL at the
  URL in the certificate's `CRLDistributionPoints` extension.
- **Authority Info Access / OCSP** (RFC 5280 §4.2.2.1) — send an OCSP
  request to the URL in the `AuthorityInfoAccess` extension.

## Planned API

```rust
use pkix_revocation_http::{HttpCrlFetcher, RevocationFetcher};

// Supply your own HTTP client by implementing RevocationFetcher
struct MyHttpClient;

impl RevocationFetcher for MyHttpClient {
    fn fetch(&self, url: &str) -> Result<Vec<u8>, FetchError> {
        // use reqwest, ureq, hyper, etc.
        Ok(reqwest::blocking::get(url)?.bytes()?.to_vec())
    }
}

let crl_checker = HttpCrlFetcher::new(MyHttpClient, unix_now());
// Use as a RevocationChecker with pkix_chain::verify_chain
verify_chain(&chain, &anchors, &policy, &DefaultVerifier, &crl_checker)?;
```

## Design

The `RevocationFetcher` trait abstracts HTTP transport so you can supply
any client library. The concrete fetchers extract URLs from certificate
extensions, fetch on demand, cache responses for the duration of the
validation call, and delegate to the underlying `CrlChecker`/`OcspChecker`
from `pkix-revocation`.

## Standards

- [RFC 5280] §4.2.1.13 — CRLDistributionPoints extension
- [RFC 5280] §4.2.2.1 — AuthorityInfoAccess extension
- [RFC 5280] §6.3 — CRL validation algorithm
- [RFC 6960] — OCSP

## License

Apache-2.0 OR MIT
