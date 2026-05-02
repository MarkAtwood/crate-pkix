# pkix-revocation-http

Online CRL and OCSP fetching for `pkix-revocation`.

**Status: planned (not yet implemented). See issue PKIX-58m.**

## What this will do

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
