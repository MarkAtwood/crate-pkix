//! Review regressions for the async wrappers' anchor flow: both used to
//! inherit `AsyncRevocationChecker::check_revocation_against_anchor`'s
//! default `Ok(())`, so the certificate issued directly by the trust anchor
//! was never checked. Fixtures: `tests/fixtures/review/`.
//!
//! Run: cargo test -p pkix-revocation-http --features async,crl,ocsp --test review_async_anchor

#![cfg(all(feature = "async", feature = "crl", feature = "ocsp"))]

use async_trait::async_trait;
use der::Decode as _;
use pkix_path::{DefaultVerifier, TrustAnchor};
use pkix_revocation::Error as RevError;
use pkix_revocation_http::{
    AsyncHttpCrlFetcher, AsyncHttpOcspFetcher, AsyncRevocationChecker, AsyncRevocationFetcher,
    FetchError, FetchRequest, FetchResponse,
};
use x509_cert::Certificate;

/// 2026-06-01T00:00:00Z — inside the review CRL and OCSP windows.
const NOW: u64 = 1_780_272_000;

fn fx(name: &str) -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/review/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}
fn cert(name: &str) -> Certificate {
    Certificate::from_der(&fx(name)).unwrap()
}

/// Serves the same body for every request.
struct Fixed(Vec<u8>);

#[async_trait]
impl AsyncRevocationFetcher for Fixed {
    async fn fetch(&self, _req: &FetchRequest<'_>) -> Result<FetchResponse, FetchError> {
        Ok(FetchResponse {
            bytes: self.0.clone(),
            content_type: None,
        })
    }
}

#[tokio::test]
async fn async_http_crl_fetcher_checks_anchor_issued_cert() {
    let h = AsyncHttpCrlFetcher::new(Fixed(fx("base-crl.der")), DefaultVerifier, NOW);
    let anchor = TrustAnchor::from_cert(cert("ca.der"));
    let r = h
        .check_revocation_against_anchor(&cert("leaf-serial2.der"), &anchor)
        .await;
    assert!(matches!(r, Err(RevError::Revoked { .. })), "got {r:?}");
}

#[tokio::test]
async fn async_http_ocsp_fetcher_checks_anchor_issued_cert() {
    let h = AsyncHttpOcspFetcher::new(Fixed(fx("ocsp-serial2-revoked.der")), DefaultVerifier, NOW);
    let anchor = TrustAnchor::from_cert(cert("ca.der"));
    let r = h
        .check_revocation_against_anchor(&cert("leaf-serial2.der"), &anchor)
        .await;
    assert!(matches!(r, Err(RevError::Revoked { .. })), "got {r:?}");
}
