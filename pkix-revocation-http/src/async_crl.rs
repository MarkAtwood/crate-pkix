//! [`crate::AsyncRevocationChecker`] impl for [`crate::AsyncHttpCrlFetcher`].
//!
//! Async parallel of `crate::crl`. Same algorithm — extract HTTP/HTTPS
//! CDP URLs from the certificate, fetch each via the user-supplied
//! [`crate::AsyncRevocationFetcher`], parse the bytes into a
//! [`pkix_revocation::CrlChecker`], delegate. The only behavioural
//! difference vs the sync side is that `fetch` is awaited; CRL parsing
//! and signature verification stay synchronous because they do no I/O.
//!
//! See `crate::crl` for the per-step rationale (first-success-wins,
//! fall-through on transport / parse errors, no-CDPs ⇒ `Ok(())`,
//! all-failed ⇒ [`pkix_revocation::Error::RevocationFetchFailed`] with
//! a per-URL summary).

use crate::{
    extract_cdp_http_urls, AsyncHttpCrlFetcher, AsyncRevocationChecker, AsyncRevocationFetcher,
    FetchRequest,
};
use async_trait::async_trait;
use pkix_path::SignatureVerifier;
use pkix_revocation::{CrlChecker, Error as RevError, RevocationChecker};
use x509_cert::Certificate;

#[async_trait]
impl<F, V> AsyncRevocationChecker for AsyncHttpCrlFetcher<F, V>
where
    F: AsyncRevocationFetcher,
    V: SignatureVerifier + Clone + Send + Sync,
{
    async fn check_revocation(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
    ) -> pkix_revocation::Result<()> {
        // Step 1 — Extract HTTP/HTTPS CDP URLs from the cert. Matches
        // the sync impl's "malformed CDP ⇒ RevocationFetchFailed" choice.
        let urls = extract_cdp_http_urls(cert).map_err(|e| RevError::RevocationFetchFailed {
            description: format!("cRLDistributionPoints extension parse failed: {e}"),
        })?;

        // Step 2 — No URLs ⇒ nothing to check. Matches sync.
        if urls.is_empty() {
            return Ok(());
        }

        // Step 3 — Try each URL in document order. First successful
        // fetch + parse decides the verdict.
        //
        // Note: we deliberately do NOT fan out the fetches in parallel
        // (e.g. via futures::join_all). RFC 5280 §6.3.3 path-validation
        // CRL checking is described as a per-CDP-URL sequence; the sync
        // impl iterates document-order; mirroring that here preserves
        // the "no CRL is ever fetched after the first success" property
        // that operators rely on for rate-limit / quota planning.
        let mut failures: Vec<String> = Vec::with_capacity(urls.len());
        for url in &urls {
            let req = FetchRequest::get(url);
            match self.fetcher.fetch(&req).await {
                Ok(resp) => {
                    match CrlChecker::new(&resp.bytes, self.now_unix, self.verifier.clone()) {
                        // CrlChecker::check_revocation is sync; that's
                        // fine — the work it does is pure CPU (CRL DER
                        // parse + signature verification).
                        Ok(checker) => return checker.check_revocation(cert, issuer),
                        Err(e) => {
                            failures.push(format!("{url}: CRL parse: {e}"));
                            continue;
                        }
                    }
                }
                Err(e) => {
                    failures.push(format!("{url}: {e}"));
                    continue;
                }
            }
        }

        // Step 4 — All URLs failed.
        Err(RevError::RevocationFetchFailed {
            description: format!("all {} URL(s) failed: {}", urls.len(), failures.join("; ")),
        })
    }

    // check_revocation_against_anchor stays at the trait default
    // (`Ok(())`) for the same reason as the sync HttpCrlFetcher: the
    // underlying CrlChecker does not currently expose a
    // TrustAnchor-shaped entry point. Tracked as future work.
}

#[cfg(test)]
mod tests {
    //! Behavioural tests for `AsyncHttpCrlFetcher::check_revocation`.
    //!
    //! Mirrors the sync test suite in `src/crl.rs` — same fixtures, same
    //! verdicts, same multi-URL fallback assertions — but driven through
    //! the async trait. The fetcher is mocked with a closure-style
    //! `AsyncRevocationFetcher` impl so we never touch the network in
    //! a unit test.
    //!
    //! Independent oracle: pyca/cryptography produces the CA + leaves +
    //! CRL bytes (see `tests/fixtures/` and `tests/gen_http_crl_fixtures.py`).
    //! The test asserts revocation verdicts under each fixture.
    use super::*;
    use crate::{FetchError, FetchResponse};
    use der::Decode;
    use pkix_path::DefaultVerifier;
    use std::sync::Mutex;

    const CA: &[u8] = include_bytes!("../tests/fixtures/http-ca.der");
    const LEAF_GOOD: &[u8] = include_bytes!("../tests/fixtures/http-leaf-good.der");
    const LEAF_REVOKED: &[u8] = include_bytes!("../tests/fixtures/http-leaf-revoked.der");
    const LEAF_NO_CDP: &[u8] = include_bytes!("../tests/fixtures/http-leaf-no-cdp.der");
    const CRL_REVOKES_2: &[u8] = include_bytes!("../tests/fixtures/http-crl-revokes-2.der");
    const CRL_EMPTY: &[u8] = include_bytes!("../tests/fixtures/http-crl-empty.der");

    /// Validation timestamp matching the CRL window in the gen script.
    const NOW: u64 = 1_780_272_000;

    /// Mock async fetcher backed by a fixed URL → bytes map. Mutex
    /// (not RefCell) because `AsyncRevocationFetcher: Sync` and unit
    /// tests may run multi-threaded.
    struct StaticMap {
        map: Vec<(&'static str, Vec<u8>)>,
        seen: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl AsyncRevocationFetcher for StaticMap {
        async fn fetch(&self, req: &FetchRequest<'_>) -> Result<FetchResponse, FetchError> {
            self.seen.lock().unwrap().push(req.url.to_owned());
            for (url, bytes) in &self.map {
                if *url == req.url {
                    return Ok(FetchResponse {
                        bytes: bytes.clone(),
                        content_type: Some("application/pkix-crl".into()),
                    });
                }
            }
            Err(FetchError::HttpStatus(404))
        }
    }

    /// Mock fetcher that always returns a fixed error.
    struct AlwaysFail;
    #[async_trait]
    impl AsyncRevocationFetcher for AlwaysFail {
        async fn fetch(&self, _req: &FetchRequest<'_>) -> Result<FetchResponse, FetchError> {
            Err(FetchError::HttpStatus(503))
        }
    }

    fn cert(b: &[u8]) -> Certificate {
        Certificate::from_der(b).unwrap()
    }

    fn fetcher_with_crl(crl: &[u8]) -> StaticMap {
        StaticMap {
            map: vec![("http://crl.example.com/test.crl", crl.to_vec())],
            seen: Mutex::new(Vec::new()),
        }
    }

    // Tests are driven via `#[tokio::test]` — tokio is a dev-dep of
    // this crate already, and the macro is the idiomatic way to drive
    // an async test. We use the single-threaded current-thread runtime
    // (the default `flavor` for `#[tokio::test]`) because the
    // closure-style StaticMap fetcher never yields.

    #[tokio::test]
    async fn good_cert_against_empty_crl_returns_ok() {
        let f = fetcher_with_crl(CRL_EMPTY);
        let h = AsyncHttpCrlFetcher::new(f, DefaultVerifier, NOW);
        h.check_revocation(&cert(LEAF_GOOD), &cert(CA))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn good_cert_against_crl_revoking_other_serial_returns_ok() {
        let f = fetcher_with_crl(CRL_REVOKES_2);
        let h = AsyncHttpCrlFetcher::new(f, DefaultVerifier, NOW);
        h.check_revocation(&cert(LEAF_GOOD), &cert(CA))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn revoked_cert_returns_revoked_error() {
        let f = fetcher_with_crl(CRL_REVOKES_2);
        let h = AsyncHttpCrlFetcher::new(f, DefaultVerifier, NOW);
        let err = h
            .check_revocation(&cert(LEAF_REVOKED), &cert(CA))
            .await
            .unwrap_err();
        assert!(
            matches!(err, RevError::Revoked { .. }),
            "expected Revoked, got {err:?}"
        );
    }

    #[tokio::test]
    async fn cert_without_cdp_extension_returns_ok() {
        let f = AlwaysFail; // fetcher should never be called
        let h = AsyncHttpCrlFetcher::new(f, DefaultVerifier, NOW);
        h.check_revocation(&cert(LEAF_NO_CDP), &cert(CA))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn all_fetches_failing_returns_revocation_fetch_failed() {
        let h = AsyncHttpCrlFetcher::new(AlwaysFail, DefaultVerifier, NOW);
        let err = h
            .check_revocation(&cert(LEAF_GOOD), &cert(CA))
            .await
            .unwrap_err();
        match err {
            RevError::RevocationFetchFailed { description } => {
                assert!(
                    description.contains("http://crl.example.com/test.crl"),
                    "description should name the failed URL: {description}"
                );
                assert!(
                    description.contains("503"),
                    "description should include HTTP status: {description}"
                );
            }
            other => panic!("expected RevocationFetchFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn malformed_crl_response_is_treated_as_fetch_failure_per_url() {
        let f = StaticMap {
            map: vec![("http://crl.example.com/test.crl", vec![0xff, 0xff, 0xff])],
            seen: Mutex::new(Vec::new()),
        };
        let h = AsyncHttpCrlFetcher::new(f, DefaultVerifier, NOW);
        let err = h
            .check_revocation(&cert(LEAF_GOOD), &cert(CA))
            .await
            .unwrap_err();
        match err {
            RevError::RevocationFetchFailed { description } => {
                assert!(
                    description.contains("CRL parse"),
                    "expected CRL-parse hint in description: {description}"
                );
            }
            other => panic!("expected RevocationFetchFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fetcher_actually_called_with_advertised_url() {
        let f = fetcher_with_crl(CRL_EMPTY);
        let h = AsyncHttpCrlFetcher::new(f, DefaultVerifier, NOW);
        h.check_revocation(&cert(LEAF_GOOD), &cert(CA))
            .await
            .unwrap();
        let seen = h.fetcher.seen.lock().unwrap().clone();
        assert_eq!(seen, vec!["http://crl.example.com/test.crl".to_string()]);
    }
}
