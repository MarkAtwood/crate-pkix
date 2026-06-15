//! [`crate::AsyncRevocationChecker`] impl for [`crate::AsyncHttpOcspFetcher`].
//!
//! Async parallel of `crate::ocsp`. Same algorithm — build the OCSP
//! request body once, walk every HTTP/HTTPS responder URL from the
//! cert's `authorityInfoAccess` extension, POST the body, hand the
//! response bytes to [`pkix_revocation::OcspChecker`], delegate. The
//! only behavioural difference vs the sync side is that `fetch` is
//! awaited; OCSP parsing and signature verification stay synchronous.
//!
//! See `crate::ocsp` for the per-step rationale.

use crate::{
    build_ocsp_request, extract_aia_http_urls, AsyncHttpOcspFetcher, AsyncRevocationChecker,
    AsyncRevocationFetcher, FetchRequest, OCSP_REQUEST_CT,
};
use async_trait::async_trait;
use pkix_path::SignatureVerifier;
use pkix_revocation::{Error as RevError, OcspChecker, RevocationChecker};
use x509_cert::Certificate;

#[async_trait]
impl<F, V> AsyncRevocationChecker for AsyncHttpOcspFetcher<F, V>
where
    F: AsyncRevocationFetcher,
    V: SignatureVerifier + Clone + Send + Sync,
{
    async fn check_revocation(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
    ) -> pkix_revocation::Result<()> {
        // Step 1 — Build the OCSP request body once. Body reuse across
        // URLs matches the sync impl.
        let req_bytes = build_ocsp_request(cert, issuer, self.hash_alg).map_err(|e| {
            RevError::RevocationFetchFailed {
                description: format!("OCSP request build failed: {e}"),
            }
        })?;

        // Step 2 — Extract HTTP/HTTPS OCSP responder URLs.
        let aia = extract_aia_http_urls(cert).map_err(|e| RevError::RevocationFetchFailed {
            description: format!("authorityInfoAccess extension parse failed: {e}"),
        })?;

        // Step 3 — No OCSP URLs ⇒ nothing for an OCSP-only checker to
        // do. Matches sync.
        if aia.ocsp.is_empty() {
            return Ok(());
        }

        // Step 4 — POST to each URL in document order. First successful
        // POST + parse decides the verdict. As with the CRL side we
        // serialize rather than fan out in parallel: deterministic
        // ordering, predictable responder rate-limit profile.
        let mut failures: Vec<String> = Vec::with_capacity(aia.ocsp.len());
        for url in &aia.ocsp {
            let req = FetchRequest::post(url, &req_bytes.body, OCSP_REQUEST_CT);
            match self.fetcher.fetch(&req).await {
                Ok(resp) => {
                    match OcspChecker::new(&resp.bytes, self.now_unix, self.verifier.clone()) {
                        Ok(checker) => return checker.check_revocation(cert, issuer),
                        Err(e) => {
                            failures.push(format!("{url}: OCSP parse: {e}"));
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

        // Step 5 — All URLs failed.
        Err(RevError::RevocationFetchFailed {
            description: format!(
                "all {} URL(s) failed: {}",
                aia.ocsp.len(),
                failures.join("; ")
            ),
        })
    }

    // check_revocation_against_anchor stays at the trait default
    // (`Ok(())`). Same reason as the sync HttpOcspFetcher.
}

#[cfg(test)]
mod tests {
    //! Behavioural tests for `AsyncHttpOcspFetcher::check_revocation`.
    //!
    //! Mirrors `src/ocsp.rs` tests on the sync side. Independent oracle:
    //! pyca/cryptography produces CA + leaves + matched OCSP responses
    //! (see `tests/gen_http_crl_fixtures.py`); the HTTP transport is
    //! mocked with a closure-style `AsyncRevocationFetcher`.
    use super::*;
    use crate::{FetchError, FetchMethod, FetchResponse, OcspHashAlg};
    use der::Decode;
    use pkix_path::DefaultVerifier;
    use std::sync::Mutex;

    const CA: &[u8] = include_bytes!("../tests/fixtures/http-ca.der");
    const LEAF_GOOD: &[u8] = include_bytes!("../tests/fixtures/http-leaf-good.der");
    const LEAF_REVOKED: &[u8] = include_bytes!("../tests/fixtures/http-leaf-revoked.der");
    const LEAF_NO_AIA: &[u8] = include_bytes!("../tests/fixtures/http-leaf-no-cdp.der");
    const RESP_GOOD: &[u8] = include_bytes!("../tests/fixtures/http-ocsp-good.der");
    const RESP_REVOKED: &[u8] = include_bytes!("../tests/fixtures/http-ocsp-revoked.der");

    const NOW: u64 = 1_780_272_000;

    /// Mock async OCSP fetcher. Records each call so tests can assert
    /// POST shape (URL + body + Content-Type) — the OCSP regression
    /// guard from the sync test suite, ported.
    struct StaticOcspMap {
        map: Vec<(&'static str, Vec<u8>)>,
        seen: Mutex<Vec<RecordedCall>>,
    }

    #[derive(Debug, Clone)]
    struct RecordedCall {
        url: String,
        body: Option<Vec<u8>>,
        content_type: Option<String>,
    }

    #[async_trait]
    impl AsyncRevocationFetcher for StaticOcspMap {
        async fn fetch(&self, req: &FetchRequest<'_>) -> Result<FetchResponse, FetchError> {
            let (body, content_type) = match req.method {
                FetchMethod::Get => (None, None),
                FetchMethod::Post { body, content_type } => {
                    (Some(body.to_vec()), Some(content_type.to_string()))
                }
            };
            self.seen.lock().unwrap().push(RecordedCall {
                url: req.url.to_string(),
                body,
                content_type,
            });
            for (url, bytes) in &self.map {
                if *url == req.url {
                    return Ok(FetchResponse {
                        bytes: bytes.clone(),
                        content_type: Some("application/ocsp-response".to_string()),
                    });
                }
            }
            Err(FetchError::HttpStatus(404))
        }
    }

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

    fn fetcher_with(resp: &[u8]) -> StaticOcspMap {
        StaticOcspMap {
            map: vec![("http://ocsp.example.com/", resp.to_vec())],
            seen: Mutex::new(Vec::new()),
        }
    }

    #[tokio::test]
    async fn good_cert_with_good_ocsp_returns_ok() {
        let f = fetcher_with(RESP_GOOD);
        let h = AsyncHttpOcspFetcher::new(f, DefaultVerifier, NOW);
        h.check_revocation(&cert(LEAF_GOOD), &cert(CA))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn revoked_cert_with_revoked_ocsp_returns_revoked() {
        let f = fetcher_with(RESP_REVOKED);
        let h = AsyncHttpOcspFetcher::new(f, DefaultVerifier, NOW);
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
    async fn cert_without_aia_extension_returns_ok() {
        let f = AlwaysFail; // fetcher should never be called
        let h = AsyncHttpOcspFetcher::new(f, DefaultVerifier, NOW);
        h.check_revocation(&cert(LEAF_NO_AIA), &cert(CA))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn all_fetches_failing_returns_revocation_fetch_failed() {
        let h = AsyncHttpOcspFetcher::new(AlwaysFail, DefaultVerifier, NOW);
        let err = h
            .check_revocation(&cert(LEAF_GOOD), &cert(CA))
            .await
            .unwrap_err();
        match err {
            RevError::RevocationFetchFailed { description } => {
                assert!(
                    description.contains("http://ocsp.example.com/"),
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
    async fn malformed_ocsp_response_is_treated_as_fetch_failure() {
        let f = StaticOcspMap {
            map: vec![("http://ocsp.example.com/", vec![0xff, 0xff, 0xff])],
            seen: Mutex::new(Vec::new()),
        };
        let h = AsyncHttpOcspFetcher::new(f, DefaultVerifier, NOW);
        let err = h
            .check_revocation(&cert(LEAF_GOOD), &cert(CA))
            .await
            .unwrap_err();
        match err {
            RevError::RevocationFetchFailed { description } => {
                assert!(
                    description.contains("OCSP parse"),
                    "expected OCSP-parse hint in description: {description}"
                );
            }
            other => panic!("expected RevocationFetchFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fetcher_called_with_post_body_and_content_type() {
        let f = fetcher_with(RESP_GOOD);
        let h = AsyncHttpOcspFetcher::new(f, DefaultVerifier, NOW);
        h.check_revocation(&cert(LEAF_GOOD), &cert(CA))
            .await
            .unwrap();

        let calls = h.fetcher.seen.lock().unwrap().clone();
        assert_eq!(calls.len(), 1, "should POST exactly once");
        let only = &calls[0];
        assert_eq!(only.url, "http://ocsp.example.com/");
        assert_eq!(
            only.content_type.as_deref(),
            Some("application/ocsp-request")
        );
        assert!(
            only.body.is_some() && !only.body.as_ref().unwrap().is_empty(),
            "POST body must be non-empty DER OCSP request"
        );
        let body = only.body.as_ref().unwrap();
        x509_ocsp::OcspRequest::from_der(body)
            .expect("emitted POST body must parse as OCSPRequest");
    }

    #[tokio::test]
    async fn hash_alg_override_takes_effect() {
        // Same regression guard as the sync side: with_hash_alg(Sha1)
        // must produce a different POST body than the SHA-256 default.
        let f = fetcher_with(RESP_GOOD);
        let h = AsyncHttpOcspFetcher::new(f, DefaultVerifier, NOW).with_hash_alg(OcspHashAlg::Sha1);
        let _ = h.check_revocation(&cert(LEAF_GOOD), &cert(CA)).await;

        let calls = h.fetcher.seen.lock().unwrap().clone();
        assert_eq!(calls.len(), 1);
        let body_sha1 = calls[0].body.as_ref().unwrap().clone();

        let f2 = fetcher_with(RESP_GOOD);
        let h2 = AsyncHttpOcspFetcher::new(f2, DefaultVerifier, NOW);
        let _ = h2.check_revocation(&cert(LEAF_GOOD), &cert(CA)).await;
        let body_sha256 = h2.fetcher.seen.lock().unwrap()[0]
            .body
            .as_ref()
            .unwrap()
            .clone();

        assert_ne!(
            body_sha1, body_sha256,
            "with_hash_alg(Sha1) must produce a different POST body than the default (Sha256)"
        );
    }
}
