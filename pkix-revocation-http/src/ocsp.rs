//! [`pkix_revocation::RevocationChecker`] impl for [`HttpOcspFetcher`].
//!
//! On `check_revocation` the fetcher walks every HTTP/HTTPS OCSP responder
//! URL extracted from the certificate's `authorityInfoAccess` extension,
//! POSTs an RFC 6960 §A.1 OCSP request body to each, hands the response
//! bytes to [`pkix_revocation::OcspChecker`], and delegates the revocation
//! verdict.
//!
//! Per the parent bead (PKIX-a1yc.6):
//!
//! - The OCSP request body is built once via [`crate::build_ocsp_request`]
//!   using the configured [`OcspHashAlg`] and reused across URL attempts.
//!   POST `Content-Type` is the constant `application/ocsp-request`.
//! - First successful POST + parse path is determinative; the
//!   [`OcspChecker::check_revocation`] verdict is returned immediately.
//!   Subsequent URLs are NOT attempted.
//! - Fetch failure (transport / HTTP status / oversize body) and OCSP
//!   response parse failure both fall through to the next URL.
//! - All URLs failing surfaces as
//!   [`pkix_revocation::Error::RevocationFetchFailed`].
//! - Cert with no AIA OCSP URL ⇒ `Ok(())` (documented).
//!
//! `check_revocation_against_anchor` is left at the trait default (`Ok(())`)
//! for the same reason as in [`crate::HttpCrlFetcher`]: pkix-revocation's
//! OcspChecker does not currently expose a TrustAnchor-shaped entry point
//! and adding one is tracked as future work.

use crate::{
    build_ocsp_request, extract_aia_http_urls, FetchRequest, HttpOcspFetcher, RevocationFetcher,
};
use pkix_path::SignatureVerifier;
use pkix_revocation::{Error as RevError, OcspChecker, RevocationChecker};
use x509_cert::Certificate;

/// `Content-Type` for an OCSP request body, per RFC 6960 §A.1.
const OCSP_REQUEST_CT: &str = "application/ocsp-request";

impl<F, V> RevocationChecker for HttpOcspFetcher<F, V>
where
    F: RevocationFetcher,
    V: SignatureVerifier + Clone,
{
    fn check_revocation(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
    ) -> pkix_revocation::Result<()> {
        // Step 1 — Build the OCSP request body. We only need to do this
        // once per check_revocation call; the body is the same for every
        // candidate responder URL. A failure here means the cert /
        // issuer pair could not be turned into a CertID — almost always
        // a structurally broken input, surfaced through
        // RevocationFetchFailed for caller convenience (the alternative
        // is mapping the BuildError to a different pkix_revocation::Error
        // variant, which would either lie about what happened or
        // require yet another variant addition).
        let req_bytes = build_ocsp_request(cert, issuer, self.hash_alg).map_err(|e| {
            RevError::RevocationFetchFailed {
                description: format!("OCSP request build failed: {e}"),
            }
        })?;

        // Step 2 — Extract HTTP/HTTPS OCSP responder URLs from the cert.
        let aia = extract_aia_http_urls(cert).map_err(|e| RevError::RevocationFetchFailed {
            description: format!("authorityInfoAccess extension parse failed: {e}"),
        })?;

        // Step 3 — No OCSP URLs ⇒ nothing for this checker to do.
        // Same rationale as HttpCrlFetcher: a cert without OCSP AIA
        // entries does not advertise OCSP-based revocation. Returning
        // Ok(()) is the only reasonable behaviour for an OCSP-only
        // checker; stricter "OCSP must be present" policies are caller
        // composition.
        if aia.ocsp.is_empty() {
            return Ok(());
        }

        // Step 4 — POST to each URL in document order.
        let mut failures: Vec<String> = Vec::with_capacity(aia.ocsp.len());
        for url in &aia.ocsp {
            let req = FetchRequest::post(url, &req_bytes.body, OCSP_REQUEST_CT);
            match self.fetcher.fetch(&req) {
                Ok(resp) => {
                    // We have response bytes. Try to construct an
                    // OcspChecker; on parse failure, fall through to
                    // the next URL. On construction success the
                    // checker's verdict is returned immediately.
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

        // Step 5 — Every URL failed.
        Err(RevError::RevocationFetchFailed {
            description: format!(
                "all {} URL(s) failed: {}",
                aia.ocsp.len(),
                failures.join("; ")
            ),
        })
    }

    // check_revocation_against_anchor: trait default (Ok(())). See module
    // docs for rationale; full coverage is future work.
}

#[cfg(test)]
mod tests {
    //! Unit tests for HttpOcspFetcher::check_revocation.
    //!
    //! Independent oracle: pyca/cryptography (gen_http_crl_fixtures.py)
    //! produces CA + leaves + matched OCSP responses. The HTTP transport
    //! is mocked with a closure-style RevocationFetcher; tests assert
    //! verdicts and that POST requests carry the expected body and
    //! Content-Type.
    use super::*;
    use crate::{FetchError, FetchMethod, FetchResponse, OcspHashAlg};
    use der::Decode;
    use pkix_path::DefaultVerifier;
    use std::cell::RefCell;

    const CA: &[u8] = include_bytes!("../tests/fixtures/http-ca.der");
    const LEAF_GOOD: &[u8] = include_bytes!("../tests/fixtures/http-leaf-good.der");
    const LEAF_REVOKED: &[u8] = include_bytes!("../tests/fixtures/http-leaf-revoked.der");
    const LEAF_NO_AIA: &[u8] = include_bytes!("../tests/fixtures/http-leaf-no-cdp.der");
    const RESP_GOOD: &[u8] = include_bytes!("../tests/fixtures/http-ocsp-good.der");
    const RESP_REVOKED: &[u8] = include_bytes!("../tests/fixtures/http-ocsp-revoked.der");

    /// Validation timestamp: 2026-06-01 00:00:00 UTC. Inside the
    /// thisUpdate / nextUpdate window of the gen-script-produced
    /// responses (2026-06-01 .. 2026-07-01).
    const NOW: u64 = 1_780_272_000;

    /// Mock fetcher backed by a fixed URL → bytes map for OCSP. Records
    /// each call so tests can assert that requests are POSTs with the
    /// correct body and Content-Type.
    struct StaticOcspMap {
        map: Vec<(&'static str, Vec<u8>)>,
        seen: RefCell<Vec<RecordedCall>>,
    }

    #[derive(Debug, Clone)]
    struct RecordedCall {
        url: String,
        body: Option<Vec<u8>>,
        content_type: Option<String>,
    }

    impl RevocationFetcher for StaticOcspMap {
        fn fetch(&self, req: &FetchRequest<'_>) -> Result<FetchResponse, FetchError> {
            let (body, content_type) = match req.method {
                FetchMethod::Get => (None, None),
                FetchMethod::Post { body, content_type } => {
                    (Some(body.to_vec()), Some(content_type.to_string()))
                }
            };
            self.seen.borrow_mut().push(RecordedCall {
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

    /// Mock fetcher that always returns a fixed error.
    struct AlwaysFail;
    impl RevocationFetcher for AlwaysFail {
        fn fetch(&self, _req: &FetchRequest<'_>) -> Result<FetchResponse, FetchError> {
            Err(FetchError::HttpStatus(503))
        }
    }

    fn cert(b: &[u8]) -> Certificate {
        Certificate::from_der(b).unwrap()
    }

    fn fetcher_with(resp: &[u8]) -> StaticOcspMap {
        StaticOcspMap {
            map: vec![("http://ocsp.example.com/", resp.to_vec())],
            seen: RefCell::new(Vec::new()),
        }
    }

    #[test]
    fn good_cert_with_good_ocsp_returns_ok() {
        let f = fetcher_with(RESP_GOOD);
        let h = HttpOcspFetcher::new(f, DefaultVerifier, NOW);
        h.check_revocation(&cert(LEAF_GOOD), &cert(CA)).unwrap();
    }

    #[test]
    fn revoked_cert_with_revoked_ocsp_returns_revoked() {
        let f = fetcher_with(RESP_REVOKED);
        let h = HttpOcspFetcher::new(f, DefaultVerifier, NOW);
        let err = h
            .check_revocation(&cert(LEAF_REVOKED), &cert(CA))
            .unwrap_err();
        assert!(
            matches!(err, RevError::Revoked { .. }),
            "expected Revoked, got {err:?}"
        );
    }

    #[test]
    fn cert_without_aia_extension_returns_ok() {
        let f = AlwaysFail; // fetcher should never be called
        let h = HttpOcspFetcher::new(f, DefaultVerifier, NOW);
        h.check_revocation(&cert(LEAF_NO_AIA), &cert(CA)).unwrap();
    }

    #[test]
    fn all_fetches_failing_returns_revocation_fetch_failed() {
        let h = HttpOcspFetcher::new(AlwaysFail, DefaultVerifier, NOW);
        let err = h.check_revocation(&cert(LEAF_GOOD), &cert(CA)).unwrap_err();
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

    #[test]
    fn malformed_ocsp_response_is_treated_as_fetch_failure() {
        let f = StaticOcspMap {
            map: vec![("http://ocsp.example.com/", vec![0xff, 0xff, 0xff])],
            seen: RefCell::new(Vec::new()),
        };
        let h = HttpOcspFetcher::new(f, DefaultVerifier, NOW);
        let err = h.check_revocation(&cert(LEAF_GOOD), &cert(CA)).unwrap_err();
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

    #[test]
    fn fetcher_called_with_post_body_and_content_type() {
        // Pin down the request shape: POST to the AIA URL with body =
        // the DER-encoded OCSP request and Content-Type =
        // application/ocsp-request. This regression-guards against
        // accidental GET use or wrong header.
        let f = fetcher_with(RESP_GOOD);
        let h = HttpOcspFetcher::new(f, DefaultVerifier, NOW);
        h.check_revocation(&cert(LEAF_GOOD), &cert(CA)).unwrap();

        let calls = h.fetcher.seen.borrow().clone();
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
        // Sanity: emitted body must round-trip through x509-ocsp's parser.
        let body = only.body.as_ref().unwrap();
        x509_ocsp::OcspRequest::from_der(body)
            .expect("emitted POST body must parse as OCSPRequest");
    }

    #[test]
    fn hash_alg_override_takes_effect() {
        // Switching to SHA-1 must change the bytes of the POSTed OCSP
        // request body (different CertID.hashAlgorithm OID). This is a
        // regression guard against silent ignoring of with_hash_alg.
        let f = fetcher_with(RESP_GOOD);
        let h = HttpOcspFetcher::new(f, DefaultVerifier, NOW).with_hash_alg(OcspHashAlg::Sha1);
        // Cert is good, response is good, but we won't make it that far —
        // the response was generated with SHA-256 so the CertID will not
        // match. We just want to inspect what we POSTed.
        let _ = h.check_revocation(&cert(LEAF_GOOD), &cert(CA));

        let calls = h.fetcher.seen.borrow().clone();
        assert_eq!(calls.len(), 1);
        let body_sha1 = calls[0].body.as_ref().unwrap().clone();

        // Now run again with SHA-256 (the default).
        let f2 = fetcher_with(RESP_GOOD);
        let h2 = HttpOcspFetcher::new(f2, DefaultVerifier, NOW);
        let _ = h2.check_revocation(&cert(LEAF_GOOD), &cert(CA));
        let body_sha256 = h2.fetcher.seen.borrow()[0].body.as_ref().unwrap().clone();

        assert_ne!(
            body_sha1, body_sha256,
            "with_hash_alg(Sha1) must produce a different POST body than the default (Sha256)"
        );
    }
}
