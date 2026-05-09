//! [`pkix_revocation::RevocationChecker`] impl for [`HttpCrlFetcher`].
//!
//! On `check_revocation` the fetcher walks every HTTP/HTTPS URL extracted
//! from the certificate's `cRLDistributionPoints` extension, fetches each
//! URL via the user-supplied [`RevocationFetcher`], and delegates the
//! parsed CRL to [`pkix_revocation::CrlChecker`] with the user-supplied
//! [`pkix_path::SignatureVerifier`].
//!
//! Per the parent bead (PKIX-a1yc.5):
//!
//! - First successful fetch + parse path is taken; the result of
//!   [`pkix_revocation::CrlChecker::check_revocation`] is returned
//!   immediately. Subsequent URLs are NOT fetched even if the first
//!   yielded a non-revocation outcome (e.g., `CrlExpired`).
//! - Fetch failure (transport, HTTP status, oversize body) and CRL parse
//!   failure both fall through to the next URL.
//! - When ALL URLs fail, the impl surfaces
//!   [`pkix_revocation::Error::RevocationFetchFailed`] with a per-URL
//!   description suitable for logging.
//! - When the certificate has no `cRLDistributionPoints` extension at
//!   all (or the extension contains only non-HTTP URLs), the impl
//!   returns `Ok(())`. Hard-fail callers wanting "no CRL = fail" must
//!   wrap this checker; v0.x explicitly defers stricter policy to
//!   composition.
//!
//! The `check_revocation_against_anchor` method is intentionally left at
//! the trait default (`Ok(())`) — same shape as
//! [`pkix_revocation::CrlChecker`] itself, which does not override it
//! either. Full anchor-aware coverage requires a `TrustAnchor`-shaped
//! API on `CrlChecker` and is tracked as future work.

use crate::{extract_cdp_http_urls, FetchRequest, HttpCrlFetcher, RevocationFetcher};
use pkix_path::SignatureVerifier;
use pkix_revocation::{CrlChecker, Error as RevError, RevocationChecker};
use x509_cert::Certificate;

impl<F, V> RevocationChecker for HttpCrlFetcher<F, V>
where
    F: RevocationFetcher,
    V: SignatureVerifier + Clone,
{
    fn check_revocation(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
    ) -> pkix_revocation::Result<()> {
        // Step 1 — Extract HTTP/HTTPS CDP URLs from the cert.
        //
        // A malformed cRLDistributionPoints extension is surfaced as a
        // RevocationFetchFailed: the cert claims to advertise a CRL
        // location but the helper cannot resolve it. Stricter callers
        // wishing to treat this as a per-cert error can pre-validate
        // certs separately; for v0.x we lump cert-level malformation
        // into the same "no usable revocation source" bucket as
        // network failure.
        let urls = extract_cdp_http_urls(cert).map_err(|e| {
            RevError::RevocationFetchFailed {
                description: format!(
                    "cRLDistributionPoints extension parse failed: {e}"
                ),
            }
        })?;

        // Step 2 — No URLs ⇒ nothing for this checker to do.
        //
        // RFC 5280 §6.3 makes CRL fetching the verifier's responsibility
        // when CDPs are present. When CDPs are absent, the cert simply
        // does not advertise CRL-based revocation. Returning Ok(()) here
        // is the only reasonable behaviour for a CRL-only checker.
        if urls.is_empty() {
            return Ok(());
        }

        // Step 3 — Try each URL in document order. Record per-URL
        // failures for the RevocationFetchFailed payload if every URL
        // fails to yield a constructible CrlChecker.
        let mut failures: Vec<String> = Vec::with_capacity(urls.len());
        for url in &urls {
            let req = FetchRequest::get(url);
            match self.fetcher.fetch(&req) {
                Ok(resp) => {
                    // We have bytes. Try to construct a CrlChecker and
                    // run check_revocation. If construction fails (parse
                    // error etc.), continue to the next URL per the
                    // bead's failure semantics. If construction
                    // succeeds, the checker's verdict is
                    // returned IMMEDIATELY — see module docs for why we
                    // do not retry on e.g. CrlExpired.
                    match CrlChecker::new(
                        &resp.bytes,
                        self.now_unix,
                        self.verifier.clone(),
                    ) {
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

        // Step 4 — Every URL failed. Surface a structured description.
        Err(RevError::RevocationFetchFailed {
            description: format!(
                "all {} URL(s) failed: {}",
                urls.len(),
                failures.join("; ")
            ),
        })
    }

    // check_revocation_against_anchor: keep the trait default (Ok(())).
    // Documented in the module-level docstring above.
}

#[cfg(test)]
mod tests {
    //! Unit tests exercising HttpCrlFetcher::check_revocation.
    //!
    //! Independent oracle: pyca/cryptography (via gen_http_crl_fixtures.py)
    //! produces the CA, leaves, and CRL bytes; the test harness mocks the
    //! HTTP transport with a closure-based RevocationFetcher impl. The
    //! tests assert revocation verdicts (Ok, Err::Revoked, fetch failure,
    //! URL fallback) without touching the network.
    use super::*;
    use crate::{FetchError, FetchResponse};
    use der::Decode;
    use pkix_path::DefaultVerifier;
    use std::cell::RefCell;

    const CA: &[u8] = include_bytes!("../tests/fixtures/http-ca.der");
    const LEAF_GOOD: &[u8] = include_bytes!("../tests/fixtures/http-leaf-good.der");
    const LEAF_REVOKED: &[u8] =
        include_bytes!("../tests/fixtures/http-leaf-revoked.der");
    const LEAF_NO_CDP: &[u8] =
        include_bytes!("../tests/fixtures/http-leaf-no-cdp.der");
    const CRL_REVOKES_2: &[u8] =
        include_bytes!("../tests/fixtures/http-crl-revokes-2.der");
    const CRL_EMPTY: &[u8] = include_bytes!("../tests/fixtures/http-crl-empty.der");

    /// Validation timestamp: 2026-06-01 00:00:00 UTC. Matches the CRL's
    /// thisUpdate / nextUpdate window from the gen script.
    const NOW: u64 = 1_780_272_000;

    /// Mock fetcher backed by a fixed URL → bytes map. Records each
    /// requested URL so tests can assert call counts without eyeballing
    /// the order of pkix-revocation-http's URL iteration.
    struct StaticMap {
        map: Vec<(&'static str, Vec<u8>)>,
        seen: RefCell<Vec<String>>,
    }

    impl RevocationFetcher for StaticMap {
        fn fetch(
            &self,
            req: &FetchRequest<'_>,
        ) -> Result<FetchResponse, FetchError> {
            self.seen.borrow_mut().push(req.url.to_owned());
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
    impl RevocationFetcher for AlwaysFail {
        fn fetch(
            &self,
            _req: &FetchRequest<'_>,
        ) -> Result<FetchResponse, FetchError> {
            Err(FetchError::HttpStatus(503))
        }
    }

    fn cert(b: &[u8]) -> Certificate {
        Certificate::from_der(b).unwrap()
    }

    fn fetcher_with_crl(crl: &[u8]) -> StaticMap {
        StaticMap {
            map: vec![("http://crl.example.com/test.crl", crl.to_vec())],
            seen: RefCell::new(Vec::new()),
        }
    }

    #[test]
    fn good_cert_against_empty_crl_returns_ok() {
        // Oracle: serial=1 is not present in the empty CRL.
        let f = fetcher_with_crl(CRL_EMPTY);
        let h = HttpCrlFetcher::new(f, DefaultVerifier, NOW);
        h.check_revocation(&cert(LEAF_GOOD), &cert(CA)).unwrap();
    }

    #[test]
    fn good_cert_against_crl_revoking_other_serial_returns_ok() {
        // Oracle: serial=1 is not in the CRL (which lists serial=2).
        let f = fetcher_with_crl(CRL_REVOKES_2);
        let h = HttpCrlFetcher::new(f, DefaultVerifier, NOW);
        h.check_revocation(&cert(LEAF_GOOD), &cert(CA)).unwrap();
    }

    #[test]
    fn revoked_cert_returns_revoked_error() {
        // Oracle: serial=2 IS in the CRL, so check_revocation must say so.
        let f = fetcher_with_crl(CRL_REVOKES_2);
        let h = HttpCrlFetcher::new(f, DefaultVerifier, NOW);
        let err = h
            .check_revocation(&cert(LEAF_REVOKED), &cert(CA))
            .unwrap_err();
        assert!(
            matches!(err, RevError::Revoked { .. }),
            "expected Revoked, got {err:?}"
        );
    }

    #[test]
    fn cert_without_cdp_extension_returns_ok() {
        // Oracle: leaf-no-cdp.der has no cRLDistributionPoints extension.
        // Documented behaviour is "no CDPs ⇒ no check possible ⇒ Ok(())".
        let f = AlwaysFail; // fetcher should never be called
        let h = HttpCrlFetcher::new(f, DefaultVerifier, NOW);
        h.check_revocation(&cert(LEAF_NO_CDP), &cert(CA)).unwrap();
    }

    #[test]
    fn all_fetches_failing_returns_revocation_fetch_failed() {
        let h = HttpCrlFetcher::new(AlwaysFail, DefaultVerifier, NOW);
        let err = h
            .check_revocation(&cert(LEAF_GOOD), &cert(CA))
            .unwrap_err();
        match err {
            RevError::RevocationFetchFailed { description } => {
                // Per-URL summary must mention the URL and the HTTP status.
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

    #[test]
    fn malformed_crl_response_is_treated_as_fetch_failure_per_url() {
        // First and only URL returns garbage bytes. CrlChecker::new
        // fails to parse them → impl falls into the all-URLs-failed bucket
        // and surfaces RevocationFetchFailed.
        let f = StaticMap {
            map: vec![("http://crl.example.com/test.crl", vec![0xff, 0xff, 0xff])],
            seen: RefCell::new(Vec::new()),
        };
        let h = HttpCrlFetcher::new(f, DefaultVerifier, NOW);
        let err = h
            .check_revocation(&cert(LEAF_GOOD), &cert(CA))
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

    #[test]
    fn fetcher_actually_called_with_advertised_url() {
        // Pin down the URL HttpCrlFetcher requests. If the CDP extractor
        // ever drifts (e.g., trims/normalises the URL), this test catches it.
        let f = fetcher_with_crl(CRL_EMPTY);
        let h = HttpCrlFetcher::new(f, DefaultVerifier, NOW);
        h.check_revocation(&cert(LEAF_GOOD), &cert(CA)).unwrap();
        let seen = h.fetcher.seen.borrow().clone();
        assert_eq!(seen, vec!["http://crl.example.com/test.crl".to_string()]);
    }
}
