//! A verifier that is not `Clone` must still be usable.
//!
//! `CrlChecker::new` / `OcspChecker::new` take the verifier by value and
//! the HTTP wrappers require `V: SignatureVerifier + Clone`, because they
//! hold it and clone it once per candidate URL. That bound used to
//! exclude a whole class of verifier outright: one owning a hardware
//! token handle, an open PKCS#11 session, or anything else that cannot
//! be duplicated.
//!
//! `pkix-path` now forwards `SignatureVerifier` through `&T` and (under
//! `std`) `Arc<T>`, so such a verifier is used by reference or by shared
//! handle instead of being cloned. These tests are mostly a compile-time
//! assertion: `NotClone` deliberately does not implement `Clone`, so if
//! either forwarding impl were removed this file would stop building.
//!
//! Run: cargo test -p pkix-revocation-http --features crl,ocsp --test non_clone_verifier

#![cfg(all(feature = "crl", feature = "ocsp"))]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use der::Decode as _;
use pkix_path::{
    AlgorithmIdentifierRef, SignatureVerifier, SubjectPublicKeyInfoRef, VerificationError,
    VerificationErrorKind,
};
use pkix_revocation::RevocationChecker;
use pkix_revocation_http::{
    FetchError, FetchRequest, FetchResponse, HttpCrlFetcher, HttpOcspFetcher, RevocationFetcher,
};
use x509_cert::Certificate;

const NOW: u64 = 1_780_272_000;

/// Stands in for a verifier holding something undupliable — a token
/// handle, a session. It counts calls so the forwarding can be observed
/// to reach the real implementation rather than some default.
///
/// Deliberately NOT `Clone`. That is the point of the file.
struct NotClone {
    calls: AtomicUsize,
}

impl SignatureVerifier for NotClone {
    fn verify_signature(
        &self,
        _algorithm: AlgorithmIdentifierRef<'_>,
        _issuer_spki: SubjectPublicKeyInfoRef<'_>,
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<(), VerificationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        // Refuse everything: this test is about the type system reaching
        // the verifier at all, not about cryptography.
        Err(VerificationError::new(
            VerificationErrorKind::InvalidSignature,
        ))
    }
}

struct Serves(Vec<u8>);

impl RevocationFetcher for Serves {
    fn fetch(&self, _req: &FetchRequest<'_>) -> Result<FetchResponse, FetchError> {
        Ok(FetchResponse {
            bytes: self.0.clone(),
            content_type: None,
        })
    }
}

fn fx(name: &str) -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/review/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn cert(name: &str) -> Certificate {
    Certificate::from_der(&fx(name)).expect("fixture parses")
}

/// By shared reference: `&NotClone` is `Copy`, so the wrapper's `Clone`
/// bound is satisfied with nothing duplicated.
#[test]
fn a_non_clone_verifier_works_by_reference() {
    let verifier = NotClone {
        calls: AtomicUsize::new(0),
    };
    let h = HttpCrlFetcher::new(Serves(fx("base-crl.der")), &verifier, NOW);

    // The verifier refuses, so the check cannot succeed. What matters is
    // that it compiled and that the verifier was actually consulted.
    let _ = h.check_revocation(&cert("leaf-serial2.der"), &cert("ca.der"));
    assert!(
        verifier.calls.load(Ordering::SeqCst) > 0,
        "the forwarding impl must reach the real verifier, not a default"
    );
}

/// By `Arc`: for a fetcher that outlives any borrow. Cloning the `Arc`
/// per URL is a refcount bump, not a duplication of the verifier.
#[test]
fn a_non_clone_verifier_works_behind_an_arc() {
    let verifier = Arc::new(NotClone {
        calls: AtomicUsize::new(0),
    });
    let h = HttpCrlFetcher::new(Serves(fx("base-crl.der")), Arc::clone(&verifier), NOW);
    let _ = h.check_revocation(&cert("leaf-serial2.der"), &cert("ca.der"));
    assert!(verifier.calls.load(Ordering::SeqCst) > 0);

    // And it survives being moved somewhere with no borrow to hold.
    let owned: Box<dyn Fn() -> bool> = {
        let v = Arc::clone(&verifier);
        let f = HttpCrlFetcher::new(Serves(fx("base-crl.der")), Arc::clone(&verifier), NOW);
        Box::new(move || {
            let _ = f.check_revocation(&cert("leaf-serial2.der"), &cert("ca.der"));
            v.calls.load(Ordering::SeqCst) > 0
        })
    };
    assert!(owned(), "an Arc-held verifier must work past the borrow");
}

/// The OCSP wrapper carries the same bound and must accept both shapes
/// too; it is a separate generic instantiation.
#[test]
fn the_ocsp_wrapper_accepts_both_shapes() {
    let verifier = NotClone {
        calls: AtomicUsize::new(0),
    };
    let by_ref = HttpOcspFetcher::new(Serves(fx("ocsp-serial2-revoked.der")), &verifier, NOW);
    let _ = by_ref.check_revocation(&cert("leaf-serial2.der"), &cert("ca.der"));

    let shared = Arc::new(NotClone {
        calls: AtomicUsize::new(0),
    });
    let by_arc = HttpOcspFetcher::new(
        Serves(fx("ocsp-serial2-revoked.der")),
        Arc::clone(&shared),
        NOW,
    );
    let _ = by_arc.check_revocation(&cert("leaf-serial2.der"), &cert("ca.der"));

    assert!(
        verifier.calls.load(Ordering::SeqCst) > 0 || shared.calls.load(Ordering::SeqCst) > 0,
        "at least one OCSP path must have consulted its verifier"
    );
}
