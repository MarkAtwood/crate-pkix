//! The forwarding `SignatureVerifier` impls for `&T` and `Arc<T>`.
//!
//! Both are four-line delegations, and both could return `Ok(())` instead
//! -- which is a verifier that accepts every signature, reached by nothing
//! more unusual than holding the real verifier behind a reference or an
//! `Arc`. `Arc<V>` is the shape a long-lived consumer uses, because it is
//! `Clone` whatever `V` is; `&T` is what every caller that passes a
//! borrowed verifier gets.
//!
//! Nothing exercised either impl. Every test in the suite passes
//! `&DefaultVerifier` to `validate_path`, which takes `&V` and so makes
//! `V = DefaultVerifier` rather than `&DefaultVerifier`: the forwarding
//! impl is only selected when the verifier is *itself* a reference or an
//! `Arc`.
//!
//! The chain is the PKITS §4.1.1 valid path, because this is a test about
//! the verifier and not about the chain.

mod pkits_helper;

use pkits_helper::{pkits_cert, pkits_trust_anchor, PKITS_NOW};

use pkix_path::{
    validate_path, AlgorithmIdentifierRef, DefaultVerifier, SignatureVerifier,
    SubjectPublicKeyInfoRef, ValidationPolicy, VerificationError,
};
use x509_cert::Certificate;

/// Refuses every signature, and counts how many times it was asked.
///
/// The count is what distinguishes "the forwarding impl refused" from "the
/// forwarding impl never called anything": a delegation replaced by
/// `Err(..)` would also refuse, and would be just as wrong.
///
/// The counter is atomic rather than a `Cell` so the type is `Sync`: an
/// `Arc` around something that is not `Send + Sync` is pointless, and
/// clippy says so.
struct RefusesEverything(std::sync::atomic::AtomicUsize);

impl RefusesEverything {
    fn new() -> Self {
        Self(std::sync::atomic::AtomicUsize::new(0))
    }

    fn calls(&self) -> usize {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl SignatureVerifier for RefusesEverything {
    fn verify_signature(
        &self,
        _algorithm: AlgorithmIdentifierRef<'_>,
        _issuer_spki: SubjectPublicKeyInfoRef<'_>,
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<(), VerificationError> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Err(VerificationError::invalid_signature())
    }
}

fn chain() -> Vec<Certificate> {
    vec![
        pkits_cert("ValidCertificatePathTest1EE"),
        pkits_cert("GoodCACert"),
    ]
}

fn validate_with<V: SignatureVerifier>(verifier: &V) -> pkix_path::Result<()> {
    let anchors = [pkits_trust_anchor()];
    validate_path(
        &chain(),
        &anchors,
        &ValidationPolicy::new(PKITS_NOW),
        verifier,
    )
    .map(|_| ())
}

/// A real verifier behind a reference still verifies.
#[test]
fn a_reference_forwards_to_the_verifier() {
    let inner = DefaultVerifier;
    let by_ref: &DefaultVerifier = &inner;
    validate_with(&by_ref).expect("the §4.1.1 path validates");
}

/// A real verifier behind an `Arc` still verifies.
#[test]
fn an_arc_forwards_to_the_verifier() {
    let shared = std::sync::Arc::new(DefaultVerifier);
    validate_with(&shared).expect("the §4.1.1 path validates");
}

/// A refusing verifier behind a reference still refuses, and was asked.
#[test]
fn a_reference_does_not_answer_for_the_verifier() {
    let inner = RefusesEverything::new();
    let by_ref: &RefusesEverything = &inner;
    assert!(
        validate_with(&by_ref).is_err(),
        "the forwarding impl must not vouch for a signature itself"
    );
    assert!(
        inner.calls() > 0,
        "and it must have asked: a delegation replaced by an error would \
         refuse without ever consulting the verifier"
    );
}

/// A refusing verifier behind an `Arc` still refuses, and was asked.
#[test]
fn an_arc_does_not_answer_for_the_verifier() {
    let shared = std::sync::Arc::new(RefusesEverything::new());
    assert!(
        validate_with(&shared).is_err(),
        "the forwarding impl must not vouch for a signature itself"
    );
    assert!(shared.calls() > 0, "and it must have asked");
}
