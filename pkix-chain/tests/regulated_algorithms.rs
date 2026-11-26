//! A verifier that refuses an algorithm must stay legible at this boundary.
//!
//! The project stance is that every RustCrypto backend is available by
//! default, and that a constrained environment — FIPS mode, or any other
//! regulator that forbids an algorithm — turns backends *off* rather than
//! on. That only works if the resulting error says what happened.
//!
//! The distinction that matters is between two things a signature check
//! can report:
//!
//! - `SignatureInvalid` — "I checked it and it did not verify." In a PKI
//!   that reads as a forged or corrupted certificate, and someone will go
//!   looking for an attacker.
//! - `SignatureNotVerified { reason: UnsupportedAlgorithm }` — "I could
//!   not check it, because this build does not do that algorithm." That is
//!   a configuration fact.
//!
//! Conflating them in a regulated deployment sends an operator hunting a
//! non-existent attack. `pkix_path::Error::SignatureNotVerified`'s own
//! rustdoc promises `reason` "is never
//! `VerificationErrorKind::InvalidSignature`", and these tests hold the
//! whole stack to that promise rather than just the crate that makes it.
//!
//! Modelled with a verifier that refuses, rather than by disabling cargo
//! features: the concern is error propagation, not whether RustCrypto
//! honours its own feature gates, and a `#[cfg(not(feature = ...))]` test
//! would be skipped in the `--all-features` run CI uses.
//!
//! Run: cargo test -p pkix-chain --test regulated_algorithms

use pkix_chain::{
    verify_chain, Error, NoAiaFetcher, NoRevocation, PathBuildError, PathError, SignatureVerifier,
    TrustAnchor, ValidationPolicy, VerificationError, VerificationErrorKind,
};
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

const NOW: u64 = 1_780_272_000;

fn load_fixture(name: &str) -> Certificate {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let der = std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
    Certificate::from_der(&der).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

/// Stands in for a build without a given backend, or a regulator that
/// forbids it. Reports what such a verifier reports: not that the
/// signature is wrong, but that it cannot be checked here.
struct Refuses(fn() -> VerificationError);

impl SignatureVerifier for Refuses {
    fn verify_signature(
        &self,
        _: spki::AlgorithmIdentifierRef<'_>,
        _: spki::SubjectPublicKeyInfoRef<'_>,
        _: &[u8],
        _: &[u8],
    ) -> Result<(), VerificationError> {
        Err((self.0)())
    }
}

/// Pulls the underlying validation failure out of whichever wrapper it
/// arrives in.
///
/// It arrives as `PathBuild(NoValidPath { last_error, .. })` rather than
/// `Path(..)`, because `verify_chain` treats an unverifiable signature as
/// AIA-recoverable and tries chain reassembly before giving up. That is
/// right rather than wasteful: in a cross-signed topology an alternative
/// issuer may sign with an algorithm this build *does* support, so
/// fetching can genuinely rescue the case.
///
/// Which matters for a reason worth stating. `NoValidPath.last_error` held
/// a `Display`-rendered `String` until it was typed earlier; a regulated
/// deployment would have received prose to grep rather than a variant to
/// match. The guarantee these tests check depends on that field carrying a
/// `pkix_path::Error`.
fn underlying(err: Error) -> PathError {
    match err {
        Error::Path(e) => e,
        Error::PathBuild(PathBuildError::NoValidPath { last_error, .. }) => last_error,
        other => panic!("expected a validation failure, got {other:?}"),
    }
}

fn verify_with(v: &Refuses) -> Error {
    let leaf = load_fixture("host-exact-foo.der");
    let anchors = [TrustAnchor::from_cert(load_fixture("root.der"))];
    let policy = ValidationPolicy::new(NOW);
    verify_chain(
        std::slice::from_ref(&leaf),
        &anchors,
        &policy,
        v,
        &NoRevocation,
        &NoAiaFetcher,
    )
    .expect_err("the verifier refused, so validation cannot succeed")
}

/// An algorithm this build does not implement surfaces as
/// `SignatureNotVerified { reason: UnsupportedAlgorithm }`, all the way out
/// through `pkix_chain::Error`.
#[test]
fn an_unsupported_algorithm_is_reported_as_unsupported_not_invalid() {
    match underlying(verify_with(&Refuses(
        VerificationError::unsupported_algorithm,
    ))) {
        PathError::SignatureNotVerified { reason, .. } => {
            assert_eq!(reason, VerificationErrorKind::UnsupportedAlgorithm);
        }
        other => panic!("expected SignatureNotVerified {{ .. }}, got {other:?}"),
    }
}

/// A curve this build does not implement surfaces as `UnsupportedKey`,
/// which is the ECDSA case: the signature algorithm is known, the named
/// curve in the issuer's SPKI is not compiled in.
#[test]
fn an_unsupported_curve_is_reported_as_unsupported_key() {
    match underlying(verify_with(&Refuses(VerificationError::unsupported_key))) {
        PathError::SignatureNotVerified { reason, .. } => {
            assert_eq!(reason, VerificationErrorKind::UnsupportedKey);
        }
        other => panic!("expected SignatureNotVerified {{ .. }}, got {other:?}"),
    }
}

/// A malformed key is a third, distinct answer — the certificate really is
/// defective, as opposed to this build being unable to read it.
#[test]
fn a_malformed_key_is_reported_distinctly_from_an_unsupported_one() {
    match underlying(verify_with(&Refuses(VerificationError::malformed_key))) {
        PathError::SignatureNotVerified { reason, .. } => {
            assert_eq!(reason, VerificationErrorKind::MalformedKey);
        }
        other => panic!("expected SignatureNotVerified {{ .. }}, got {other:?}"),
    }
}

/// And a genuinely bad signature does NOT come back as
/// `SignatureNotVerified`.
///
/// This is the half that gives the other three their meaning. If every
/// verifier failure collapsed to one variant, matching on `reason` would
/// tell an operator nothing. `pkix_path::Error` keeps the cases apart:
/// "checked and wrong" is `SignatureInvalid`, which carries no `reason`
/// because there is nothing to explain.
#[test]
fn an_invalid_signature_is_not_reported_as_unverifiable() {
    let err = underlying(verify_with(&Refuses(VerificationError::invalid_signature)));
    assert!(
        matches!(err, PathError::SignatureInvalid { .. }),
        "a refused-as-invalid signature must not surface as SignatureNotVerified; got {err:?}"
    );
}
