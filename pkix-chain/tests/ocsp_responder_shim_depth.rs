//! `verify_ocsp_responder`'s revocation shim on a chain deeper than one.
//!
//! RFC 6960 §4.2.2.2.1 lets a delegated responder certificate carry
//! `id-pkix-ocsp-nocheck` so that checking its own revocation status does
//! not require another OCSP round trip. `verify_ocsp_responder` honours
//! that by wrapping the caller's `RevocationChecker` in a shim that
//! short-circuits the check for `chain[0]` and delegates everything else.
//!
//! `verify_ocsp_responder.rs` covers the bypass, but every chain there holds
//! a single certificate, which reaches only the shim's
//! `check_revocation_against_anchor`. Its `check_revocation` -- the method
//! every certificate below the top of the chain goes through -- was never
//! called, so three separate ways for the shim to stop consulting the
//! caller were invisible:
//!
//!   * `check_revocation` returning `Ok(())` without delegating, which
//!     reports every certificate below the top of a responder chain as
//!     not revoked;
//!   * the identity test matching every certificate, which bypasses the
//!     whole chain;
//!   * the identity test accepting an issuer match *or* a serial match
//!     instead of both, which bypasses any certificate that collides with
//!     the responder on either.
//!
//! The fixtures are a three-certificate chain under a separate root, and
//! `ca2` shares the responders' serial number deliberately -- serial
//! numbers are unique per issuer, not globally (RFC 5280 §4.1.2.2). See
//! `fixtures/ocsp-depth2/gen.py`.

use pkix_chain::{
    verify_ocsp_responder, DefaultVerifier, Error, NoAiaFetcher, NoRevocation, RevocationChecker,
    TrustAnchor,
};
use pkix_profiles::BasicOcspResponderProfile;
use pkix_revocation::Error as RevocationError;
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

const NOW: u64 = 1_780_272_000;

fn load(name: &str) -> Certificate {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/ocsp-depth2")
        .join(name);
    let der = std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
    Certificate::from_der(&der).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

/// Revokes exactly one certificate, identified by its subject common name.
///
/// `AlwaysRevoking` in the neighbouring file cannot distinguish these cases:
/// it refuses every certificate, so the chain fails whether or not the shim
/// consulted it for the one certificate under test. Naming a single subject
/// makes the refusal attributable.
struct RevokesSubject(&'static str);

impl RevokesSubject {
    fn decide(&self, cert: &Certificate) -> pkix_revocation::Result<()> {
        let subject = cert.tbs_certificate().subject().to_string();
        if subject.contains(self.0) {
            return Err(RevocationError::Revoked {
                serial: cert.tbs_certificate().serial_number().clone(),
                reason_code: None,
            });
        }
        Ok(())
    }
}

impl RevocationChecker for RevokesSubject {
    fn check_revocation(
        &self,
        cert: &Certificate,
        _issuer: &Certificate,
    ) -> pkix_revocation::Result<()> {
        self.decide(cert)
    }

    fn check_revocation_against_anchor(
        &self,
        cert: &Certificate,
        _anchor: &TrustAnchor,
    ) -> pkix_revocation::Result<()> {
        self.decide(cert)
    }
}

fn run<R: RevocationChecker>(responder: &str, revocation: &R) -> pkix_chain::Result<()> {
    let chain = [load(responder), load("ca2.der"), load("ca1.der")];
    let anchors = [TrustAnchor::from_cert(load("root.der"))];
    verify_ocsp_responder(
        &chain,
        &anchors,
        &load("ca2.der"),
        &BasicOcspResponderProfile,
        NOW,
        &DefaultVerifier,
        revocation,
        &NoAiaFetcher,
    )
    .map(|_| ())
}

/// The control: the chain itself validates, so a failure in any test below
/// is attributable to the revocation decision and not to the fixtures.
#[test]
fn the_depth_two_responder_chain_validates() {
    run("responder-nocheck.der", &NoRevocation).expect("chain should validate");
}

/// The bypass still applies at depth: the responder is `chain[0]`, so its
/// own revocation status is not consulted even though the checker would
/// refuse it.
#[test]
fn nocheck_bypasses_the_responder_at_depth() {
    run(
        "responder-nocheck.der",
        &RevokesSubject("OCSP Depth Responder"),
    )
    .expect("id-pkix-ocsp-nocheck must bypass revocation on the responder");
}

/// The rule the shim's `check_revocation` exists to keep: everything that
/// is not `chain[0]` is still the caller's to decide.
///
/// `ca2` is reached through `check_revocation` rather than the anchor
/// method, and it carries the responders' serial number, so this one
/// assertion fails if the shim stops delegating, if it bypasses
/// indiscriminately, or if it treats a serial match alone as identity.
#[test]
fn an_intermediate_below_the_responder_is_still_checked() {
    let err = run("responder-nocheck.der", &RevokesSubject("OCSP Depth CA2"))
        .expect_err("a revoked intermediate must be reported");
    match err {
        Error::Revocation(RevocationError::Revoked { .. }) => {}
        other => panic!("expected Error::Revocation(Revoked {{ .. }}), got: {other:?}"),
    }
}

/// And the top of the chain, which the anchor method handles.
#[test]
fn the_anchor_issued_intermediate_is_still_checked() {
    let err = run("responder-nocheck.der", &RevokesSubject("OCSP Depth CA1"))
        .expect_err("a revoked anchor-issued intermediate must be reported");
    match err {
        Error::Revocation(RevocationError::Revoked { .. }) => {}
        other => panic!("expected Error::Revocation(Revoked {{ .. }}), got: {other:?}"),
    }
}

/// The bypass is keyed on the extension, not on the position: the same
/// chain with a responder that omits `id-pkix-ocsp-nocheck` must report it
/// as revoked.
#[test]
fn without_the_extension_the_responder_is_checked_at_depth() {
    let err = run("responder.der", &RevokesSubject("OCSP Depth Responder"))
        .expect_err("without nocheck the responder's status must be honoured");
    match err {
        Error::Revocation(RevocationError::Revoked { .. }) => {}
        other => panic!("expected Error::Revocation(Revoked {{ .. }}), got: {other:?}"),
    }
}
