//! A discovered CRL signer has to reach a self-signed certificate.
//!
//! `CrlChecker::new_with_signer_discovery` refuses a signer it cannot walk
//! from the supplied bundle to a self-signed certificate
//! (`Error::CrlSignerNotTrusted`). The walk is bounded by the bundle's own
//! length, and it only accepts a parent whose subject is the DN the
//! certificate names as its issuer.
//!
//! Both of those had mutants nothing killed. The existing discovery tests
//! all use bundles where the walk succeeds, so a `find_parent` that picked
//! any certificate but the one in hand, and a counter that never advanced,
//! both went unnoticed.
//!
//! Fixture rationale: `tests/fixtures/signer-anchoring/gen.py`.

#![cfg(feature = "crl")]

use der::Decode as _;
use pkix_path::DefaultVerifier;
use pkix_revocation::{CrlChecker, Error};
use x509_cert::Certificate;

const NOW: u64 = 1_780_272_000;
const DIR: &str = "tests/fixtures/signer-anchoring";

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(DIR)
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn load(name: &str) -> Certificate {
    Certificate::from_der(&fixture(name)).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

/// An unrelated self-signed certificate in the bundle does not anchor the
/// signer.
///
/// The orphan's issuer DN belongs to a CA that is in no bundle, so the walk
/// has nowhere to step. What makes this worth asserting is the bundle's
/// second entry: a self-signed certificate with nothing to do with the
/// orphan. `find_parent` requires a candidate to be a *different*
/// certificate **and** to carry the subject the certificate names as its
/// issuer; relax that to either and the walk steps onto whatever entry is
/// not the one in hand, finds it self-signed, and reports a signer that
/// reaches nothing as anchored.
#[test]
fn an_unrelated_self_signed_certificate_does_not_anchor_a_signer() {
    let bundle = [load("orphan.der"), load("unrelated-root.der")];
    let r = CrlChecker::new_with_signer_discovery(
        fixture("crl-from-orphan.der"),
        &bundle,
        NOW,
        DefaultVerifier,
    );
    assert!(
        matches!(r, Err(Error::CrlSignerNotTrusted)),
        "the orphan's issuer is in no bundle, so nothing anchors it, got: {r:?}"
    );
}

/// A bundle whose issuer references form a cycle is refused, and the
/// refusal arrives.
///
/// `cycle-a` names `cycle-b` as its issuer and `cycle-b` names `cycle-a`.
/// Neither is self-signed, so the walk A -> B -> A -> ... has no
/// terminator and only the step counter stops it. Without the counter
/// advancing, this call does not return a wrong answer -- it does not
/// return, which turns a crafted bundle into a hang.
///
/// Mutual issuer references are what a cross-certified pair looks like, so
/// the shape is not purely adversarial.
///
/// The call runs on its own thread with a deadline, because the failure this
/// guards against is non-termination. Left to hang in the test harness it
/// would stall the job until CI's own timeout and read as infrastructure
/// flake; bounded here it reads as what it is.
#[test]
fn a_cycle_in_the_bundle_terminates_rather_than_looping() {
    use std::sync::mpsc;
    use std::time::Duration;

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let bundle = [load("cycle-a.der"), load("cycle-b.der")];
        let r = CrlChecker::new_with_signer_discovery(
            fixture("crl-from-a.der"),
            &bundle,
            NOW,
            DefaultVerifier,
        );
        // Only the discriminant crosses the channel: CrlChecker is not Send
        // for every verifier, and the verdict is all this test wants.
        let _ = tx.send(matches!(r, Err(Error::CrlSignerNotTrusted)));
    });

    match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(true) => {}
        Ok(false) => panic!("a cycle reaches no self-signed certificate, so this must refuse"),
        Err(_) => panic!(
            "the walk did not terminate: a cyclic bundle is bounded by the \
             step counter, and nothing else stops it"
        ),
    }
}

/// The control: a signer that is itself self-signed is anchored.
///
/// Without it the two refusals above would pass for a constructor that
/// refused every bundle, which is the failure mode a reachability check is
/// most likely to degrade into.
#[test]
fn a_self_signed_signer_anchors_itself() {
    let bundle = [load("unrelated-root.der")];
    CrlChecker::new_with_signer_discovery(
        fixture("crl-from-unrelated-root.der"),
        &bundle,
        NOW,
        DefaultVerifier,
    )
    .expect("a self-signed signer needs no further walk");
}
