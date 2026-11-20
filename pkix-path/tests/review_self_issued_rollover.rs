//! Review / GitHub issue #11: a self-issued key-rollover CA directly under a
//! same-name trust anchor.
//!
//! Fixtures: `tests/fixtures/review/self-issued-rollover/` (see `gen.sh`).
//! Oracle: `openssl verify -x509_strict` accepts `[leaf, ica]` under `root`
//! and rejects it under `forged-root` (same name, unrelated key).
//!
//! RFC 5280 §6.1.3(b)/(c) exempt the self-issued intermediate from the
//! root's name constraints, and its signature is checked with the anchor's
//! key like any other top certificate, so the path is valid.

#![cfg(feature = "p256")]

use der::Decode as _;
use pkix_path::{validate_path, DefaultVerifier, Error, TrustAnchor, ValidationPolicy};
use x509_cert::Certificate;

const NOW: u64 = 1_798_761_600; // 2027-01-01T00:00:00Z

fn load(name: &str) -> Certificate {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/review/self-issued-rollover")
        .join(format!("{name}.der"));
    Certificate::from_der(&std::fs::read(&p).unwrap()).unwrap()
}

fn run(chain: &[&str], anchors: &[&str]) -> pkix_path::Result<pkix_path::ValidatedPath> {
    let chain: Vec<_> = chain.iter().map(|n| load(n)).collect();
    let anchors: Vec<_> = anchors
        .iter()
        .map(|n| TrustAnchor::from_cert(load(n)))
        .collect();
    validate_path(
        &chain,
        &anchors,
        &ValidationPolicy::new(NOW),
        &DefaultVerifier,
    )
}

#[test]
fn rollover_intermediate_under_same_name_anchor_validates() {
    run(&["leaf", "ica"], &["root"]).expect("key-rollover CA signed by the anchor key");
}

#[test]
fn rollover_with_root_included_validates() {
    run(&["leaf", "ica", "root"], &["root"]).expect("root included as last chain element");
}

#[test]
fn forged_same_name_anchor_is_no_trusted_path() {
    let r = run(&["leaf", "ica"], &["forged-root"]);
    assert_eq!(r.map(|v| v.anchor_index), Err(Error::NoTrustedPath));
}

/// The real anchor is found even when a same-name forged anchor is listed
/// first (key-rollover trust stores hold several same-name anchors).
#[test]
fn forged_anchor_listed_first_does_not_mask_real_anchor() {
    let vp = run(&["leaf", "ica"], &["forged-root", "root"]).expect("second anchor signs ica");
    assert_eq!(vp.anchor_index, 1);
}
