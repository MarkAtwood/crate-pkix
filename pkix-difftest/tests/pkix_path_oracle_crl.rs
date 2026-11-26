//! Integration tests for the pkix-path oracle's CRL handling (PKIX-emf1.2).
//!
//! These tests exercise the revocation-checking branch added in PKIX-emf1.2:
//! when `Chain.crls` is non-empty, the oracle runs each cert through every
//! supplied CRL and flips the verdict to `Fail` on a `Revoked` outcome.
//!
//! # Independent oracles
//!
//! Verdict expectations come from PKITS ground truth (per-vector
//! `ShouldValidate` flag in `pkix-path/tests/pkits/vectors.json`) cross-checked
//! against `openssl verify -crl_check_all` (PKIX-emf1.3 wires the same chains
//! through OpenSSL). The PkitsCorpus loader's CRL plumbing is independently
//! asserted in `tests/corpus_pkits.rs`. This file asserts only what the
//! pkix-path oracle does with a CRL-bearing Chain.
//!
//! Chain loading uses the PkitsCorpus loader (PKIX-emf1.5) so the
//! certificates and CRLs both come straight from the PKITS manifest.

use std::path::PathBuf;

use pkix_difftest::corpus::pkits::PkitsCorpus;
use pkix_difftest::corpus::Corpus;
use pkix_difftest::{oracles, Chain, Verdict};

/// Load a PKITS testcase by name and return its `Chain`. Panics if the
/// testcase is not present in the shipped vectors manifest.
fn pkits_chain(name: &str) -> Chain {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("pkix-path/tests/pkits");
    let corpus = PkitsCorpus::load(&root).expect("load PKITS manifest");
    for item in corpus.iter() {
        let item = item.expect("PKITS entry resolves");
        if item.name == name {
            return item.chain;
        }
    }
    panic!("PKITS testcase not found: {name}");
}

#[test]
fn pkix_path_oracle_passes_pkits_4_1_1_with_crls_attached() {
    // Oracle: PKITS 4.1.1 "Valid Signatures Test1" — ShouldValidate=true.
    // The chain ships with TrustAnchorRootCRL and GoodCACRL; neither lists
    // the EE serial. The pkix-path oracle must therefore return Pass even
    // with CRLs attached.
    let chain = pkits_chain("4.1.1 Valid Signatures Test1");
    assert!(
        !chain.crls.is_empty(),
        "precondition: chain ships with CRLs (PKITS 4.1.1 has CRLPath)"
    );
    let verdict =
        oracles::pkix_path::verify(&chain).expect("pkix-path oracle ran without harness error");
    assert_eq!(
        verdict,
        Verdict::Pass,
        "PKITS 4.1.1 must validate with CRLs attached; got {verdict}"
    );
}

#[test]
fn pkix_path_oracle_reports_revoked_for_pkits_4_4_3() {
    // Oracle: PKITS 4.4.3 "Invalid Revoked EE Test3" — ShouldValidate=false.
    // The EE serial is on GoodCACRL. The pkix-path oracle must flip the
    // verdict from Pass (path-only) to Fail (after revocation check).
    let chain = pkits_chain("4.4.3 Invalid Revoked EE Test3");
    assert!(
        !chain.crls.is_empty(),
        "precondition: chain ships with CRLs"
    );
    let verdict =
        oracles::pkix_path::verify(&chain).expect("pkix-path oracle ran without harness error");
    match verdict {
        Verdict::Pass => panic!(
            "PKITS 4.4.3 must fail under pkix-path with CRLs attached (EE is revoked); got Pass"
        ),
        Verdict::Fail { reason } => {
            assert!(
                reason.to_lowercase().contains("revoked"),
                "expected revocation-related reason, got: {reason:?}"
            );
        }
    }
}

#[test]
fn pkix_path_oracle_does_not_check_revocation_when_crls_empty() {
    // Oracle: a chain whose `crls` field is empty must produce the same
    // verdict as it would without the CRL branch. PKITS 4.1.1 with crls
    // cleared still passes (path-only validation), no revocation attempt.
    let mut chain = pkits_chain("4.1.1 Valid Signatures Test1");
    chain.crls.clear();
    let verdict =
        oracles::pkix_path::verify(&chain).expect("pkix-path oracle ran without harness error");
    assert_eq!(
        verdict,
        Verdict::Pass,
        "PKITS 4.1.1 must validate with no CRLs; got {verdict}"
    );
}

/// PKITS 4.15.5: a base CRL holds the certificate, the delta releases it.
///
/// Oracle: PKITS §4.15.5 "Valid delta-CRL Test5" — ShouldValidate=true, and
/// `openssl verify -crl_check_all` agrees. RFC 5280 §5.3.1 `removeFromCRL`
/// in a delta means the certificate is no longer revoked.
///
/// This is a regression test for a defect in the oracle, not in
/// `pkix-revocation`: that crate's own `pkits_4_15_5_valid_delta_remove_from_crl`
/// passed throughout. The oracle offered both a base+delta checker and a bare
/// base checker for the same base, and failed closed on the first revocation
/// any checker reported — so the bare base's `certificateHold` always won and
/// `removeFromCRL` could never take effect. It was reported as a real
/// disagreement with NIST for as long as the baseline recorded it.
///
/// The bare base must not be consulted by any route once a delta amends it,
/// signer discovery included: putting the supersession guard in one place and
/// leaving a second construction site outside it is what made the first
/// attempt at this fix insufficient.
#[test]
fn pkix_path_oracle_honours_remove_from_crl_in_a_delta() {
    let chain = pkits_chain("4.15.5 Valid delta-CRL Test5");
    assert!(
        chain.crls.len() >= 2,
        "precondition: 4.15.5 ships a base CRL and a delta; got {}",
        chain.crls.len()
    );
    let verdict =
        oracles::pkix_path::verify(&chain).expect("pkix-path oracle ran without harness error");
    assert_eq!(
        verdict,
        Verdict::Pass,
        "4.15.5: the delta's removeFromCRL releases serial 4, so the chain must \
         validate; got {verdict}"
    );
}

/// The other direction, so the fix above cannot have been a blanket
/// "ignore the base when a delta is present".
///
/// Oracle: PKITS §4.15.3 "Invalid delta-CRL Test3" — ShouldValidate=false.
/// The certificate is revoked in the base and the delta does not release it,
/// so it stays revoked. A delta amends the base rather than replacing it.
#[test]
fn pkix_path_oracle_keeps_a_base_revocation_a_delta_does_not_release() {
    let chain = pkits_chain("4.15.3 Invalid delta-CRL Test3");
    let verdict =
        oracles::pkix_path::verify(&chain).expect("pkix-path oracle ran without harness error");
    assert!(
        matches!(verdict, Verdict::Fail { .. }),
        "4.15.3: revoked in the base and not released by the delta must stay \
         revoked; got {verdict}"
    );
}
