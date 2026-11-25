//! `check_revocation_with_crls`: RFC 5280 §6.3.3 reason-mask accumulation.
//!
//! A CRL carrying `onlySomeReasons` covers only those revocation reasons. It
//! can prove a certificate **is** revoked, but alone it cannot prove one is
//! **not** revoked — another reason may be listed on a CRL covering the rest.
//! A single `CrlChecker` therefore reports `CrlOnlySomeReasons`, which is
//! correct and incomplete.
//!
//! Fixtures are the PKITS vectors that exist for exactly this. CA3 and CA4
//! each publish two CRLs: one for `keyCompromise` + `cACompromise`, one for
//! the remaining reasons. Together they cover everything.

use der::Decode as _;
use pkix_path::DefaultVerifier;
use pkix_revocation::{
    check_revocation_with_crls, CrlChecker, Error, OutOfScopeReason, RevocationChecker as _,
};
use x509_cert::Certificate;

const NOW: u64 = 1_580_000_000; // 2020-01-26, inside every PKITS CRL window
/// This crate's own fixtures are issued for 2026; the PKITS clock above is
/// outside their CRL window and yields `CrlExpired`.
const NOW_LOCAL: u64 = 1_780_272_000; // 2026-06-01

fn file(dir: &str, name: &str, ext: &str) -> Vec<u8> {
    let base = env!("CARGO_MANIFEST_DIR");
    std::fs::read(format!(
        "{base}/../pkix-path/tests/pkits/{dir}/{name}.{ext}"
    ))
    .unwrap_or_else(|e| panic!("{dir}/{name}.{ext}: {e}"))
}
fn cert(name: &str) -> Certificate {
    Certificate::from_der(&file("certs", name, "crt")).unwrap()
}
fn crl(name: &str) -> Vec<u8> {
    file("crls", name, "crl")
}
/// This crate's own fixtures, where PKITS has no vector for the case.
fn local(name: &str) -> Vec<u8> {
    let base = env!("CARGO_MANIFEST_DIR");
    std::fs::read(format!("{base}/tests/fixtures/{name}.der")).unwrap()
}

// ---------------------------------------------------------------------------
// The gap this closes
// ---------------------------------------------------------------------------

/// A single partitioned CRL cannot clear a certificate — the pre-existing,
/// correct, incomplete behaviour.
///
/// Asserted so the improvement below is visibly an improvement rather than a
/// claim, and so a regression that made one partitioned CRL sufficient would
/// be caught here.
#[test]
fn one_partitioned_crl_alone_leaves_status_undetermined() {
    let leaf = cert("ValidonlySomeReasonsTest18EE");
    let ca = cert("onlySomeReasonsCA3Cert");
    let checker = CrlChecker::new(crl("onlySomeReasonsCA3compromiseCRL"), NOW, DefaultVerifier)
        .expect("CRL parses");
    assert_eq!(
        checker.check_revocation(&leaf, &ca),
        Err(Error::OutOfScope(OutOfScopeReason::CrlOnlySomeReasons)),
        "a CRL covering only keyCompromise and cACompromise cannot prove a \
         certificate is unrevoked for every reason"
    );
}

/// PKITS 4.14.18: the two CA3 CRLs together cover every reason, so the
/// certificate is cleared.
#[test]
fn two_partitioned_crls_covering_all_reasons_clear_the_cert() {
    let leaf = cert("ValidonlySomeReasonsTest18EE");
    let ca = cert("onlySomeReasonsCA3Cert");
    let compromise = crl("onlySomeReasonsCA3compromiseCRL");
    let other = crl("onlySomeReasonsCA3otherreasonsCRL");

    assert_eq!(
        check_revocation_with_crls(
            &leaf,
            &ca,
            &[&compromise[..], &other[..]],
            NOW,
            &DefaultVerifier
        ),
        Ok(()),
        "PKITS 4.14.18 is a valid chain: the union of the two partitions \
         covers every RFC 5280 §5.2.5 reason"
    );
}

/// PKITS 4.14.19, the CA4 variant, to show it is not one fixture's quirk.
#[test]
fn the_ca4_partitions_also_clear_their_cert() {
    let leaf = cert("ValidonlySomeReasonsTest19EE");
    let ca = cert("onlySomeReasonsCA4Cert");
    let compromise = crl("onlySomeReasonsCA4compromiseCRL");
    let other = crl("onlySomeReasonsCA4otherreasonsCRL");

    assert_eq!(
        check_revocation_with_crls(
            &leaf,
            &ca,
            &[&compromise[..], &other[..]],
            NOW,
            &DefaultVerifier
        ),
        Ok(())
    );
}

/// Order must not matter: the mask is a union.
#[test]
fn the_verdict_is_independent_of_crl_order() {
    let leaf = cert("ValidonlySomeReasonsTest18EE");
    let ca = cert("onlySomeReasonsCA3Cert");
    let compromise = crl("onlySomeReasonsCA3compromiseCRL");
    let other = crl("onlySomeReasonsCA3otherreasonsCRL");

    let forward = check_revocation_with_crls(
        &leaf,
        &ca,
        &[&compromise[..], &other[..]],
        NOW,
        &DefaultVerifier,
    );
    let reverse = check_revocation_with_crls(
        &leaf,
        &ca,
        &[&other[..], &compromise[..]],
        NOW,
        &DefaultVerifier,
    );
    assert_eq!(forward, reverse, "a union cannot depend on iteration order");
    assert_eq!(forward, Ok(()));
}

// ---------------------------------------------------------------------------
// Incomplete coverage still fails closed
// ---------------------------------------------------------------------------

/// One partition is still one partition, even through the combining path.
///
/// This is the test that matters: a function that accumulated reasons but
/// forgot to require full coverage would pass everything above and fail here.
#[test]
fn partial_coverage_still_fails_closed() {
    let leaf = cert("ValidonlySomeReasonsTest18EE");
    let ca = cert("onlySomeReasonsCA3Cert");
    let compromise = crl("onlySomeReasonsCA3compromiseCRL");

    assert_eq!(
        check_revocation_with_crls(&leaf, &ca, &[&compromise[..]], NOW, &DefaultVerifier),
        Err(Error::OutOfScope(OutOfScopeReason::CrlOnlySomeReasons)),
        "covering only two reasons leaves the status undetermined"
    );
}

/// PKITS 4.14.17: two genuinely different partitions whose union is *still*
/// incomplete.
///
/// CRL1 covers affiliationChanged and superseded; CRL2 covers
/// cessationOfOperation and certificateHold. Four of eight reasons, so
/// keyCompromise among others is uncovered and NIST classes the chain
/// invalid. Both CRLs are empty, so nothing is proven revoked either.
///
/// Stronger than the single-CRL case above: an implementation that accepted
/// a certificate once it had seen more than one partitioned CRL, without
/// checking what they actually covered, would pass every other test here and
/// fail this one.
#[test]
fn two_different_partitions_with_incomplete_union_fail_closed() {
    let leaf = cert("InvalidonlySomeReasonsTest17EE");
    let ca = cert("onlySomeReasonsCA2Cert");
    let c1 = crl("onlySomeReasonsCA2CRL1");
    let c2 = crl("onlySomeReasonsCA2CRL2");

    assert_eq!(
        check_revocation_with_crls(&leaf, &ca, &[&c1[..], &c2[..]], NOW, &DefaultVerifier),
        Err(Error::OutOfScope(OutOfScopeReason::CrlOnlySomeReasons)),
        "four of eight reasons covered leaves the status undetermined"
    );
}

/// Revoked wins, and wins immediately.
///
/// A CRL that lists the certificate is authoritative for the reasons it
/// covers, so the accumulation must not continue hunting for full coverage
/// and report undetermined. PKITS has no partitioned CRL with a revoked
/// entry, so this uses this crate's fixtures: `crl-with-reason` revokes
/// serial 02, which is `crl-leaf-revoked`.
#[test]
fn a_crl_listing_the_cert_reports_revoked_not_undetermined() {
    let leaf = Certificate::from_der(&local("crl-leaf-revoked")).unwrap();
    let ca = Certificate::from_der(&local("crl-ca")).unwrap();
    let listing = local("crl-with-reason");

    assert!(
        matches!(
            check_revocation_with_crls(&leaf, &ca, &[&listing[..]], NOW_LOCAL, &DefaultVerifier),
            Err(Error::Revoked { .. })
        ),
        "a CRL listing the certificate must report Revoked, not undetermined"
    );
}

/// Repeating the same partition does not fake coverage.
#[test]
fn duplicating_one_partition_does_not_complete_the_mask() {
    let leaf = cert("ValidonlySomeReasonsTest18EE");
    let ca = cert("onlySomeReasonsCA3Cert");
    let c = crl("onlySomeReasonsCA3compromiseCRL");

    assert_eq!(
        check_revocation_with_crls(&leaf, &ca, &[&c[..], &c[..], &c[..]], NOW, &DefaultVerifier),
        Err(Error::OutOfScope(OutOfScopeReason::CrlOnlySomeReasons)),
        "a union of one set with itself is that set"
    );
}

/// No applicable CRL reports why, not a misleading partition verdict.
#[test]
fn no_applicable_crl_reports_its_own_reason() {
    let leaf = cert("ValidonlySomeReasonsTest18EE");
    let ca = cert("onlySomeReasonsCA3Cert");
    let unrelated = crl("TrustAnchorRootCRL");

    let got = check_revocation_with_crls(&leaf, &ca, &[&unrelated[..]], NOW, &DefaultVerifier);
    assert!(
        got.is_err() && got != Err(Error::OutOfScope(OutOfScopeReason::CrlOnlySomeReasons)),
        "an unrelated CRL is not a reason-partitioning problem; got {got:?}"
    );
}

/// An empty CRL list is an error, not a clean bill of health.
#[test]
fn no_crls_at_all_is_an_error() {
    let leaf = cert("ValidonlySomeReasonsTest18EE");
    let ca = cert("onlySomeReasonsCA3Cert");
    assert!(check_revocation_with_crls(&leaf, &ca, &[], NOW, &DefaultVerifier).is_err());
}
