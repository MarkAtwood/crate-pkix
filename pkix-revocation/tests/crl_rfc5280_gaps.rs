//! PKITS vectors where `CrlChecker` reports "not revoked" (`Ok(())`) although
//! RFC 5280 §6.3.3 leaves the status undetermined, and one where it refused a
//! CRL that applies (GitHub issue #9). Each test prints the result and asserts
//! PKITS' outcome; the undetermined cases must fail safe with the specific
//! error the checker now reports.

use der::Decode as _;
use pkix_path::DefaultVerifier;
use pkix_revocation::{CrlChecker, Error, OutOfScopeReason, RevocationChecker as _};
use x509_cert::Certificate;

const NOW: u64 = 1_580_000_000; // 2020-01-26, inside every PKITS CRL window

fn file(dir: &str, name: &str, ext: &str) -> Vec<u8> {
    let base = env!("CARGO_MANIFEST_DIR");
    std::fs::read(format!(
        "{base}/../pkix-path/tests/pkits/{dir}/{name}.{ext}"
    ))
    .unwrap()
}
fn cert(name: &str) -> Certificate {
    Certificate::from_der(&file("certs", name, "crt")).unwrap()
}
fn crl(name: &str) -> Vec<u8> {
    file("crls", name, "crl")
}

/// 4.4.10: the CRL carries an unrecognized critical CRL extension
/// (2.16.840.1.101.2.1.12.2). RFC 5280 §5.2: such a CRL MUST NOT be used.
/// The EE (serial 2) is not listed, so using the CRL anyway yields "not revoked".
#[test]
fn pkits_4_4_10_unknown_critical_crl_extension() {
    let r = CrlChecker::new(crl("UnknownCRLExtensionCACRL"), NOW, DefaultVerifier).and_then(|c| {
        c.check_revocation(
            &cert("InvalidUnknownCRLExtensionTest10EE"),
            &cert("UnknownCRLExtensionCACert"),
        )
    });
    println!("4.4.10: {r:?}");
    assert_eq!(
        r,
        Err(Error::CrlUnsupportedCriticalExtension),
        "4.4.10: a CRL with an unknown critical extension must not be used"
    );
}

/// 4.14.17: CRL1 covers only {affiliationChanged, superseded}, CRL2 only
/// {cessationOfOperation, certificateHold}. Neither, nor both together, covers
/// all reasons (§6.3.3 (b)(1)/(d)/(k)), so the status stays undetermined.
#[test]
fn pkits_4_14_17_only_some_reasons() {
    let (ee, ca) = (
        cert("InvalidonlySomeReasonsTest17EE"),
        cert("onlySomeReasonsCA2Cert"),
    );
    for name in ["onlySomeReasonsCA2CRL1", "onlySomeReasonsCA2CRL2"] {
        let r = CrlChecker::new(crl(name), NOW, DefaultVerifier)
            .and_then(|c| c.check_revocation(&ee, &ca));
        println!("4.14.17 {name}: {r:?}");
        // Fail safe: combining reason-partitioned CRLs is not implemented, so a
        // CRL that does not list the EE reports "out of scope", never Ok(()).
        assert_eq!(
            r,
            Err(Error::OutOfScope(OutOfScopeReason::CrlOnlySomeReasons)),
            "4.14.17: {name} covers only some reasons; Ok(()) claims a full check"
        );
    }
}

/// 4.14.26: the EE's distribution point names cRLIssuer "CN=indirectCRL CA1x";
/// the only CRL is indirect and issued by "CN=indirectCRL CA1". §6.3.3 (b)(1):
/// the CRL issuer must match the DP's cRLIssuer, so this CRL does not apply.
#[test]
fn pkits_4_14_26_dp_crl_issuer_mismatch() {
    let r = CrlChecker::new_with_crl_issuer(
        crl("indirectCRLCA1CRL"),
        cert("indirectCRLCA1Cert"),
        NOW,
        DefaultVerifier,
    )
    .and_then(|c| {
        c.check_revocation(
            &cert("InvalidIDPwithindirectCRLTest26EE"),
            &cert("indirectCRLCA2Cert"),
        )
    });
    println!("4.14.26: {r:?}");
    assert_eq!(
        r,
        Err(Error::OutOfScope(
            OutOfScopeReason::CrlDistributionPointIssuerMismatch
        )),
        "4.14.26: the DP's cRLIssuer (CA1x) does not name the CRL issuer (CA1)"
    );
}

/// 4.14.29: the EE's DP is nameRelativeToCRLIssuer "CN=indirect CRL for
/// indirectCRL CA3" with cRLIssuer "OU=indirectCRL CA3 cRLIssuer". RFC 5280
/// §4.2.1.13 appends the fragment to the cRLIssuer DN, which then matches the
/// IDP of the cRLIssuer's indirect CRL. PKITS: valid.
#[test]
fn pkits_4_14_29_relative_name_against_crl_issuer() {
    let r = CrlChecker::new_with_crl_issuer(
        crl("indirectCRLCA3cRLIssuerCRL"),
        cert("indirectCRLCA3cRLIssuerCert"),
        NOW,
        DefaultVerifier,
    )
    .and_then(|c| c.check_revocation(&cert("ValidcRLIssuerTest29EE"), &cert("indirectCRLCA3Cert")));
    println!("4.14.29: {r:?}");
    assert!(
        r.is_ok(),
        "4.14.29: the cRLIssuer's indirect CRL covers the EE"
    );
}
