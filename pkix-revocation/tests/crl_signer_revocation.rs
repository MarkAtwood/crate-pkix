//! The CRL signer is reachable, so a caller can check whether it is revoked.
//!
//! `CrlChecker` does not and cannot determine whether the certificate that
//! signed a CRL has itself been revoked — nothing in its inputs carries that
//! information. A CRL signed by a revoked certificate must not be trusted, so
//! the caller has to make the determination, and needs to know which
//! certificate to make it about.
//!
//! With `new_with_signer_discovery` that certificate is chosen inside the
//! constructor, so these tests exist to prove the caller can still find it and
//! act on it. Without `crl_signer()` the information was simply unavailable.
//!
//! The scenario is NIST PKITS 4.4.21, which is structurally identical to the
//! 4.4.19 beside it — same topology, CRL-signing certificate a sibling of the
//! chain rather than a link in it, empty CRL — and differs only in that its
//! signer's certificate is revoked by the trust anchor's CRL.

use der::Decode as _;
use pkix_path::DefaultVerifier;
use pkix_revocation::{discover_crl_signer, CrlChecker, RevocationChecker as _};
use x509_cert::crl::CertificateList;
use x509_cert::Certificate;

const NOW: u64 = 1_580_000_000; // 2020-01-26, inside every PKITS CRL window

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

/// Does `crl_der` list `cert` as revoked? A caller's own check, by serial.
fn is_revoked_by(cert: &Certificate, crl_der: &[u8]) -> bool {
    let Ok(parsed) = CertificateList::<x509_cert::certificate::Rfc5280>::from_der(crl_der) else {
        return false;
    };
    if &parsed.tbs_cert_list.issuer != cert.tbs_certificate().issuer() {
        return false;
    }
    parsed
        .tbs_cert_list
        .revoked_certificates
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .any(|e| &e.serial_number == cert.tbs_certificate().serial_number())
}

// ---------------------------------------------------------------------------
// The accessor exposes what discovery chose
// ---------------------------------------------------------------------------

/// Discovery selects a signer and the caller can see which.
#[test]
fn the_discovered_signer_is_reachable() {
    let bundle = vec![
        cert("TrustAnchorRootCertificate"),
        cert("SeparateCertificateandCRLKeysCA2CertificateSigningCACert"),
        cert("SeparateCertificateandCRLKeysCA2CRLSigningCert"),
    ];
    let leaf = cert("InvalidSeparateCertificateandCRLKeysTest21EE");

    let checker = CrlChecker::new_with_signer_discovery(
        crl("SeparateCertificateandCRLKeysCA2CRL"),
        &bundle,
        &leaf,
        NOW,
        DefaultVerifier,
    )
    .expect("the CA2 CRL signer is in the bundle");

    let signer = checker
        .crl_signer()
        .expect("a discovered signer is stored, not just used");
    assert_eq!(
        signer.tbs_certificate().subject(),
        cert("SeparateCertificateandCRLKeysCA2CRLSigningCert")
            .tbs_certificate()
            .subject()
    );
    assert!(
        checker.crl_signer_was_discovered(),
        "this signer came from discovery, not from the caller"
    );
}

/// A caller-supplied indirect signer is reported as not discovered.
///
/// The distinction matters to a caller that trusts a certificate it chose
/// itself but wants to re-examine one the library picked out of a bundle.
#[test]
fn an_explicit_signer_is_not_marked_discovered() {
    let signer = cert("SeparateCertificateandCRLKeysCA2CRLSigningCert");
    let checker = CrlChecker::new_with_crl_issuer(
        crl("SeparateCertificateandCRLKeysCA2CRL"),
        signer,
        NOW,
        DefaultVerifier,
    )
    .expect("constructs");
    assert!(checker.crl_signer().is_some());
    assert!(!checker.crl_signer_was_discovered());
}

/// A direct CRL stores no separate signer: it is the issuer the caller
/// already holds.
#[test]
fn a_direct_crl_reports_no_separate_signer() {
    let checker = CrlChecker::new(crl("TrustAnchorRootCRL"), NOW, DefaultVerifier).expect("parses");
    assert!(checker.crl_signer().is_none());
    assert!(!checker.crl_signer_was_discovered());
}

// ---------------------------------------------------------------------------
// And the caller can act on it — the point of the accessor
// ---------------------------------------------------------------------------

/// PKITS 4.4.21: the checker accepts the CRL, and the caller catches it.
///
/// This is the whole gap in one test. `check_revocation` reports the end
/// entity as not revoked, because the CA2 CRL is empty and validly signed.
/// NIST classes the chain invalid because the signer's certificate, serial
/// 68, is revoked by `TrustAnchorRootCRL`. The library cannot see that; the
/// caller can, via `crl_signer()`, and must.
#[test]
fn a_caller_can_detect_a_revoked_crl_signer() {
    let bundle = vec![
        cert("TrustAnchorRootCertificate"),
        cert("SeparateCertificateandCRLKeysCA2CertificateSigningCACert"),
        cert("SeparateCertificateandCRLKeysCA2CRLSigningCert"),
    ];
    let leaf = cert("InvalidSeparateCertificateandCRLKeysTest21EE");
    let ca = cert("SeparateCertificateandCRLKeysCA2CertificateSigningCACert");
    let root_crl = crl("TrustAnchorRootCRL");

    let checker = CrlChecker::new_with_signer_discovery(
        crl("SeparateCertificateandCRLKeysCA2CRL"),
        &bundle,
        &leaf,
        NOW,
        DefaultVerifier,
    )
    .expect("constructs");

    // The library's own verdict: not revoked.
    assert_eq!(
        checker.check_revocation(&leaf, &ca),
        Ok(()),
        "the CA2 CRL is empty and validly signed, so the checker clears the \
         end entity — this is the behaviour the caller must not take at face \
         value"
    );

    // The caller's check, which is what NIST requires.
    let signer = checker.crl_signer().expect("discovered");
    assert!(
        is_revoked_by(signer, &root_crl),
        "PKITS 4.4.21's CRL signer is revoked by the trust anchor's CRL; if \
         this fails the fixtures changed and the scenario is gone"
    );
}

/// 4.4.19's signer is NOT revoked, so the same caller-side check clears it.
///
/// Without this the test above would pass against a check that called
/// everything revoked.
#[test]
fn the_valid_siblings_signer_is_not_revoked() {
    let signer = cert("SeparateCertificateandCRLKeysCRLSigningCert");
    assert!(
        !is_revoked_by(&signer, &crl("TrustAnchorRootCRL")),
        "4.4.19's signer must not be revoked — it is the control for 4.4.21"
    );
}

/// `discover_crl_signer` gives the same answer without building a checker,
/// which is the pre-filtering route the documentation points at.
#[test]
fn discovery_can_be_run_standalone_to_pre_filter() {
    let bundle = vec![
        cert("TrustAnchorRootCertificate"),
        cert("SeparateCertificateandCRLKeysCA2CertificateSigningCACert"),
        cert("SeparateCertificateandCRLKeysCA2CRLSigningCert"),
    ];
    let der = crl("SeparateCertificateandCRLKeysCA2CRL");
    let parsed =
        CertificateList::<x509_cert::certificate::Rfc5280>::from_der(&der).expect("CRL parses");

    let signer = discover_crl_signer(&bundle, &parsed).expect("signer is in the bundle");
    assert!(
        is_revoked_by(signer, &crl("TrustAnchorRootCRL")),
        "a caller can identify and reject the signer before building a checker"
    );
}

// ---------------------------------------------------------------------------
// A direct CRL must name the CA that issued the certificate
// ---------------------------------------------------------------------------

/// Discovery mode must not accept a direct CRL issued by a different CA than
/// the one that issued the certificate.
///
/// This is the hole the `(2c)` check closes. The earlier code enforced
/// `cert.issuer == CRL.issuer` only when no signer certificate was supplied
/// at all, so discovery mode skipped it outright. The other two name checks
/// do not cover the gap:
///
/// - `(2a)` ties the CRL's issuer to the *discovered signer's* subject, so it
///   is satisfied by construction whenever discovery works at all.
/// - `(2b)` ties the `issuer` argument to `cert.issuer`, which says nothing
///   about the CRL.
///
/// Between them the certificate and the CRL are never compared, so a CRL from
/// an unrelated CA could decide an unrelated certificate's revocation status
/// as long as its own signer was present in the bundle. Here the certificate
/// is issued by `GoodCA` while the CRL comes from the Trust Anchor Root, both
/// legitimate and both correctly signed — only the pairing is wrong.
#[test]
fn discovery_rejects_a_direct_crl_from_a_different_ca_than_the_certs_issuer() {
    let ee = cert("ValidCertificatePathTest1EE");
    let good_ca = cert("GoodCACert");
    let anchor = cert("TrustAnchorRootCertificate");

    // The CRL belongs to the Trust Anchor Root, not to GoodCA.
    let foreign_crl = crl("TrustAnchorRootCRL");

    // Bundle holds the CRL's real signer, so discovery succeeds and the
    // rejection cannot be blamed on a failed lookup.
    let bundle = [anchor.clone(), good_ca.clone()];
    let checker =
        CrlChecker::new_with_signer_discovery(&foreign_crl, &bundle, &ee, NOW, DefaultVerifier)
            .expect("the CRL's signer is in the bundle, so discovery must succeed");
    assert!(
        checker.crl_signer().is_some(),
        "the signer must have been discovered for this test to mean anything"
    );

    // `good_ca` is the EE's real issuer, so check (2b) passes and the
    // failure can only come from the certificate-to-CRL comparison.
    let err = checker
        .check_revocation(&ee, &good_ca)
        .expect_err("a GoodCA-issued certificate must not be judged by the anchor's CRL");
    assert!(
        matches!(err, pkix_revocation::Error::CrlIssuerMismatch),
        "expected CrlIssuerMismatch, got {err:?}"
    );
}

/// The matching positive case: discovery still accepts a direct CRL that does
/// name the certificate's issuer.
///
/// Without this, the test above would also pass if `(2c)` rejected every
/// discovered direct CRL.
#[test]
fn discovery_accepts_a_direct_crl_from_the_certs_own_issuer() {
    let ee = cert("ValidCertificatePathTest1EE");
    let good_ca = cert("GoodCACert");
    let anchor = cert("TrustAnchorRootCertificate");

    let own_crl = crl("GoodCACRL");
    let bundle = [anchor, good_ca.clone()];
    let checker =
        CrlChecker::new_with_signer_discovery(&own_crl, &bundle, &ee, NOW, DefaultVerifier)
            .expect("GoodCA is in the bundle");

    checker
        .check_revocation(&ee, &good_ca)
        .expect("a valid EE against its own issuer's CRL must pass");
}
