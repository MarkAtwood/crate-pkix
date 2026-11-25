//! `crl_applies_to`: RFC 5280 §6.3.3(b) distribution-point selection.
//!
//! The predicate answers "does this certificate's `cRLDistributionPoints`
//! point at this CRL?" — the question that must be settled *before* checking
//! revocation status, and the one that separates "the right CRL says nothing
//! about this certificate" from "some CRL says nothing".
//!
//! Fixtures are PKITS vectors, so the cases are the ones NIST built to
//! distinguish a conformant validator from a credulous one.
//!
//! # Why the negative cases carry the weight
//!
//! A caller holding several CRLs is tempted to try them all and accept
//! whichever validates. That is not RFC 5280's procedure and it cannot
//! distinguish a chain with no applicable CRL from one whose CRL merely
//! happens to be validly signed by somebody present. `wrong_crl_*` and
//! `unrelated_crl_*` below are the tests that fail for such a caller.

use der::Decode as _;
use pkix_revocation::{crl_applies_to, Error};
use x509_cert::Certificate;

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
/// This crate's own purpose-built fixtures, for the cases where a PKITS
/// vector's point is that something does *not* pair.
fn local(name: &str) -> Vec<u8> {
    let base = env!("CARGO_MANIFEST_DIR");
    std::fs::read(format!("{base}/tests/fixtures/{name}.der")).unwrap()
}

// ---------------------------------------------------------------------------
// The CRL a certificate points at
// ---------------------------------------------------------------------------

/// The CA's own CRL applies to a certificate it issued.
///
/// Uses this crate's fixtures rather than a PKITS vector: the obvious-looking
/// PKITS candidate is `InvalidWrongCRLTest6EE` with `WrongCRLCACRL`, and as
/// the vector name says, that CRL is deliberately the *wrong* one. Reaching
/// for it here was a misread that the issuer check below promptly caught.
#[test]
fn the_issuing_cas_crl_applies() {
    let leaf = Certificate::from_der(&local("crl-leaf-good")).unwrap();
    assert_eq!(
        crl_applies_to(&leaf, &local("crl-empty")),
        Ok(()),
        "a CRL issued by this certificate's own CA must be selected"
    );
}

/// PKITS 4.14.22: an **indirect** CRL applies when the certificate's
/// distribution point names its issuer as the `cRLIssuer`.
///
/// This is the case a caller cannot express by matching issuer DNs, because
/// the CRL issuer deliberately is not the certificate issuer. Getting it right
/// needs the `cRLIssuer` field and the CRL's `indirectCRL` IDP flag together.
#[test]
fn an_indirect_crl_applies_when_the_dp_names_its_issuer() {
    let leaf = cert("ValidIDPwithindirectCRLTest22EE");
    assert_eq!(
        crl_applies_to(&leaf, &crl("indirectCRLCA1CRL")),
        Ok(()),
        "an indirect CRL named by the certificate's cRLIssuer must be selected"
    );
}

// ---------------------------------------------------------------------------
// The CRLs it does not point at
// ---------------------------------------------------------------------------

/// A CRL from an unrelated CA is not selected, however valid it is.
///
/// `TrustAnchorRootCRL` is validly signed and current. A caller that tried
/// every CRL it held would reach it and read "serial not listed, not revoked".
#[test]
fn unrelated_crl_is_not_selected() {
    let leaf = cert("InvalidWrongCRLTest6EE");
    assert_eq!(
        crl_applies_to(&leaf, &crl("TrustAnchorRootCRL")),
        Err(Error::CrlIssuerMismatch),
        "a CRL from an unrelated issuer must not be selected, even though it \
         is validly signed and current"
    );
}

/// An indirect CRL whose IDP names no distribution point is selected even for
/// a certificate with no `cRLDistributionPoints`.
///
/// This pins **documented** behaviour rather than asserting a reading of the
/// RFC. `check_dp_scope`'s table says an absent CDP "match[es] unless the IDP
/// names a distribution point", and `indirectCRLCA1CRL`'s IDP carries only the
/// `indirectCRL` flag with no name — so there is no name constraint to fail.
/// The issuer constraint in `crl_applies_to` deliberately skips indirect CRLs,
/// since coming from another issuer is the entire point of one.
///
/// Whether a stricter reading is owed — RFC 5280 §6.3.3(b)(2)(i) can be read
/// as requiring a distribution point to name the `cRLIssuer`, which a
/// certificate without the extension can never do — is a real question, and
/// it is recorded rather than silently resolved by this test. Changing it
/// would change `check_dp_scope` for every caller, not just this predicate.
#[test]
fn an_unnamed_indirect_crl_is_selected_for_a_cert_without_a_cdp() {
    let other = cert("InvalidWrongCRLTest6EE");
    assert_eq!(
        crl_applies_to(&other, &crl("indirectCRLCA1CRL")),
        Ok(()),
        "documented behaviour: absent CDP matches an IDP that names no \
         distribution point"
    );
}

/// And the converse pairing: 4.14.22's certificate does not accept the
/// unrelated CA's CRL.
#[test]
fn wrong_crl_for_an_indirect_cert_is_rejected() {
    let leaf = cert("ValidIDPwithindirectCRLTest22EE");
    assert!(
        crl_applies_to(&leaf, &crl("WrongCRLCACRL")).is_err(),
        "selection must reject a CRL this certificate does not point at"
    );
}

// ---------------------------------------------------------------------------
// Malformed input fails closed
// ---------------------------------------------------------------------------

/// Garbage is a parse error, not a match.
#[test]
fn malformed_crl_der_is_a_parse_error() {
    let leaf = cert("InvalidWrongCRLTest6EE");
    assert!(matches!(
        crl_applies_to(&leaf, b"not a certificate list"),
        Err(Error::CrlParseError(_))
    ));
}

/// Truncating a real CRL is also a parse error rather than a silent miss.
#[test]
fn truncated_crl_der_is_a_parse_error() {
    let leaf = cert("InvalidWrongCRLTest6EE");
    let full = crl("WrongCRLCACRL");
    assert!(matches!(
        crl_applies_to(&leaf, &full[..full.len() / 2]),
        Err(Error::CrlParseError(_))
    ));
}

// ---------------------------------------------------------------------------
// Selection is not validation
// ---------------------------------------------------------------------------

/// `Ok(())` says the CRL is addressed to the certificate and nothing more.
///
/// PKITS 4.4.4 ships a CRL with a **bad signature**. Selection still accepts
/// it, because the certificate does point at it — rejecting it is
/// `CrlChecker`'s job. A caller treating `crl_applies_to` as validation would
/// accept a forged CRL, so the asymmetry is asserted rather than left to the
/// documentation.
#[test]
fn selection_does_not_check_the_signature() {
    let leaf = cert("InvalidBadCRLSignatureTest4EE");
    assert_eq!(
        crl_applies_to(&leaf, &crl("BadCRLSignatureCACRL")),
        Ok(()),
        "selection is addressing, not validation: a badly-signed CRL the \
         certificate points at is still the CRL it points at"
    );
}
