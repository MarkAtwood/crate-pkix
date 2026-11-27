//! A pre-2050 date encoded as `GeneralizedTime`: the case
//! [`tbs_certificate_der`] exists for.
//!
//! RFC 5280 §4.1.2.5 requires a validity time before 2050 to be a
//! `UTCTime`, and x509-cert's `Rfc5280` profile applies that rule when it
//! *serializes*: `TbsCertificate::to_der` converts a pre-2050
//! `GeneralizedTime` it parsed back into a `UTCTime`. Those are different
//! bytes, and the issuer signed the bytes it wrote. So re-encoding a
//! certificate of this shape to check its signature checks the wrong
//! message, and reports an invalid signature on a certificate that is
//! merely non-conformant.
//!
//! Every other fixture in this workspace encodes pre-2050 dates as
//! `UTCTime`, which is what the profile requires, so for all of them
//! `tbs_certificate_der` and a plain `to_der` return the same bytes and the
//! function's purpose went untested.
//!
//! Oracle: `tests/fixtures/gentime/gen.py` writes the signed bytes out as
//! `<name>-tbs.bin` beside each certificate and checks the signature over
//! them before writing either file.
#![cfg(all(feature = "p256", feature = "std"))]

use pkix_path::{
    tbs_certificate_der, validate_path, DefaultVerifier, SignatureVerifier, TrustAnchor,
    ValidationPolicy,
};
use x509_cert::der::{Decode as _, Encode as _};
use x509_cert::Certificate;

/// 2030-01-01T00:00:00Z, inside every fixture's validity window.
const NOW: u64 = 1_893_456_000;
const DIR: &str = "tests/fixtures/gentime";

fn read(name: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(DIR)
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn cert(stem: &str) -> Certificate {
    let der = read(&format!("{stem}.der"));
    Certificate::from_der(&der).unwrap_or_else(|e| panic!("parse {stem}: {e}"))
}

/// Does `cert`'s own key verify `cert`'s signature over `message`?
fn self_verifies(cert: &Certificate, message: &[u8]) -> bool {
    use x509_cert::der::referenced::OwnedToRef as _;
    DefaultVerifier
        .verify_signature(
            cert.signature_algorithm().owned_to_ref(),
            cert.tbs_certificate()
                .subject_public_key_info()
                .owned_to_ref(),
            message,
            cert.signature().raw_bytes(),
        )
        .is_ok()
}

const EVERY_FIXTURE: &[&str] = &["utctime-control", "gentime-both", "gentime-not-before"];

/// `tbs_certificate_der` returns the bytes that were signed.
///
/// Including for the control, where the two encoders agree: a function that
/// only worked for the non-conformant shape would be no use.
#[test]
fn the_returned_bytes_are_the_signed_bytes() {
    for stem in EVERY_FIXTURE {
        let cert = cert(stem);
        assert_eq!(
            tbs_certificate_der(&cert).expect("encode TBS"),
            read(&format!("{stem}-tbs.bin")),
            "{stem}"
        );
    }
}

/// Re-encoding through the profile changes a pre-2050 `GeneralizedTime`,
/// and only that.
///
/// This is the premise the whole function rests on, so it is asserted
/// rather than assumed: if a later x509-cert stopped normalizing on
/// serialize, `tbs_certificate_der` would be dead weight and this test
/// would say so.
#[test]
fn only_the_nonconformant_fixtures_are_re_encoded_differently() {
    for stem in EVERY_FIXTURE {
        let cert = cert(stem);
        let signed = read(&format!("{stem}-tbs.bin"));
        let re_encoded = cert.tbs_certificate().to_der().expect("re-encode TBS");
        let conformant = *stem == "utctime-control";
        assert_eq!(
            re_encoded == signed,
            conformant,
            "{stem}: re-encoding {} the signed bytes",
            if conformant {
                "should reproduce"
            } else {
                "should not reproduce"
            }
        );
    }
}

/// The consequence: the wrong encoder rejects a sound signature.
///
/// Both certificates are self-signed, so the key in each verifies the
/// signature on it -- over the bytes that were signed, and over nothing
/// else. That is what makes this a test of the encoding and not of the
/// verifier.
#[test]
fn a_generalized_time_certificate_verifies_only_against_the_parsed_bytes() {
    for stem in ["gentime-both", "gentime-not-before"] {
        let cert = cert(stem);
        assert!(
            self_verifies(&cert, &tbs_certificate_der(&cert).expect("encode TBS")),
            "{stem}: the parsed bytes must verify"
        );
        assert!(
            !self_verifies(&cert, &cert.tbs_certificate().to_der().expect("re-encode")),
            "{stem}: the re-encoded bytes must not verify"
        );
    }
}

/// Path validation accepts such a certificate.
///
/// The end-to-end statement, and the reason any of this matters: a
/// certificate whose only fault is encoding a 2026 date as
/// `GeneralizedTime` validates, rather than failing as though its
/// signature were forged.
#[test]
fn path_validation_accepts_a_generalized_time_certificate() {
    for stem in EVERY_FIXTURE {
        let subject = cert(stem);
        let anchors = [TrustAnchor::from_cert(cert(stem))];
        validate_path(
            core::slice::from_ref(&subject),
            &anchors,
            &ValidationPolicy::new(NOW),
            &DefaultVerifier,
        )
        .unwrap_or_else(|e| panic!("{stem}: {e}"));
    }
}
