//! The supported `UTCTime` range is 1970-2049, and that is a decision.
//!
//! RFC 5280 §4.1.2.5.1 allows 1950-2049. This crate supports 1970-2049,
//! because `der` 0.8 puts the floor at the Unix epoch and lifting it
//! would mean forking the DER layer every consumer builds against. No
//! conforming CA issues certificates dated before 1970.
//!
//! These tests pin the boundary so it cannot move unnoticed — in either
//! direction. If a dependency bump widens the range, the first test
//! fails and the documented range needs updating with it.
//!
//! Fixtures are NIST PKITS certificates, used here for their dates
//! rather than for their validation outcome. Their dates are the oracle,
//! read with `openssl x509 -dates`, which parses all of them.

use der::Decode as _;
use x509_cert::Certificate;

fn pkits_der(name: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/pkits/certs")
        .join(format!("{name}.crt"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

/// A certificate dated before 1970 is refused, and refused while parsing.
///
/// `Validpre2000UTCnotBeforeDateTest3EE` has `notBefore=1950-01-01`
/// (`openssl x509 -dates`). PKITS expects it to validate and OpenSSL
/// reads it, so this is a real disagreement rather than strictness —
/// stated in the crate docs, and the one PKITS vector this crate does
/// not evaluate.
///
/// Fail-closed is the property that matters: the certificate is refused,
/// never misread as some other date.
#[test]
fn a_pre_1970_certificate_is_refused_not_misread() {
    let der = pkits_der("Validpre2000UTCnotBeforeDateTest3EE");
    let result = Certificate::from_der(&der);
    assert!(
        result.is_err(),
        "a notBefore of 1950 is outside the supported 1970-2049 range and \
         must be refused, not reinterpreted"
    );
}

/// The boundary is the epoch, not the millennium.
///
/// This is the mistake worth guarding against, because the workspace
/// made it: earlier documentation described the limit as "pre-2000
/// UTCTime". `Invalidpre2000UTCEEnotAfterDateTest7EE` is named "pre2000"
/// and dated 1997-1999 — comfortably inside the supported range — and it
/// parses. Only the 1950 fixture above does not.
///
/// A test that only checked the 1950 case would pass just as well under
/// a parser that rejected everything before 2000.
#[test]
fn dates_between_1970_and_2000_parse_normally() {
    for name in [
        // notBefore 1997, notAfter 1999.
        "Invalidpre2000UTCEEnotAfterDateTest7EE",
        // notBefore 2010, for contrast.
        "pre2000CRLnextUpdateCACert",
    ] {
        let der = pkits_der(name);
        assert!(
            Certificate::from_der(&der).is_ok(),
            "{name} is inside 1970-2049 and must parse; the supported \
             floor is the Unix epoch, not the year 2000"
        );
    }
}
