//! A delegated responder certificate valid at the instant the response was
//! produced, with `producedAt` on each validity edge.
//!
//! RFC 6960 §4.2.2.2 requires the designated responder's certificate to
//! have been valid when the response was produced, and a certificate's
//! validity period is inclusive at both ends (RFC 5280 §4.1.2.5). So
//! `producedAt` equal to `notBefore`, or equal to `notAfter`, is valid.
//!
//! `validate_delegate_responder_cert` decides it with
//!
//! ```text
//! if produced_at_unix < nb || produced_at_unix > na
//! ```
//!
//! and neither comparison was pinned. `producedAt` in every other fixture
//! is the wall-clock second its generator ran -- `ocsp-delegated-good.der`
//! carries 2026-05-08 20:05:11 against a responder valid from 2026-01-01
//! to 2030-01-01 -- so both edges sat months away and `<` read as `<=` or
//! `==`, or `>` as `>=`, changed no verdict in the suite.
//!
//! Each pair below differs by one second of `producedAt` and in nothing
//! else, which is what makes these tests of the comparison. Oracle:
//! `tests/fixtures/ocsp-produced-at/gen.py`, which writes `producedAt`
//! into the signed `ResponseData` and re-signs, then checks that the
//! response still parses, carries the value asked for, and verifies under
//! the embedded responder certificate.

use pkix_path::DefaultVerifier;
use pkix_revocation::{Error, OcspChecker, RevocationChecker as _};
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

/// 2026-06-01T00:00:00Z, after every fixture's `producedAt` -- a response
/// claiming to come from the future is refused earlier, as malformed.
const NOW: u64 = 1_780_272_000;
const DIR: &str = "tests/fixtures/ocsp-produced-at";

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(DIR)
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn load_cert(name: &str) -> Certificate {
    Certificate::from_der(&fixture(name)).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

fn check(response: &str) -> pkix_revocation::Result<()> {
    let ca = load_cert("ca.der");
    let leaf = load_cert("leaf.der");
    OcspChecker::new(fixture(response), NOW, DefaultVerifier)
        .expect("fixture is a valid OCSP response")
        .check_revocation(&leaf, &ca)
}

/// `producedAt` equal to the responder certificate's `notBefore` is inside
/// its validity period.
///
/// A certificate is valid *on* its `notBefore`, so refusing this is
/// refusing a sound response. The second fixture is the same responder
/// certificate one second earlier, which genuinely predates it.
#[test]
fn produced_at_the_responder_certificates_first_second_is_accepted() {
    check("at-not-before.der").expect("producedAt == notBefore is within the responder's validity");
    assert!(
        matches!(
            check("before-not-before.der"),
            Err(Error::OcspResponderCertExpired)
        ),
        "one second before notBefore must be refused, got {:?}",
        check("before-not-before.der")
    );
}

/// `producedAt` equal to the responder certificate's `notAfter` is inside
/// its validity period.
///
/// The upper edge, for the same reason and with the same one-second
/// control on the other side of it. This is the direction that matters
/// most: the comparison exists so that a response produced after the
/// responder's certificate expired is refused even while the response's
/// own freshness window still looks current, and an off-by-one here
/// refuses the last second of every responder certificate's life.
#[test]
fn produced_at_the_responder_certificates_last_second_is_accepted() {
    check("at-not-after.der").expect("producedAt == notAfter is within the responder's validity");
    assert!(
        matches!(
            check("after-not-after.der"),
            Err(Error::OcspResponderCertExpired)
        ),
        "one second after notAfter must be refused, got {:?}",
        check("after-not-after.der")
    );
}
