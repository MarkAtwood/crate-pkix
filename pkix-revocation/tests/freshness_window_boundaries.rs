//! The exact instants at which a CRL or an OCSP response stops being fresh.
//!
//! Four comparisons decide freshness on the CRL path and six on the OCSP
//! path, and each appears twice: once in `check_revocation`, once in
//! `check_revocation_against_anchor`. Every test in the suite ran at a
//! `now` comfortably inside the validity window, so not one of those
//! comparisons had its boundary pinned: `<` could become `<=`, or `>`
//! become `>=`, and nothing failed.
//!
//! Both directions are defects. Rejecting a certificate's status one
//! second early turns a usable CRL into `CrlExpired` and strands a caller
//! with no revocation information; accepting one second late is the
//! fail-open direction, and the window exists precisely to bound how long
//! a stale revocation list may suppress a revocation.
//!
//! RFC 5280 §5.1.2.4 and §5.1.2.5 make the interval inclusive: `thisUpdate`
//! is the issue date and `nextUpdate` the date by which the next CRL will
//! be issued, so a CRL is current *at* both. RFC 6960 §4.2.2.1 says the
//! same of a `SingleResponse`.
//!
//! The boundaries are read out of the fixtures rather than written down
//! here, so regenerating them cannot leave the tests asserting a window
//! the fixtures no longer have.

use der::Decode as _;
use pkix_path::{DefaultVerifier, TrustAnchor};
use pkix_revocation::{CrlChecker, Error, OcspChecker, RevocationChecker as _};
use x509_cert::crl::CertificateList;
use x509_cert::Certificate;
use x509_ocsp::{BasicOcspResponse, OcspResponse};

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn load_cert(name: &str) -> Certificate {
    Certificate::from_der(&fixture(name)).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

/// A fixture path inside one of the subdirectories of `tests/fixtures`.
fn in_dir(dir: &str, name: &str) -> String {
    format!("{dir}/{name}")
}

/// `thisUpdate` and `nextUpdate` of a CRL fixture, in seconds.
fn crl_window(name: &str) -> (u64, u64) {
    let crl: CertificateList =
        CertificateList::from_der(&fixture(name)).expect("fixture is a DER CRL");
    let this = crl.tbs_cert_list.this_update.to_unix_duration().as_secs();
    let next = crl
        .tbs_cert_list
        .next_update
        .as_ref()
        .expect("fixture has nextUpdate")
        .to_unix_duration()
        .as_secs();
    (this, next)
}

/// `producedAt`, and the single response's `thisUpdate` and `nextUpdate`,
/// in seconds.
fn ocsp_window(name: &str) -> (u64, u64, u64) {
    let resp = OcspResponse::from_der(&fixture(name)).expect("fixture is a DER OcspResponse");
    let bytes = resp
        .response_bytes
        .as_ref()
        .expect("fixture carries responseBytes");
    let basic =
        BasicOcspResponse::from_der(bytes.response.as_bytes()).expect("BasicOcspResponse decodes");
    let produced = basic
        .tbs_response_data
        .produced_at
        .as_ref()
        .to_unix_duration()
        .as_secs();
    let single = basic
        .tbs_response_data
        .responses
        .first()
        .expect("fixture carries one SingleResponse");
    let this = single.this_update.as_ref().to_unix_duration().as_secs();
    let next = single
        .next_update
        .as_ref()
        .expect("fixture has nextUpdate")
        .as_ref()
        .to_unix_duration()
        .as_secs();
    (produced, this, next)
}

// ---------------------------------------------------------------------------
// CRL, both entry points
// ---------------------------------------------------------------------------

fn crl_at(now: u64) -> CrlChecker<DefaultVerifier> {
    CrlChecker::new(fixture("crl-empty.der"), now, DefaultVerifier)
        .expect("fixture is a valid DER-encoded CRL")
}

#[test]
fn a_crl_is_current_at_this_update_and_at_next_update() {
    let (this, next) = crl_window("crl-empty.der");
    let ca = load_cert("crl-ca.der");
    let anchor = TrustAnchor::from(&ca);
    let leaf = load_cert("crl-leaf-good.der");

    for now in [this, next] {
        crl_at(now)
            .check_revocation(&leaf, &ca)
            .unwrap_or_else(|e| panic!("CRL must be current at {now}, got {e:?}"));
        crl_at(now)
            .check_revocation_against_anchor(&leaf, &anchor)
            .unwrap_or_else(|e| panic!("CRL must be current at {now} via anchor, got {e:?}"));
    }
}

#[test]
fn a_crl_is_not_current_one_second_outside_either_end() {
    let (this, next) = crl_window("crl-empty.der");
    let ca = load_cert("crl-ca.der");
    let anchor = TrustAnchor::from(&ca);
    let leaf = load_cert("crl-leaf-good.der");

    for now in [this - 1, next + 1] {
        assert!(
            matches!(
                crl_at(now).check_revocation(&leaf, &ca),
                Err(Error::CrlExpired)
            ),
            "CRL must be out of window at {now}"
        );
        assert!(
            matches!(
                crl_at(now).check_revocation_against_anchor(&leaf, &anchor),
                Err(Error::CrlExpired)
            ),
            "CRL must be out of window at {now} via anchor"
        );
    }
}

// ---------------------------------------------------------------------------
// OCSP, both entry points
// ---------------------------------------------------------------------------

fn ocsp_at(now: u64) -> OcspChecker<DefaultVerifier> {
    OcspChecker::new(fixture("ocsp-good.der"), now, DefaultVerifier)
        .expect("fixture is a valid DER-encoded OcspResponse")
}

#[test]
fn an_ocsp_response_is_usable_at_produced_at_and_at_next_update() {
    let (produced, _this, next) = ocsp_window("ocsp-good.der");
    let ca = load_cert("ocsp-ca.der");
    let anchor = TrustAnchor::from(&ca);
    let leaf = load_cert("ocsp-leaf-good.der");

    for now in [produced, next] {
        ocsp_at(now)
            .check_revocation(&leaf, &ca)
            .unwrap_or_else(|e| panic!("response must be usable at {now}, got {e:?}"));
        ocsp_at(now)
            .check_revocation_against_anchor(&leaf, &anchor)
            .unwrap_or_else(|e| panic!("response must be usable at {now} via anchor, got {e:?}"));
    }
}

/// One second before `producedAt` the responder has not issued the response
/// yet, which is a malformed or tampered one rather than a stale one -- so
/// `OcspMalformed`, not `OcspExpired`. One second after `nextUpdate` it is
/// simply stale.
#[test]
fn an_ocsp_response_is_refused_one_second_outside_either_end() {
    let (produced, _this, next) = ocsp_window("ocsp-good.der");
    let ca = load_cert("ocsp-ca.der");
    let anchor = TrustAnchor::from(&ca);
    let leaf = load_cert("ocsp-leaf-good.der");

    for (now, expected) in [(produced - 1, "OcspMalformed"), (next + 1, "OcspExpired")] {
        let direct = ocsp_at(now).check_revocation(&leaf, &ca);
        let via_anchor = ocsp_at(now).check_revocation_against_anchor(&leaf, &anchor);
        for r in [direct, via_anchor] {
            let got = match r {
                Err(Error::OcspMalformed) => "OcspMalformed",
                Err(Error::OcspExpired) => "OcspExpired",
                other => panic!("at {now} expected {expected}, got {other:?}"),
            };
            assert_eq!(got, expected, "at {now}");
        }
    }
}

// ---------------------------------------------------------------------------
// The `thisUpdate` guard, which a conformant response cannot reach
// ---------------------------------------------------------------------------

/// `thisUpdate` is checked separately from `producedAt`, and the separation
/// matters for one response shape.
///
/// The checker tests `now < producedAt` before `now < thisUpdate`. Any
/// response a conformant responder issues has `producedAt >= thisUpdate`
/// (RFC 6960 §4.2.2.1), so for those the first test subsumes the second and
/// no fixture in `tests/fixtures` can exercise it -- which is why its
/// boundary went unpinned.
///
/// It is still live for a response with `thisUpdate` in the future relative
/// to `producedAt`: a responder claiming to describe a status it cannot have
/// observed yet. The window it declares has to be honoured rather than
/// ignored, so the response is unusable until `thisUpdate` and usable at it.
///
/// Fixture rationale: `fixtures/ocsp-future-this-update/gen.py`.
#[test]
fn a_future_this_update_is_honoured_rather_than_ignored() {
    const DIR: &str = "ocsp-future-this-update";
    let resp = in_dir(DIR, "response.der");
    let (produced, this, next) = ocsp_window(&resp);
    assert!(
        produced < this,
        "fixture premise: producedAt {produced} must precede thisUpdate {this}"
    );
    assert!(this < next, "fixture premise: the window is non-empty");

    let ca = load_cert(&in_dir(DIR, "ca.der"));
    let anchor = TrustAnchor::from(&ca);
    let leaf = load_cert(&in_dir(DIR, "leaf.der"));

    let at = |now: u64| {
        OcspChecker::new(fixture(&resp), now, DefaultVerifier)
            .expect("fixture is a valid DER-encoded OcspResponse")
    };

    // Usable at thisUpdate, on both entry points.
    at(this)
        .check_revocation(&leaf, &ca)
        .unwrap_or_else(|e| panic!("usable at thisUpdate {this}, got {e:?}"));
    at(this)
        .check_revocation_against_anchor(&leaf, &anchor)
        .unwrap_or_else(|e| panic!("usable at thisUpdate {this} via anchor, got {e:?}"));

    // Not one second earlier, even though producedAt is long past.
    for r in [
        at(this - 1).check_revocation(&leaf, &ca),
        at(this - 1).check_revocation_against_anchor(&leaf, &anchor),
    ] {
        assert!(
            matches!(r, Err(Error::OcspExpired)),
            "must be unusable one second before thisUpdate, got {r:?}"
        );
    }
}
