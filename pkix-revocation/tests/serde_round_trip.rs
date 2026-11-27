//! Round-trip tests for `pkix-revocation`'s serde feature.
//!
//! Run with: `cargo test -p pkix-revocation --features serde,crl,ocsp --test serde_round_trip`

#![cfg(feature = "serde")]

use der::{Decode as _, Encode as _};
use pkix_revocation::{Error, OutOfScopeReason};
use x509_cert::{certificate::Rfc5280, ext::pkix::crl::CrlReason, serial_number::SerialNumber};

// Explicit `Profile` parameter so type inference does not choke on the
// generic default. `SerialNumber<Rfc5280>` matches the type used by
// the `Error::Revoked` variant.
type Serial = SerialNumber<Rfc5280>;

/// `Error::Revoked` with both `Some(reason_code)` and `None` round-trips.
#[test]
fn error_revoked_round_trips_with_and_without_reason() {
    // Build a non-trivial serial number via DER round-trip: serial = 0x42.
    let serial_der: [u8; 3] = [0x02, 0x01, 0x42]; // INTEGER 0x42
    let serial = Serial::from_der(&serial_der).expect("serial decodes");

    for reason_code in [Some(CrlReason::KeyCompromise), None] {
        let err = Error::Revoked {
            serial: serial.clone(),
            reason_code,
        };
        let json = serde_json::to_string(&err).expect("serialize");
        let back: Error = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, back);
        match back {
            Error::Revoked {
                serial: s,
                reason_code: r,
            } => {
                // DER canonicality oracle: the recovered serial
                // re-encodes to the same DER bytes as the original.
                assert_eq!(s.to_der().unwrap(), serial.to_der().unwrap());
                assert_eq!(r, reason_code);
            }
            other => panic!("expected Revoked, got {other:?}"),
        }
    }
}

/// `Error::CrlParseError(DerError)` round-trips with Display
/// preservation. Display equality is the oracle (the diagnostic
/// message survives the round-trip even though the inner `der::Error`
/// cannot).
#[test]
fn error_crl_parse_round_trips_preserving_display() {
    let truncated: &[u8] = &[0xff; 8];
    // Build a real der::Error by trying to decode a garbage SerialNumber
    // (any DER-decoding failure works as a fixture source).
    let dec_err = Serial::from_der(truncated).expect_err("garbage fails decode");
    let original = Error::CrlParseError(pkix_revocation::DerError::new(dec_err));
    let original_display = format!("{original}");
    let json = serde_json::to_string(&original).expect("serialize");
    let back: Error = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, back);
    assert_eq!(format!("{back}"), original_display);
    assert!(matches!(back, Error::CrlParseError(_)));
}

/// `Error::OutOfScope(OutOfScopeReason::*)` round-trips for every
/// variant currently in the enum.
#[test]
fn error_out_of_scope_round_trips_for_each_reason() {
    let reasons = [
        OutOfScopeReason::CrlOnlyAttributeCerts,
        OutOfScopeReason::CrlOnlyUserCerts,
        OutOfScopeReason::CrlOnlyCaCerts,
        OutOfScopeReason::CrlIdpDistributionPointMismatch,
    ];
    for r in reasons {
        let err = Error::OutOfScope(r);
        let json = serde_json::to_string(&err).expect("serialize");
        let back: Error = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, back, "mismatch for {r:?}");
    }
}

/// Unit-variant errors round-trip cleanly.
#[test]
fn error_unit_variants_round_trip() {
    let cases = [
        Error::CrlExpired,
        Error::CrlIssuerMismatch,
        Error::CrlSignatureInvalid,
        Error::OcspSignatureInvalid,
        Error::OcspStatusUnknown,
        Error::OcspMalformed,
        Error::IndirectCrlIssuerMissing,
        Error::CrlNumberMismatch,
        Error::MalformedCertificate,
    ];
    for err in &cases {
        let json = serde_json::to_string(err).expect("serialize");
        let back: Error = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, &back, "round-trip mismatch for {err:?}");
    }
}

/// `Error::Revoked` wire form for `reason_code` uses RFC 5280 §5.3.1
/// numeric codes (not the variant name). Hand-written expected JSON
/// acts as the independent oracle.
#[test]
fn revoked_reason_code_wire_form_uses_rfc_numeric_codes() {
    let serial_der: [u8; 3] = [0x02, 0x01, 0x07];
    let serial = Serial::from_der(&serial_der).expect("serial decodes");
    let err = Error::Revoked {
        serial,
        reason_code: Some(CrlReason::KeyCompromise),
    };
    let json = serde_json::to_string(&err).expect("serialize");
    // KeyCompromise = 1 per RFC 5280 §5.3.1.
    assert!(
        json.contains(r#""reason_code":1"#),
        "wire form did not use numeric reason code: {json}"
    );
}

/// Every RFC 5280 §5.3.1 reason code, in both directions.
///
/// The test above covers `keyCompromise` alone, which left the other nine
/// codes free to serialize as anything and -- worse -- free to vanish on
/// the way back. `deserialize_opt` maps an unrecognised code to `None`
/// deliberately, so a dropped case does not fail: it silently turns a
/// revocation reason into "no reason given". A cached `Error::Revoked`
/// read back by a newer build would lose the reason the certificate was
/// revoked for, which is the part a caller routes on.
///
/// The codes are written out from RFC 5280 §5.3.1 rather than derived
/// from the enum, so the table is an independent oracle. The sequence
/// skips 7: RFC 5280 assigns no reason to it.
#[test]
fn every_reason_code_round_trips_through_its_rfc_number() {
    const CODES: [(CrlReason, u32); 10] = [
        (CrlReason::Unspecified, 0),
        (CrlReason::KeyCompromise, 1),
        (CrlReason::CaCompromise, 2),
        (CrlReason::AffiliationChanged, 3),
        (CrlReason::Superseded, 4),
        (CrlReason::CessationOfOperation, 5),
        (CrlReason::CertificateHold, 6),
        (CrlReason::RemoveFromCRL, 8),
        (CrlReason::PrivilegeWithdrawn, 9),
        (CrlReason::AaCompromise, 10),
    ];

    for (reason, code) in CODES {
        let serial_der: [u8; 3] = [0x02, 0x01, 0x07];
        let err = Error::Revoked {
            serial: Serial::from_der(&serial_der).expect("serial decodes"),
            reason_code: Some(reason),
        };
        let json = serde_json::to_string(&err).expect("serialize");
        assert!(
            json.contains(&format!(r#""reason_code":{code}"#)),
            "{reason:?} must serialize as {code}, got: {json}"
        );
        let back: Error = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, back, "{reason:?} did not survive the round trip");
    }
}

/// An unassigned code deserializes as "no reason given" rather than
/// failing, so a value a future revision adds does not make the whole
/// cached error unreadable.
///
/// 7 is unassigned in RFC 5280 §5.3.1 and stands in for any code this
/// build does not know.
#[test]
fn an_unassigned_reason_code_deserializes_as_no_reason() {
    let serial_der: [u8; 3] = [0x02, 0x01, 0x07];
    let known = Error::Revoked {
        serial: Serial::from_der(&serial_der).expect("serial decodes"),
        reason_code: Some(CrlReason::KeyCompromise),
    };
    let json = serde_json::to_string(&known)
        .expect("serialize")
        .replace(r#""reason_code":1"#, r#""reason_code":7"#);
    assert!(
        json.contains(r#""reason_code":7"#),
        "the substitution must have landed: {json}"
    );

    let back: Error = serde_json::from_str(&json).expect("an unknown code must still deserialize");
    match back {
        Error::Revoked { reason_code, .. } => {
            assert_eq!(reason_code, None, "an unassigned code must become None")
        }
        other => panic!("expected Error::Revoked, got {other:?}"),
    }
}
