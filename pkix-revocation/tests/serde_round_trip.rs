//! Round-trip tests for `pkix-revocation`'s serde feature.
//!
//! Run with: `cargo test -p pkix-revocation --features serde,crl,ocsp --test serde_round_trip`

#![cfg(feature = "serde")]

use der::{Decode as _, Encode as _};
use pkix_revocation::{Error, OutOfScopeReason};
use x509_cert::{
    certificate::Rfc5280,
    ext::pkix::crl::CrlReason,
    serial_number::SerialNumber,
};

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
