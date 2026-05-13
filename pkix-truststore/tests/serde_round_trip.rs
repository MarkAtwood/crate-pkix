//! Round-trip tests for `pkix-truststore`'s serde feature.
//!
//! Verifies the `Error` and `IoFailure` types round-trip cleanly
//! through JSON without losing the diagnostic message or
//! pattern-matchable variant identity.
//!
//! Run with: `cargo test -p pkix-truststore --features serde --test serde_round_trip`

#![cfg(feature = "serde")]

use pkix_truststore::{from_der, from_der_iter, from_pem, Error, IoFailure};
use std::io;

/// `Error::NoCertificates` (unit variant) round-trips.
#[test]
fn error_no_certificates_round_trips() {
    let err = from_pem(b"").expect_err("empty input must be NoCertificates");
    let json = serde_json::to_string(&err).expect("serialize");
    let back: Error = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, back);
    assert!(matches!(back, Error::NoCertificates));
}

/// `Error::MalformedAnchor(usize)` round-trips, preserving the index.
#[test]
fn error_malformed_anchor_round_trips_preserving_index() {
    let bad: &[&[u8]] = &[&[0xff_u8; 16]];
    let err = from_der_iter(bad.iter().copied()).expect_err("malformed entry");
    let json = serde_json::to_string(&err).expect("serialize");
    let back: Error = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, back);
    match back {
        Error::MalformedAnchor(i) => assert_eq!(i, 0),
        other => panic!("expected MalformedAnchor(0), got {other:?}"),
    }
}

/// `Error::Der(DerError)` round-trips. The recovered `Error` has the
/// same Display output as the original (DerError's cached message
/// survives serde round-trips). `inner` is dropped on the deserialize
/// side, but DerError's `PartialEq` compares only the message, so
/// `Error::Der == Error::Der` holds across round-trips.
#[test]
fn error_der_round_trips_preserving_display() {
    let bad = [0xff_u8; 64];
    let err = from_der(&bad).expect_err("garbage DER");
    let original_display = format!("{err}");

    let json = serde_json::to_string(&err).expect("serialize");
    let back: Error = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, back);
    assert_eq!(format!("{back}"), original_display);
    assert!(matches!(back, Error::Der(_)));
}

/// `IoFailure` constructed from a real `io::Error` round-trips.
/// `kind` is preserved (round-tripped via the Debug-string serde
/// helper) and the message is preserved verbatim.
#[test]
fn io_failure_round_trips_preserving_kind_and_message() {
    let original = io::Error::new(io::ErrorKind::NotFound, "no such file");
    let failure = IoFailure::from_io(&original);
    let json = serde_json::to_string(&failure).expect("serialize");
    let back: IoFailure = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(failure, back);
    assert_eq!(back.kind, io::ErrorKind::NotFound);
    assert!(back.message.contains("no such file"));
}

/// `IoFailure` deserialization gracefully accepts kinds the consumer
/// does not know. Producer emits `"FutureKind"`, consumer falls back
/// to `ErrorKind::Other` so the message field is still recovered.
/// This is forward-compat insurance: `io::ErrorKind` is
/// `#[non_exhaustive]` upstream and grows non-breakingly.
#[test]
fn io_failure_unknown_kind_falls_back_to_other() {
    // Hand-written JSON with a kind value that does not match any
    // known variant in the deserializer's lookup table.
    let json = r#"{"kind":"FutureKindAddedIn2030","message":"hypothetical"}"#;
    let back: IoFailure = serde_json::from_str(json).expect("deserialize");
    assert_eq!(back.kind, io::ErrorKind::Other);
    assert_eq!(back.message, "hypothetical");
}

/// `IoFailure` emitted Debug representation of `ErrorKind` matches the
/// upstream variant name. Hand-written expected JSON acts as the
/// independent oracle (verifies our serializer's wire form, not just
/// our round-trip).
#[test]
fn io_failure_wire_form_uses_debug_variant_name() {
    // Round trip via `from_io` because `IoFailure` is
    // `#[non_exhaustive]` and cannot be constructed with a struct
    // literal from outside the crate.
    let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "forbidden");
    let failure = IoFailure::from_io(&io_err);
    let json = serde_json::to_string(&failure).expect("serialize");
    // Independent oracle: the wire form is `{"kind":"PermissionDenied",
    // "message":"<rendered>"}`. Display of `io::Error::new(..., msg)` is
    // exactly `msg`, so the message field equals "forbidden".
    assert_eq!(
        json,
        r#"{"kind":"PermissionDenied","message":"forbidden"}"#
    );
}
