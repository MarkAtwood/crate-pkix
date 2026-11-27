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

/// `Error::MalformedAnchor { index, source }` round-trips, preserving
/// the index and the cached Display message of the inner `DerError`.
/// `DerError`'s `inner` field (the original `der::Error`) is dropped on
/// the deserialize side, but `DerError`'s `PartialEq` compares only the
/// message, so `Error::MalformedAnchor == Error::MalformedAnchor` holds
/// across round-trips.
#[test]
fn error_malformed_anchor_round_trips_preserving_index_and_source() {
    let bad: &[&[u8]] = &[&[0xff_u8; 16]];
    let err = from_der_iter(bad.iter().copied()).expect_err("malformed entry");
    let original_display = format!("{err}");
    let json = serde_json::to_string(&err).expect("serialize");
    let back: Error = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, back);
    assert_eq!(format!("{back}"), original_display);
    match back {
        Error::MalformedAnchor { index, source: _ } => assert_eq!(index, 0),
        other => panic!("expected MalformedAnchor {{ index: 0, .. }}, got {other:?}"),
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
    assert_eq!(json, r#"{"kind":"PermissionDenied","message":"forbidden"}"#);
}

/// Every `io::ErrorKind` the shim names, with its wire form written out.
///
/// The names are the oracle: they are what `Debug` on `ErrorKind`
/// produces, quoted here rather than derived from the code under test,
/// so a `Debug` rendering that changed upstream would show up as a
/// failure rather than as a silently different wire format.
const KNOWN_KINDS: &[(&str, io::ErrorKind)] = &[
    ("NotFound", io::ErrorKind::NotFound),
    ("PermissionDenied", io::ErrorKind::PermissionDenied),
    ("ConnectionRefused", io::ErrorKind::ConnectionRefused),
    ("ConnectionReset", io::ErrorKind::ConnectionReset),
    ("ConnectionAborted", io::ErrorKind::ConnectionAborted),
    ("NotConnected", io::ErrorKind::NotConnected),
    ("AddrInUse", io::ErrorKind::AddrInUse),
    ("AddrNotAvailable", io::ErrorKind::AddrNotAvailable),
    ("BrokenPipe", io::ErrorKind::BrokenPipe),
    ("AlreadyExists", io::ErrorKind::AlreadyExists),
    ("WouldBlock", io::ErrorKind::WouldBlock),
    ("InvalidInput", io::ErrorKind::InvalidInput),
    ("InvalidData", io::ErrorKind::InvalidData),
    ("TimedOut", io::ErrorKind::TimedOut),
    ("WriteZero", io::ErrorKind::WriteZero),
    ("Interrupted", io::ErrorKind::Interrupted),
    ("Unsupported", io::ErrorKind::Unsupported),
    ("UnexpectedEof", io::ErrorKind::UnexpectedEof),
    ("OutOfMemory", io::ErrorKind::OutOfMemory),
];

/// Each named `ErrorKind` survives a round-trip as itself.
///
/// The shim maps a finite list of names and sends everything else to
/// `ErrorKind::Other`, which is lossy by design -- a producer on a newer
/// Rust emitting a kind this list does not know reaches an older
/// consumer as `Other`, with the message preserved. That design makes
/// every arm fail silently when it goes missing: the kind degrades to
/// `Other` and nothing errors. Only `NotFound` was covered, so eighteen
/// arms could each have been deleted with the suite still green.
///
/// A caller branching on `kind` to decide whether a missing bundle is a
/// configuration problem or a permissions problem gets `Other` for both.
#[test]
fn every_known_error_kind_round_trips_as_itself() {
    for (name, kind) in KNOWN_KINDS {
        let failure = IoFailure::from_io(&io::Error::from(*kind));

        let value: serde_json::Value =
            serde_json::to_value(&failure).expect("IoFailure serializes");
        assert_eq!(
            value.get("kind").and_then(serde_json::Value::as_str),
            Some(*name),
            "{name} must appear on the wire under that name"
        );

        let back: IoFailure =
            serde_json::from_value(value).unwrap_or_else(|e| panic!("{name} deserializes: {e}"));
        assert_eq!(back.kind, *kind, "{name} must come back as itself");
        assert_eq!(back.message, failure.message, "and keep its message");
    }
}

/// A name the shim does not know degrades to `Other`, keeping the
/// message.
///
/// This is the documented lossy edge, and asserting it is what makes the
/// test above a statement about the named arms rather than about the
/// catch-all: without it, a shim that answered `Other` for everything
/// would be indistinguishable from one missing a single arm.
#[test]
fn an_unknown_error_kind_degrades_to_other_with_its_message_kept() {
    let value = serde_json::json!({
        "kind": "FilesystemQuotaExceeded",
        "message": "quota exceeded while reading the bundle",
    });
    let back: IoFailure = serde_json::from_value(value).expect("unknown kinds still deserialize");
    assert_eq!(back.kind, io::ErrorKind::Other);
    assert_eq!(back.message, "quota exceeded while reading the bundle");
}
