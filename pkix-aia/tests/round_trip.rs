//! JSON serialization round-trip tests for [`pkix_aia::AiaError`].
//!
//! Required features: `serde` + `std`. The `[[test]]` entry in
//! `Cargo.toml` gates this test on both being enabled.
//!
//! The oracle is hand-written JSON: each variant has an expected
//! wire form pinned as a string literal. The test asserts both
//! directions —
//!
//! 1. `serde_json::to_string(&error)` == expected literal, and
//! 2. `serde_json::from_str(expected)` == original error
//!
//! This shape is required by PKIX-2l0v.1 D1 (cache-key bytewise
//! stability of result-type serializations) and by AGENTS.md
//! non-negotiable #6 (cache-friendly result types support serde).

use std::io::ErrorKind;

use pkix_aia::AiaError;

/// Helper: serialize → deserialize → compare equal. Returns the
/// serialized form so the caller can additionally pin its bytes.
fn round_trip(error: &AiaError) -> String {
    let json = serde_json::to_string(error).expect("serialize");
    let back: AiaError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(*error, back, "round-trip identity failed");
    json
}

#[test]
fn round_trip_fetching_disabled() {
    let json = round_trip(&AiaError::FetchingDisabled);
    assert_eq!(json, r#""FetchingDisabled""#);
}

#[test]
fn round_trip_http_status() {
    let json = round_trip(&AiaError::HttpStatus(503));
    assert_eq!(json, r#"{"HttpStatus":503}"#);
}

#[test]
fn round_trip_response_too_large() {
    let json = round_trip(&AiaError::ResponseTooLarge {
        limit: 65_536,
        actual: 131_072,
    });
    assert_eq!(
        json,
        r#"{"ResponseTooLarge":{"limit":65536,"actual":131072}}"#
    );
}

#[test]
fn round_trip_malformed_certificate() {
    let json = round_trip(&AiaError::MalformedCertificate(
        "expected SEQUENCE got SET".into(),
    ));
    assert_eq!(
        json,
        r#"{"MalformedCertificate":"expected SEQUENCE got SET"}"#,
    );
}

#[test]
fn round_trip_timeout() {
    let json = round_trip(&AiaError::Timeout);
    assert_eq!(json, r#""Timeout""#);
}

#[test]
fn round_trip_uri_unsupported() {
    let json = round_trip(&AiaError::UriUnsupported(
        "ldap://ca.example.com/cn=ca".into(),
    ));
    assert_eq!(json, r#"{"UriUnsupported":"ldap://ca.example.com/cn=ca"}"#,);
}

#[test]
fn round_trip_io_failure_connection_refused() {
    let error = AiaError::IoFailure {
        kind: ErrorKind::ConnectionRefused,
        message: "connection refused by 10.0.0.1:443".into(),
    };
    let json = round_trip(&error);
    assert_eq!(
        json,
        r#"{"IoFailure":{"kind":"ConnectionRefused","message":"connection refused by 10.0.0.1:443"}}"#,
    );
}

#[test]
fn round_trip_io_failure_timed_out() {
    let error = AiaError::IoFailure {
        kind: ErrorKind::TimedOut,
        message: "deadline exceeded after 30s".into(),
    };
    let json = round_trip(&error);
    assert_eq!(
        json,
        r#"{"IoFailure":{"kind":"TimedOut","message":"deadline exceeded after 30s"}}"#,
    );
}

#[test]
fn round_trip_io_failure_not_found() {
    let error = AiaError::IoFailure {
        kind: ErrorKind::NotFound,
        message: "DNS lookup failed: NXDOMAIN".into(),
    };
    let json = round_trip(&error);
    assert_eq!(
        json,
        r#"{"IoFailure":{"kind":"NotFound","message":"DNS lookup failed: NXDOMAIN"}}"#,
    );
}

#[test]
fn round_trip_io_failure_other() {
    let error = AiaError::IoFailure {
        kind: ErrorKind::Other,
        message: "unspecified error".into(),
    };
    let json = round_trip(&error);
    assert_eq!(
        json,
        r#"{"IoFailure":{"kind":"Other","message":"unspecified error"}}"#,
    );
}

/// Forward-compat contract for the io::ErrorKind label helper:
/// unknown labels deserialize to `Other`. Existing on-disk caches
/// produced by a future stdlib version (e.g. with a renamed variant
/// or a brand-new variant) MUST remain readable.
#[test]
fn unknown_io_error_kind_label_deserializes_as_other() {
    let json =
        r#"{"IoFailure":{"kind":"DefinitelyNotAVariant","message":"future stdlib variant"}}"#;
    let parsed: AiaError = serde_json::from_str(json).expect("deserialize");
    assert_eq!(
        parsed,
        AiaError::IoFailure {
            kind: ErrorKind::Other,
            message: "future stdlib variant".into(),
        },
    );
}

/// Bytewise stability: two equal `AiaError` values produce equal
/// JSON. This is the property cache-key replay relies on.
#[test]
fn equal_errors_produce_equal_json() {
    let a = AiaError::IoFailure {
        kind: ErrorKind::ConnectionRefused,
        message: "host unreachable".into(),
    };
    let b = AiaError::IoFailure {
        kind: ErrorKind::ConnectionRefused,
        message: "host unreachable".into(),
    };
    assert_eq!(a, b);
    assert_eq!(
        serde_json::to_string(&a).expect("a"),
        serde_json::to_string(&b).expect("b"),
    );
}
