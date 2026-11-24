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
fn round_trip_io_failure() {
    // IoFailure carries one diagnostic string. It previously carried a
    // `kind: std::io::ErrorKind` too, which needed a bespoke serde helper
    // because ErrorKind does not derive Serialize upstream; folding the kind
    // into the message removed that helper and the crate's std feature with
    // it. See AiaError::IoFailure.
    for message in [
        "connection refused by 10.0.0.1:443",
        "deadline exceeded after 30s",
        "DNS lookup failed: NXDOMAIN",
        // The one adapter site that had a real io::ErrorKind renders it into
        // the message, so this is the shape that now reaches a log.
        "ConnectionRefused: connection refused",
    ] {
        let error = AiaError::IoFailure(message.into());
        let json = round_trip(&error);
        assert_eq!(json, format!(r#"{{"IoFailure":"{message}"}}"#));
    }
}

/// The ErrorKind label helper this test used to guard is gone along with
/// the field it served. What remains worth asserting is that the variant's
/// wire form is a bare string, so there is no bespoke representation left to
/// break.
#[test]
fn io_failure_wire_form_is_a_bare_string() {
    let json = r#"{"IoFailure":"anything at all"}"#;
    let parsed: AiaError = serde_json::from_str(json).expect("deserialize");
    assert_eq!(parsed, AiaError::IoFailure("anything at all".into()));
}

/// Bytewise stability: two equal `AiaError` values produce equal
/// JSON. This is the property cache-key replay relies on.
#[test]
fn equal_errors_produce_equal_json() {
    let a = AiaError::IoFailure("host unreachable".into());
    let b = AiaError::IoFailure("host unreachable".into());
    assert_eq!(a, b);
    assert_eq!(
        serde_json::to_string(&a).expect("a"),
        serde_json::to_string(&b).expect("b"),
    );
}
