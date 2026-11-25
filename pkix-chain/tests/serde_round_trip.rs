//! Round-trip tests for `pkix-chain`'s serde feature.
//!
//! `pkix-chain::Error` wraps `pkix_path::Error`, `pkix_revocation::Error`,
//! and `pkix_identity::IdentityError`; each of those is independently
//! tested under its own crate's `tests/serde_round_trip.rs`. This file
//! exercises only:
//!
//! * The `Path` / `Revocation` / `Identity` wrapper variants forward
//!   correctly through serde.
//! * The `ProfileViolation` / `OcspDelegation` variants preserve their
//!   `Cow<'static, str>` reason field across serialize → deserialize.
//!
//! Run with: `cargo test -p pkix-chain --features serde --test serde_round_trip`

#![cfg(feature = "serde")]

use pkix_chain::{Error, OcspDelegationKind, ProfileViolationKind};
use pkix_identity::IdentityError;

/// `Error::Identity` round-trips, preserving the inner `IdentityError`
/// variant identity.
#[test]
fn error_identity_round_trips() {
    let cases = [
        IdentityError::MissingSan,
        IdentityError::MalformedSan,
        IdentityError::MalformedInput,
        IdentityError::NoMatchingSan,
    ];
    for inner in cases {
        let err = Error::Identity(inner.clone());
        let json = serde_json::to_string(&err).expect("serialize");
        let back: Error = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, back);
    }
}

/// `Error::Path` forwards a `pkix_path::Error` through serde. Only one
/// variant exercised here; full coverage lives in pkix-path's own
/// round-trip suite.
#[test]
fn error_path_forwards_inner_serde() {
    let inner = pkix_path::Error::NoTrustedPath;
    let err = Error::Path(inner);
    let json = serde_json::to_string(&err).expect("serialize");
    let back: Error = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, back);
    assert!(matches!(back, Error::Path(pkix_path::Error::NoTrustedPath)));
}

/// `Error::Revocation` forwards a `pkix_revocation::Error` through
/// serde. Coverage parity with the previous test for the path wrapper.
#[test]
fn error_revocation_forwards_inner_serde() {
    let inner = pkix_revocation::Error::CrlSignatureInvalid;
    let err = Error::Revocation(inner);
    let json = serde_json::to_string(&err).expect("serialize");
    let back: Error = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, back);
    assert!(matches!(
        back,
        Error::Revocation(pkix_revocation::Error::CrlSignatureInvalid)
    ));
}

/// `Error::ProfileViolation` and `Error::OcspDelegation` preserve their
/// typed kind through serde.
///
/// These used to carry a `Cow<'static, str>` and this test turned on
/// `Cow`'s content-based equality surviving the `Borrowed` to `Owned`
/// transition. The payload is now an enum, so the round trip is an
/// ordinary one and the kind comes back the kind it went in as — which
/// is the point: a caller caching one of these recovers something it can
/// still match on.
///
/// Every kind is covered rather than one sample, since the whole value of
/// the change is that the kinds are distinguishable.
#[test]
fn profile_violation_and_ocsp_delegation_preserve_their_kind() {
    let profile = [
        ProfileViolationKind::TsaEkuMissing,
        ProfileViolationKind::TsaEkuNotCritical,
        ProfileViolationKind::TsaEkuMalformed,
        ProfileViolationKind::TsaEkuNotSoleTimeStamping,
        ProfileViolationKind::TsaKeyUsageMalformed,
        ProfileViolationKind::TsaKeyUsageNotSigningOnly,
    ];
    let delegation = [
        OcspDelegationKind::EmptyChain,
        OcspDelegationKind::IssuerDnMismatch,
        OcspDelegationKind::TbsReencodeFailed,
        OcspDelegationKind::SignatureNotVerified,
    ];

    let cases: Vec<Error> = profile
        .iter()
        .copied()
        .map(Error::profile_violation)
        .chain(delegation.iter().copied().map(Error::ocsp_delegation))
        .collect();

    for err in cases {
        let json = serde_json::to_string(&err).expect("serialize");
        let back: Error = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, back, "round trip changed the error: {json}");
        assert_eq!(format!("{err}"), format!("{back}"));
    }

    // Distinct kinds must not collapse to the same wire form, or caching
    // one and reloading it would silently lose the classification.
    let mut wire: Vec<String> = profile
        .iter()
        .copied()
        .map(Error::profile_violation)
        .map(|e| serde_json::to_string(&e).expect("serialize"))
        .collect();
    wire.sort_unstable();
    let before = wire.len();
    wire.dedup();
    assert_eq!(before, wire.len(), "two kinds share a wire form: {wire:?}");
}

/// Hand-written expected JSON for `Error::ProfileViolation`. Acts as an
/// independent oracle on the wire form: externally tagged, with the kind
/// as a nested name rather than a prose string.
#[test]
fn profile_violation_wire_form_is_externally_tagged() {
    let err = Error::profile_violation(ProfileViolationKind::TsaEkuNotCritical);
    let json = serde_json::to_string(&err).expect("serialize");
    assert_eq!(json, r#"{"ProfileViolation":{"kind":"TsaEkuNotCritical"}}"#);
}

/// `Error::Aia` forwards a `pkix_aia::AiaError` through serde. Variant
/// coverage parity with the `Path` / `Revocation` / `Identity` wrapper
/// tests above. The companion `pkix_aia` crate exercises full per-variant
/// coverage in its own round-trip suite.
#[test]
fn error_aia_forwards_inner_serde() {
    let inner = pkix_aia::AiaError::FetchingDisabled;
    let err = Error::Aia(inner);
    let json = serde_json::to_string(&err).expect("serialize");
    let back: Error = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, back);
    assert!(matches!(
        back,
        Error::Aia(pkix_aia::AiaError::FetchingDisabled)
    ));
}

/// `Error::PathBuild` forwards a `pkix_path_builder::Error` through
/// serde. Coverage parity with the wrapper tests.
#[test]
fn error_path_build_forwards_inner_serde() {
    let inner = pkix_path_builder::Error::NoPathFound;
    let err = Error::PathBuild(inner);
    let json = serde_json::to_string(&err).expect("serialize");
    let back: Error = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, back);
    assert!(matches!(
        back,
        Error::PathBuild(pkix_path_builder::Error::NoPathFound)
    ));
}

/// `Error::AiaDepthExceeded` is a unit variant; round-trip is a sanity
/// check that no payload requirements were missed.
#[test]
fn error_aia_depth_exceeded_round_trips() {
    let err = Error::AiaDepthExceeded;
    let json = serde_json::to_string(&err).expect("serialize");
    let back: Error = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, back);
    assert_eq!(json, r#""AiaDepthExceeded""#);
}
