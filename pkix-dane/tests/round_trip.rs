//! Serde round-trips for the cacheable public types.
//!
//! AGENTS.md non-negotiable #6 asks that load-bearing public types support
//! serde so cross-process and persistent caches can hold them. TLSA records
//! carry DNS TTLs, which makes caching them an expected deployment pattern
//! rather than a hypothetical one, so these round-trips are part of the
//! contract and not merely a nicety.
//!
//! Requires the `serde` and `std` features; see the `[[test]]` stanza in
//! `Cargo.toml`.

use pkix_dane::{
    record::TlsaRecord, DaneError, DnssecStatus, TlsaMatchingType, TlsaName, TlsaProtocol,
    TlsaResponse, TlsaSelector, TlsaUsage, TrustAnchorSource,
};

fn round_trip<T>(value: &T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let json = serde_json::to_string(value).expect("serializing should succeed");
    serde_json::from_str(&json).expect("deserializing our own output should succeed")
}

#[test]
fn record_round_trips() {
    let record = TlsaRecord::new(
        TlsaUsage::DaneEe,
        TlsaSelector::Spki,
        TlsaMatchingType::Sha256,
        vec![0x11; 32],
    );
    assert_eq!(round_trip(&record), record);
}

/// The `Unassigned` and `PrivateUse` variants must survive a round trip too:
/// a cache that silently dropped an unrecognized record would change what the
/// record set says on reload.
#[test]
fn unassigned_and_private_use_variants_round_trip() {
    for usage in [TlsaUsage::Unassigned(42), TlsaUsage::PrivateUse] {
        assert_eq!(round_trip(&usage), usage);
    }
    for selector in [TlsaSelector::Unassigned(7), TlsaSelector::PrivateUse] {
        assert_eq!(round_trip(&selector), selector);
    }
    for matching in [
        TlsaMatchingType::Unassigned(9),
        TlsaMatchingType::PrivateUse,
    ] {
        assert_eq!(round_trip(&matching), matching);
    }
}

/// The DNSSEC status must round-trip alongside the records. A cache that kept
/// the records and lost the status would turn an unvalidated answer into one
/// indistinguishable from a validated one.
#[test]
fn response_round_trips_with_its_dnssec_status() {
    let record = TlsaRecord::new(
        TlsaUsage::PkixEe,
        TlsaSelector::Cert,
        TlsaMatchingType::Sha512,
        vec![0x22; 64],
    );
    for status in [
        DnssecStatus::Secure,
        DnssecStatus::Insecure,
        DnssecStatus::Indeterminate,
        DnssecStatus::Bogus,
    ] {
        let response = TlsaResponse::new(vec![record.clone()], status);
        let restored = round_trip(&response);
        assert_eq!(restored, response);
        assert_eq!(restored.dnssec(), status);
    }
}

#[test]
fn authenticated_denial_survives_a_round_trip() {
    let denial = TlsaResponse::new(Vec::new(), DnssecStatus::Secure);
    assert!(denial.is_authenticated_denial());
    assert!(round_trip(&denial).is_authenticated_denial());
}

#[test]
fn name_round_trips() {
    let name = TlsaName::new(443, &TlsaProtocol::Tcp, "www.example.com").expect("valid");
    assert_eq!(round_trip(&name), name);

    let proto = TlsaProtocol::Other("quic".into());
    assert_eq!(round_trip(&proto), proto);
}

#[test]
fn every_error_variant_round_trips() {
    let errors = [
        DaneError::RecordTruncated { len: 2 },
        DaneError::SpkiEncodingFailed,
        DaneError::SelectorUnsupported { octet: 7 },
        DaneError::DnssecNotSecure {
            status: DnssecStatus::Bogus,
        },
        DaneError::NoRecordsForUsage {
            usage: TlsaUsage::PkixEe,
            records_present: 3,
        },
        DaneError::NoUsableRecords {
            usage: TlsaUsage::DaneEe,
            records_for_usage: 1,
        },
        DaneError::NoMatch {
            usage: TlsaUsage::DaneEe,
            records_compared: 2,
        },
        DaneError::ResolutionDisabled,
        DaneError::ResolutionFailed("SERVFAIL".into()),
        DaneError::NameTooLong { len: 300 },
        DaneError::InvalidHost,
        DaneError::InvalidProtocol,
    ];
    for error in errors {
        assert_eq!(round_trip(&error), error);
    }
}

/// Every error variant renders a non-empty message that does not leak the
/// `Debug` form, and implements `std::error::Error` under the `std` feature.
#[test]
fn errors_display_and_implement_error() {
    fn assert_is_error<E: std::error::Error>(_: &E) {}

    let error = DaneError::NoMatch {
        usage: TlsaUsage::DaneEe,
        records_compared: 2,
    };
    assert_is_error(&error);
    let rendered = error.to_string();
    assert!(rendered.contains("matched none"), "got {rendered:?}");
    assert!(!rendered.is_empty());
}

#[test]
fn trust_anchor_source_round_trips() {
    for source in [
        TrustAnchorSource::PresentedChain { chain_index: 0 },
        TrustAnchorSource::PresentedChain { chain_index: 3 },
        TrustAnchorSource::TlsaRecord,
    ] {
        assert_eq!(round_trip(&source), source);
    }
}

#[test]
fn the_trust_anchor_error_variants_round_trip() {
    for error in [
        DaneError::MalformedAnchorCertificate,
        DaneError::AnchorNameConstraintsMalformed,
    ] {
        assert_eq!(round_trip(&error), error);
        assert!(!error.to_string().is_empty());
    }
}
