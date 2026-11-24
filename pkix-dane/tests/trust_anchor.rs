//! The trust-anchor usages: DANE-TA (2) and PKIX-TA (0).
//!
//! These differ from the end-entity usages in matching against a *chain*
//! rather than one certificate, because the record names an issuer above the
//! leaf. The fixtures include a real CA and a certificate it issued, so the
//! distinction between "matched the leaf" and "matched the issuer" is
//! exercised rather than assumed.

mod support;

use pkix_dane::{
    matches_spki, verify_dane_ta, verify_pkix_ta, DaneError, DnssecStatus, PresentedCert,
    TlsaMatchingType, TlsaResponse, TlsaSelector, TlsaUsage, TrustAnchorSource,
};
use support::{
    digest, parse, presented, record, secure, sha256_record, CA_DER, CA_SPKI_DER, CHAIN_LEAF_DER,
    LEAF_DER,
};
use x509_cert::Certificate;

/// The `[chain-leaf, ca]` chain, leaf first, as a TLS peer would present it.
struct Chain {
    leaf: Certificate,
    ca: Certificate,
}

impl Chain {
    fn new() -> Self {
        Self {
            leaf: parse(CHAIN_LEAF_DER),
            ca: parse(CA_DER),
        }
    }

    fn full(&self) -> Vec<PresentedCert<'_>> {
        vec![
            presented(CHAIN_LEAF_DER, &self.leaf),
            presented(CA_DER, &self.ca),
        ]
    }

    /// Only the leaf — a server that sends an incomplete chain.
    fn leaf_only(&self) -> Vec<PresentedCert<'_>> {
        vec![presented(CHAIN_LEAF_DER, &self.leaf)]
    }
}

// -------------------------------------------------------------------------
// DANE-TA (usage 2)
// -------------------------------------------------------------------------

/// The ordinary case: the record names the CA, the peer sends the CA, and the
/// synthesized anchor is that CA.
#[test]
fn dane_ta_finds_the_issuer_in_the_presented_chain() {
    let chain = Chain::new();
    let response = secure(vec![sha256_record(
        TlsaUsage::DaneTa,
        TlsaSelector::Cert,
        "ca",
        "Cert",
    )]);

    let established = verify_dane_ta(&chain.full(), &response).expect("the CA should match");
    assert_eq!(
        established.source(),
        TrustAnchorSource::PresentedChain { chain_index: 1 }
    );
    assert_eq!(
        established.anchor().subject,
        *chain.ca.tbs_certificate().subject(),
        "the synthesized anchor should be the CA, not the leaf"
    );
}

/// A DANE-TA record may name the leaf itself: a server presenting a single
/// self-signed certificate is its own trust anchor. Index 0 proves the search
/// does not skip the leaf.
#[test]
fn dane_ta_accepts_a_self_anchoring_leaf() {
    let parsed = parse(LEAF_DER);
    let chain = vec![presented(LEAF_DER, &parsed)];
    let response = secure(vec![sha256_record(
        TlsaUsage::DaneTa,
        TlsaSelector::Cert,
        "leaf",
        "Cert",
    )]);

    let established = verify_dane_ta(&chain, &response).expect("the leaf should match");
    assert_eq!(
        established.source(),
        TrustAnchorSource::PresentedChain { chain_index: 0 }
    );
}

/// Selector 1 pins the CA's public key rather than its certificate, which is
/// what lets an operator reissue the CA certificate without republishing the
/// TLSA record.
#[test]
fn dane_ta_matches_the_issuer_by_spki() {
    let chain = Chain::new();
    let response = secure(vec![sha256_record(
        TlsaUsage::DaneTa,
        TlsaSelector::Spki,
        "ca",
        "Spki",
    )]);

    let established = verify_dane_ta(&chain.full(), &response).expect("the CA's SPKI should match");
    assert_eq!(
        established.source(),
        TrustAnchorSource::PresentedChain { chain_index: 1 }
    );
}

/// A `Cert`/`Full` record carries the anchor certificate in DNS, so the
/// connection can succeed even though the peer sent no issuer at all. This is
/// the case that distinguishes DANE-TA from a mere constraint on PKIX.
#[test]
fn dane_ta_uses_an_anchor_published_in_dns_when_the_chain_is_incomplete() {
    let chain = Chain::new();
    let response = secure(vec![record(
        TlsaUsage::DaneTa,
        TlsaSelector::Cert,
        TlsaMatchingType::Full,
        CA_DER.to_vec(),
    )]);

    let established =
        verify_dane_ta(&chain.leaf_only(), &response).expect("the embedded anchor should be used");
    assert_eq!(established.source(), TrustAnchorSource::TlsaRecord);
    assert_eq!(
        established.anchor().subject,
        *chain.ca.tbs_certificate().subject()
    );
}

/// When the anchor is available both ways, the peer's own chain wins. The
/// peer chose what to send; preferring DNS would make the reported source
/// misleading for operators debugging a deployment.
#[test]
fn dane_ta_prefers_the_presented_chain_over_the_embedded_anchor() {
    let chain = Chain::new();
    let response = secure(vec![record(
        TlsaUsage::DaneTa,
        TlsaSelector::Cert,
        TlsaMatchingType::Full,
        CA_DER.to_vec(),
    )]);

    let established = verify_dane_ta(&chain.full(), &response).expect("should succeed either way");
    assert_eq!(
        established.source(),
        TrustAnchorSource::PresentedChain { chain_index: 1 }
    );
}

#[test]
fn dane_ta_rejects_a_chain_the_records_do_not_name() {
    let chain = Chain::new();
    let response = secure(vec![sha256_record(
        TlsaUsage::DaneTa,
        TlsaSelector::Cert,
        "other",
        "Cert",
    )]);

    assert_eq!(
        verify_dane_ta(&chain.full(), &response),
        Err(DaneError::NoMatch {
            usage: TlsaUsage::DaneTa,
            records_compared: 1,
        })
    );
}

/// A record that claims to carry an anchor certificate and carries garbage is
/// a broken record, not a non-match. Reporting it as "no match" would leave
/// the operator debugging the wrong thing.
#[test]
fn dane_ta_reports_a_malformed_embedded_anchor_distinctly() {
    let chain = Chain::new();
    let response = secure(vec![record(
        TlsaUsage::DaneTa,
        TlsaSelector::Cert,
        TlsaMatchingType::Full,
        vec![0xde, 0xad, 0xbe, 0xef],
    )]);

    assert_eq!(
        verify_dane_ta(&chain.full(), &response),
        Err(DaneError::MalformedAnchorCertificate)
    );
}

/// A truncated certificate is still malformed — the parse must fail closed
/// rather than accept a prefix.
#[test]
fn dane_ta_rejects_a_truncated_embedded_anchor() {
    let chain = Chain::new();
    let response = secure(vec![record(
        TlsaUsage::DaneTa,
        TlsaSelector::Cert,
        TlsaMatchingType::Full,
        CA_DER[..CA_DER.len() / 2].to_vec(),
    )]);

    assert_eq!(
        verify_dane_ta(&chain.full(), &response),
        Err(DaneError::MalformedAnchorCertificate)
    );
}

/// An `Spki`/`Full` record does not carry a certificate, so it cannot supply
/// an anchor on its own. With a chain that does not match, the result is a
/// non-match rather than a malformed-anchor error: nothing claimed to be a
/// certificate.
#[test]
fn dane_ta_does_not_treat_an_spki_full_record_as_an_embedded_anchor() {
    let chain = Chain::new();
    let response = secure(vec![record(
        TlsaUsage::DaneTa,
        TlsaSelector::Spki,
        TlsaMatchingType::Full,
        CA_SPKI_DER.to_vec(),
    )]);

    // It matches the CA in the chain, so this succeeds via the chain path.
    let established = verify_dane_ta(&chain.full(), &response).expect("SPKI should match the CA");
    assert_eq!(
        established.source(),
        TrustAnchorSource::PresentedChain { chain_index: 1 }
    );

    // Without the CA in the chain there is nothing to match and no embedded
    // certificate to fall back on.
    assert_eq!(
        verify_dane_ta(&chain.leaf_only(), &response),
        Err(DaneError::NoMatch {
            usage: TlsaUsage::DaneTa,
            records_compared: 1,
        })
    );
}

#[test]
fn dane_ta_refuses_unvalidated_records() {
    let chain = Chain::new();
    let matching = sha256_record(TlsaUsage::DaneTa, TlsaSelector::Cert, "ca", "Cert");

    for status in [
        DnssecStatus::Insecure,
        DnssecStatus::Indeterminate,
        DnssecStatus::Bogus,
    ] {
        let response = TlsaResponse::new(vec![matching.clone()], status);
        assert_eq!(
            verify_dane_ta(&chain.full(), &response),
            Err(DaneError::DnssecNotSecure { status })
        );
    }
}

#[test]
fn dane_ta_reports_the_record_that_established_the_anchor() {
    let chain = Chain::new();
    let expected = sha256_record(TlsaUsage::DaneTa, TlsaSelector::Cert, "ca", "Cert");
    let response = secure(vec![
        sha256_record(TlsaUsage::DaneTa, TlsaSelector::Cert, "other", "Cert"),
        expected.clone(),
    ]);

    let established = verify_dane_ta(&chain.full(), &response).expect("the second record matches");
    assert_eq!(established.record(), &expected);
}

/// `into_anchor` is how a caller hands the anchor to path validation by value.
#[test]
fn into_anchor_yields_the_same_anchor() {
    let chain = Chain::new();
    let response = secure(vec![sha256_record(
        TlsaUsage::DaneTa,
        TlsaSelector::Cert,
        "ca",
        "Cert",
    )]);

    let established = verify_dane_ta(&chain.full(), &response).expect("should match");
    let borrowed = established.anchor().clone();
    assert_eq!(established.into_anchor(), borrowed);
}

// -------------------------------------------------------------------------
// PKIX-TA (usage 0)
// -------------------------------------------------------------------------

#[test]
fn pkix_ta_matches_the_issuer_in_the_chain() {
    let chain = Chain::new();
    let expected = sha256_record(TlsaUsage::PkixTa, TlsaSelector::Cert, "ca", "Cert");
    let response = secure(vec![expected.clone()]);

    assert_eq!(
        verify_pkix_ta(&chain.full(), &response).expect("the CA should match"),
        &expected
    );
}

#[test]
fn pkix_ta_matches_the_issuer_by_spki() {
    let chain = Chain::new();
    let response = secure(vec![sha256_record(
        TlsaUsage::PkixTa,
        TlsaSelector::Spki,
        "ca",
        "Spki",
    )]);

    assert!(verify_pkix_ta(&chain.full(), &response).is_ok());
}

/// PKIX-TA never supplies an anchor, so an anchor published only in DNS does
/// not help: with the CA absent from the chain there is nothing to match.
/// This is the structural difference from DANE-TA.
#[test]
fn pkix_ta_does_not_accept_an_anchor_published_only_in_dns() {
    let chain = Chain::new();
    let response = secure(vec![record(
        TlsaUsage::PkixTa,
        TlsaSelector::Cert,
        TlsaMatchingType::Full,
        CA_DER.to_vec(),
    )]);

    assert_eq!(
        verify_pkix_ta(&chain.leaf_only(), &response),
        Err(DaneError::NoMatch {
            usage: TlsaUsage::PkixTa,
            records_compared: 1,
        })
    );
}

/// The two trust-anchor usages are not interchangeable either.
#[test]
fn trust_anchor_usages_do_not_substitute_for_one_another() {
    let chain = Chain::new();
    let dane_ta = secure(vec![sha256_record(
        TlsaUsage::DaneTa,
        TlsaSelector::Cert,
        "ca",
        "Cert",
    )]);

    assert!(verify_dane_ta(&chain.full(), &dane_ta).is_ok());
    assert_eq!(
        verify_pkix_ta(&chain.full(), &dane_ta),
        Err(DaneError::NoRecordsForUsage {
            usage: TlsaUsage::PkixTa,
            records_present: 1,
        })
    );
}

#[test]
fn pkix_ta_refuses_unvalidated_records() {
    let chain = Chain::new();
    let matching = sha256_record(TlsaUsage::PkixTa, TlsaSelector::Cert, "ca", "Cert");

    for status in [
        DnssecStatus::Insecure,
        DnssecStatus::Indeterminate,
        DnssecStatus::Bogus,
    ] {
        let response = TlsaResponse::new(vec![matching.clone()], status);
        assert_eq!(
            verify_pkix_ta(&chain.full(), &response),
            Err(DaneError::DnssecNotSecure { status })
        );
    }
}

#[test]
fn trust_anchor_usages_distinguish_unusable_from_absent() {
    let chain = Chain::new();

    // Wrong digest length for the matching type: usable() is false, so the
    // record is present but cannot be evaluated.
    let unusable = |usage| {
        secure(vec![record(
            usage,
            TlsaSelector::Cert,
            TlsaMatchingType::Sha256,
            vec![0x00; 7],
        )])
    };

    assert_eq!(
        verify_dane_ta(&chain.full(), &unusable(TlsaUsage::DaneTa)).unwrap_err(),
        DaneError::NoUsableRecords {
            usage: TlsaUsage::DaneTa,
            records_for_usage: 1,
        }
    );
    assert_eq!(
        verify_pkix_ta(&chain.full(), &unusable(TlsaUsage::PkixTa)).unwrap_err(),
        DaneError::NoUsableRecords {
            usage: TlsaUsage::PkixTa,
            records_for_usage: 1,
        }
    );

    // And an empty set is "absent", which is a different error.
    assert_eq!(
        verify_dane_ta(&chain.full(), &secure(Vec::new())).unwrap_err(),
        DaneError::NoRecordsForUsage {
            usage: TlsaUsage::DaneTa,
            records_present: 0,
        }
    );
}

/// The chain fixtures must be a real issuer relationship, or the tests above
/// do not exercise what they claim to.
#[test]
fn chain_fixtures_are_a_real_issuer_relationship() {
    let chain = Chain::new();
    assert_eq!(
        chain.leaf.tbs_certificate().issuer(),
        chain.ca.tbs_certificate().subject(),
        "chain-leaf should be issued by ca"
    );
    assert_ne!(
        chain.leaf.tbs_certificate().subject(),
        chain.ca.tbs_certificate().subject()
    );
    assert_ne!(CHAIN_LEAF_DER, CA_DER);
    assert_eq!(
        digest("ca", "Spki", "sha256").len(),
        32,
        "the manifest should carry the CA's SPKI digest"
    );
    assert_eq!(CA_SPKI_DER.len(), 91, "P-256 SPKI is 91 DER octets");
}

// -------------------------------------------------------------------------
// matches_spki — anchors held as keys rather than certificates
// -------------------------------------------------------------------------

/// A selector-1 record matches an anchor held only as a public key, which is
/// the shape `pkix_path::TrustAnchor` stores. Without this, usage 0 would be
/// unusable against the workspace's own trust-anchor type.
#[test]
fn matches_spki_evaluates_a_selector_one_record_against_a_bare_key() {
    let record = sha256_record(TlsaUsage::PkixTa, TlsaSelector::Spki, "ca", "Spki");
    assert!(matches_spki(&record, CA_SPKI_DER).expect("should not error"));

    // The CA's record must not match a different key.
    assert!(!matches_spki(&record, support::LEAF_SPKI_DER).expect("should not error"));
}

/// Matching type `Full` works the same way against a bare key.
#[test]
fn matches_spki_handles_full_matching() {
    let record = record(
        TlsaUsage::PkixTa,
        TlsaSelector::Spki,
        TlsaMatchingType::Full,
        CA_SPKI_DER.to_vec(),
    );
    assert!(matches_spki(&record, CA_SPKI_DER).expect("should not error"));
    assert!(!matches_spki(&record, support::LEAF_SPKI_DER).expect("should not error"));
}

/// A selector-0 record is genuinely unmatchable against a bare key: the
/// certificate's octets are gone, so the published digest cannot be
/// reproduced. Reported as a non-match rather than an invented answer.
#[test]
fn matches_spki_declines_selector_zero_records() {
    let record = sha256_record(TlsaUsage::PkixTa, TlsaSelector::Cert, "ca", "Cert");
    assert!(
        !matches_spki(&record, CA_SPKI_DER).expect("should not error"),
        "a Cert-selector record cannot be evaluated against a bare SPKI"
    );
}

/// Unusable records are skipped here too, consistent with `matches()`.
#[test]
fn matches_spki_skips_unusable_records() {
    let wrong_length = record(
        TlsaUsage::PkixTa,
        TlsaSelector::Spki,
        TlsaMatchingType::Sha256,
        vec![0x00; 7],
    );
    assert!(!matches_spki(&wrong_length, CA_SPKI_DER).expect("should not error"));

    let unassigned = record(
        TlsaUsage::PkixTa,
        TlsaSelector::Spki,
        TlsaMatchingType::Unassigned(9),
        digest("ca", "Spki", "sha256"),
    );
    assert!(!matches_spki(&unassigned, CA_SPKI_DER).expect("should not error"));
}

/// `matches_spki` and `matches` must agree where both apply: a selector-1
/// record evaluated against a certificate and against that certificate's own
/// SPKI is the same question asked two ways.
#[test]
fn matches_spki_agrees_with_matches_on_selector_one() {
    let chain = Chain::new();
    let presented_ca = presented(CA_DER, &chain.ca);

    for alg_record in [
        sha256_record(TlsaUsage::PkixTa, TlsaSelector::Spki, "ca", "Spki"),
        record(
            TlsaUsage::PkixTa,
            TlsaSelector::Spki,
            TlsaMatchingType::Sha512,
            digest("ca", "Spki", "sha512"),
        ),
        record(
            TlsaUsage::PkixTa,
            TlsaSelector::Spki,
            TlsaMatchingType::Full,
            CA_SPKI_DER.to_vec(),
        ),
    ] {
        assert_eq!(
            pkix_dane::matches(&alg_record, &presented_ca).expect("should not error"),
            matches_spki(&alg_record, CA_SPKI_DER).expect("should not error"),
            "the two entry points disagree for {:?}",
            alg_record.matching_type()
        );
    }
}
