//! TLSA matching and the end-entity usages, against digests computed by
//! OpenSSL.
//!
//! Expected digests come from `fixtures/digests.txt`, which `fixtures/gen.sh`
//! writes from `openssl dgst`. OpenSSL is the right oracle here: it is what
//! domain operators actually use to produce the association data they publish,
//! so agreeing with it is the interoperability property that matters. A test
//! that computed its expectation with this crate's own `sha2` calls would
//! prove only self-consistency.

mod support;

use pkix_dane::{
    matches, matching_records, verify_dane_ee, verify_pkix_ee, DaneError, DnssecStatus,
    NoTlsaResolver, TlsaMatchingType, TlsaName, TlsaProtocol, TlsaResolver, TlsaResponse,
    TlsaSelector, TlsaUsage,
};
use support::{
    digest, parse, presented, record, secure, sha256_record, LEAF_DER, LEAF_SPKI_DER, OTHER_DER,
};

// -------------------------------------------------------------------------
// Selector extraction
// -------------------------------------------------------------------------

/// The `Spki` selector re-encodes the `SubjectPublicKeyInfo`, which is sound
/// only if the re-encoding reproduces the original octets. This checks that
/// claim against the SPKI OpenSSL extracted from the same certificate, so the
/// caveat documented on `selected_content` is verified rather than asserted.
#[test]
fn spki_selector_reproduces_openssl_spki_der() {
    let parsed = parse(LEAF_DER);
    let extracted = presented(LEAF_DER, &parsed)
        .selected_content(TlsaSelector::Spki)
        .expect("the fixture's SPKI should encode");
    assert_eq!(extracted.as_ref(), LEAF_SPKI_DER);
}

/// The `Cert` selector must hand back the received octets unchanged, with no
/// round trip through the parsed certificate.
#[test]
fn cert_selector_returns_received_octets_verbatim() {
    let parsed = parse(LEAF_DER);
    let extracted = presented(LEAF_DER, &parsed)
        .selected_content(TlsaSelector::Cert)
        .expect("the Cert selector cannot fail");
    assert_eq!(extracted.as_ref(), LEAF_DER);
}

#[test]
fn unassigned_selector_is_unsupported() {
    let parsed = parse(LEAF_DER);
    assert_eq!(
        presented(LEAF_DER, &parsed).selected_content(TlsaSelector::Unassigned(7)),
        Err(DaneError::SelectorUnsupported { octet: 7 })
    );
}

// -------------------------------------------------------------------------
// Matching against OpenSSL digests
// -------------------------------------------------------------------------

#[test]
fn matches_openssl_digests_for_every_assigned_combination() {
    let parsed = parse(LEAF_DER);
    let cert = presented(LEAF_DER, &parsed);

    for (selector, selector_name) in [(TlsaSelector::Cert, "Cert"), (TlsaSelector::Spki, "Spki")] {
        for (matching_type, alg) in [
            (TlsaMatchingType::Sha256, "sha256"),
            (TlsaMatchingType::Sha512, "sha512"),
        ] {
            let rec = record(
                TlsaUsage::DaneEe,
                selector,
                matching_type,
                digest("leaf", selector_name, alg),
            );
            assert!(
                matches(&rec, &cert).expect("matching should not error"),
                "expected a match for {selector:?} / {matching_type:?}"
            );
        }
    }
}

/// Matching type `Full` compares the selected content itself rather than a
/// digest, so the association data is the whole certificate.
#[test]
fn full_matching_type_compares_content_verbatim() {
    let parsed = parse(LEAF_DER);
    let cert = presented(LEAF_DER, &parsed);

    for (selector, content) in [
        (TlsaSelector::Cert, LEAF_DER),
        (TlsaSelector::Spki, LEAF_SPKI_DER),
    ] {
        let rec = record(
            TlsaUsage::DaneEe,
            selector,
            TlsaMatchingType::Full,
            content.to_vec(),
        );
        assert!(
            matches(&rec, &cert).expect("matching should not error"),
            "Full should match verbatim content for {selector:?}"
        );
    }
}

/// A different certificate's digest must not match, for either selector.
/// Without this, a matcher that ignored its input entirely would pass every
/// other test in this file.
#[test]
fn another_certificates_digests_do_not_match() {
    let parsed = parse(LEAF_DER);
    let cert = presented(LEAF_DER, &parsed);

    for (selector, selector_name) in [(TlsaSelector::Cert, "Cert"), (TlsaSelector::Spki, "Spki")] {
        let rec = sha256_record(TlsaUsage::DaneEe, selector, "other", selector_name);
        assert!(
            !matches(&rec, &cert).expect("matching should not error"),
            "{selector:?} must not match a different certificate"
        );
    }
}

/// The two fixtures must actually differ, or the negative tests above are
/// vacuous.
#[test]
fn fixtures_are_distinct() {
    assert_ne!(LEAF_DER, OTHER_DER);
    let leaf_parsed = parse(LEAF_DER);
    let other_parsed = parse(OTHER_DER);
    let leaf_spki = presented(LEAF_DER, &leaf_parsed)
        .selected_content(TlsaSelector::Spki)
        .expect("SPKI should encode");
    let other_spki = presented(OTHER_DER, &other_parsed)
        .selected_content(TlsaSelector::Spki)
        .expect("SPKI should encode");
    assert_ne!(leaf_spki, other_spki);
}

#[test]
fn matching_records_reports_each_match() {
    let parsed = parse(LEAF_DER);
    let cert = presented(LEAF_DER, &parsed);

    let records = vec![
        sha256_record(TlsaUsage::DaneEe, TlsaSelector::Cert, "other", "Cert"),
        sha256_record(TlsaUsage::DaneEe, TlsaSelector::Cert, "leaf", "Cert"),
        sha256_record(TlsaUsage::DaneEe, TlsaSelector::Spki, "leaf", "Spki"),
    ];

    let matched = matching_records(&records, &cert).expect("matching should not error");
    assert_eq!(matched.len(), 2);
    assert_eq!(matched[0], &records[1]);
    assert_eq!(matched[1], &records[2]);
}

// -------------------------------------------------------------------------
// Unusable records are skipped, not fatal
// -------------------------------------------------------------------------

/// RFC 7671 §17: a record whose parameters the client does not recognize is
/// unusable and must be skipped. A set holding unrecognized records and one
/// good one must still authenticate — this is the forward-compatibility
/// property that lets a domain publish a future usage alongside a current one.
#[test]
fn unrecognized_record_is_skipped_so_a_sibling_can_match() {
    let parsed = parse(LEAF_DER);
    let cert = presented(LEAF_DER, &parsed);
    let good = digest("leaf", "Cert", "sha256");

    let response = secure(vec![
        record(
            TlsaUsage::DaneEe,
            TlsaSelector::Unassigned(9),
            TlsaMatchingType::Sha256,
            good.clone(),
        ),
        record(
            TlsaUsage::DaneEe,
            TlsaSelector::Cert,
            TlsaMatchingType::Unassigned(9),
            good.clone(),
        ),
        record(
            TlsaUsage::DaneEe,
            TlsaSelector::Cert,
            TlsaMatchingType::Sha256,
            good,
        ),
    ]);

    let matched = verify_dane_ee(&cert, &response).expect("the third record should match");
    assert_eq!(matched.selector(), TlsaSelector::Cert);
    assert_eq!(matched.matching_type(), TlsaMatchingType::Sha256);
}

/// RFC 7671 §10: a digest matching type whose association data is the wrong
/// length is unusable. A truncated SHA-256 must not match by prefix.
#[test]
fn wrong_length_digest_is_unusable_not_a_prefix_match() {
    let parsed = parse(LEAF_DER);
    let cert = presented(LEAF_DER, &parsed);

    let mut truncated = digest("leaf", "Cert", "sha256");
    truncated.truncate(16);

    let mut overlong = digest("leaf", "Cert", "sha256");
    overlong.push(0x00);

    for data in [truncated, overlong] {
        let rec = record(
            TlsaUsage::DaneEe,
            TlsaSelector::Cert,
            TlsaMatchingType::Sha256,
            data,
        );
        assert!(!rec.is_usable());
        assert!(!matches(&rec, &cert).expect("matching should not error"));
    }
}

#[test]
fn empty_association_data_is_unusable() {
    let rec = record(
        TlsaUsage::DaneEe,
        TlsaSelector::Cert,
        TlsaMatchingType::Full,
        Vec::new(),
    );
    assert!(!rec.is_usable());
}

// -------------------------------------------------------------------------
// verify_dane_ee / verify_pkix_ee
// -------------------------------------------------------------------------

#[test]
fn dane_ee_matches_and_returns_the_authorizing_record() {
    let parsed = parse(LEAF_DER);
    let cert = presented(LEAF_DER, &parsed);
    let expected = sha256_record(TlsaUsage::DaneEe, TlsaSelector::Spki, "leaf", "Spki");
    let response = secure(vec![expected.clone()]);

    assert_eq!(
        verify_dane_ee(&cert, &response).expect("should match"),
        &expected
    );
}

#[test]
fn dane_ee_rejects_a_certificate_the_records_do_not_name() {
    let parsed = parse(OTHER_DER);
    let cert = presented(OTHER_DER, &parsed);
    let response = secure(vec![sha256_record(
        TlsaUsage::DaneEe,
        TlsaSelector::Cert,
        "leaf",
        "Cert",
    )]);

    assert_eq!(
        verify_dane_ee(&cert, &response),
        Err(DaneError::NoMatch {
            usage: TlsaUsage::DaneEe,
            records_compared: 1,
        })
    );
}

/// Usage is not interchangeable: a usage-3 record must not satisfy a usage-1
/// check. Conflating them would let a DANE-EE record silently waive the PKIX
/// path validation that PKIX-EE requires.
#[test]
fn usages_do_not_substitute_for_one_another() {
    let parsed = parse(LEAF_DER);
    let cert = presented(LEAF_DER, &parsed);
    let response = secure(vec![sha256_record(
        TlsaUsage::DaneEe,
        TlsaSelector::Cert,
        "leaf",
        "Cert",
    )]);

    assert!(verify_dane_ee(&cert, &response).is_ok());
    assert_eq!(
        verify_pkix_ee(&cert, &response),
        Err(DaneError::NoRecordsForUsage {
            usage: TlsaUsage::PkixEe,
            records_present: 1,
        })
    );
}

#[test]
fn pkix_ee_matches_its_own_usage() {
    let parsed = parse(LEAF_DER);
    let cert = presented(LEAF_DER, &parsed);
    let expected = sha256_record(TlsaUsage::PkixEe, TlsaSelector::Cert, "leaf", "Cert");
    let response = secure(vec![expected.clone()]);

    assert_eq!(
        verify_pkix_ee(&cert, &response).expect("should match"),
        &expected
    );
}

#[test]
fn all_records_unusable_is_distinguished_from_no_match() {
    let parsed = parse(LEAF_DER);
    let cert = presented(LEAF_DER, &parsed);
    let response = secure(vec![record(
        TlsaUsage::DaneEe,
        TlsaSelector::Cert,
        TlsaMatchingType::Unassigned(200),
        digest("leaf", "Cert", "sha256"),
    )]);

    assert_eq!(
        verify_dane_ee(&cert, &response),
        Err(DaneError::NoUsableRecords {
            usage: TlsaUsage::DaneEe,
            records_for_usage: 1,
        })
    );
}

/// The DNSSEC check must come before matching: records that were not
/// validated cannot authenticate anything, however well they match.
#[test]
fn unvalidated_records_are_refused_even_when_they_match() {
    let parsed = parse(LEAF_DER);
    let cert = presented(LEAF_DER, &parsed);
    let matching = sha256_record(TlsaUsage::DaneEe, TlsaSelector::Cert, "leaf", "Cert");

    for status in [
        DnssecStatus::Insecure,
        DnssecStatus::Indeterminate,
        DnssecStatus::Bogus,
    ] {
        let response = TlsaResponse::new(vec![matching.clone()], status);
        assert_eq!(
            verify_dane_ee(&cert, &response),
            Err(DaneError::DnssecNotSecure { status }),
            "status {status:?} must not authenticate"
        );
    }
}

// -------------------------------------------------------------------------
// DnssecStatus policy surface
// -------------------------------------------------------------------------

/// Bogus is the status that must not permit PKIX fallback: treating a broken
/// signature as "no DANE" would let an attacker strip DANE by corrupting the
/// answer.
#[test]
fn only_bogus_forbids_pkix_fallback() {
    assert!(DnssecStatus::Insecure.permits_pkix_fallback());
    assert!(DnssecStatus::Indeterminate.permits_pkix_fallback());
    assert!(!DnssecStatus::Bogus.permits_pkix_fallback());
    assert!(!DnssecStatus::Secure.permits_pkix_fallback());

    assert!(DnssecStatus::Secure.is_secure());
    for status in [
        DnssecStatus::Insecure,
        DnssecStatus::Indeterminate,
        DnssecStatus::Bogus,
    ] {
        assert!(!status.is_secure());
    }
}

/// A secure response with no records is a signed statement that the domain
/// publishes no TLSA record — different from an unsigned answer, and different
/// from a lookup failure.
#[test]
fn authenticated_denial_is_only_a_secure_empty_response() {
    assert!(secure(Vec::new()).is_authenticated_denial());
    assert!(!TlsaResponse::new(Vec::new(), DnssecStatus::Insecure).is_authenticated_denial());
    assert!(!TlsaResponse::new(Vec::new(), DnssecStatus::Bogus).is_authenticated_denial());

    let with_record = secure(vec![sha256_record(
        TlsaUsage::DaneEe,
        TlsaSelector::Cert,
        "leaf",
        "Cert",
    )]);
    assert!(!with_record.is_authenticated_denial());
    assert!(with_record.has_usable_record());
}

#[test]
fn records_for_usage_filters_without_regard_to_usability() {
    let response = secure(vec![
        sha256_record(TlsaUsage::DaneEe, TlsaSelector::Cert, "leaf", "Cert"),
        sha256_record(TlsaUsage::PkixEe, TlsaSelector::Cert, "leaf", "Cert"),
        record(
            TlsaUsage::DaneEe,
            TlsaSelector::Unassigned(9),
            TlsaMatchingType::Sha256,
            digest("leaf", "Cert", "sha256"),
        ),
    ]);

    assert_eq!(response.records_for_usage(TlsaUsage::DaneEe).len(), 2);
    assert_eq!(response.records_for_usage(TlsaUsage::PkixEe).len(), 1);
    assert_eq!(response.records_for_usage(TlsaUsage::DaneTa).len(), 0);
}

// -------------------------------------------------------------------------
// NoTlsaResolver
// -------------------------------------------------------------------------

#[test]
fn no_tlsa_resolver_reports_disabled_rather_than_failure() {
    let name = TlsaName::new(443, &TlsaProtocol::Tcp, "example.com").expect("valid name");
    assert_eq!(
        NoTlsaResolver.resolve(&name),
        Err(DaneError::ResolutionDisabled)
    );

    let batch = NoTlsaResolver.batch_resolve(&[name.clone(), name]);
    assert_eq!(batch.len(), 2);
    assert!(batch
        .iter()
        .all(|r| r == &Err(DaneError::ResolutionDisabled)));
}
