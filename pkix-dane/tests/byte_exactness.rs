//! Regression tests for the rule that TLSA matching hashes received octets.
//!
//! The `Cert` selector compares against a digest the domain operator computed
//! over their certificate file. Reproducing that digest requires hashing the
//! same octets — not an equivalent certificate, the same octets. `x509-cert`
//! 0.3 re-encodes a parsed `Certificate` under the RFC 5280 profile, which
//! normalizes a validity date before 2050 from `GeneralizedTime` to `UTCTime`.
//! For such a certificate, `to_der()` on the parsed value therefore does not
//! round-trip.
//!
//! The `gentime-leaf` fixture is such a certificate, built by
//! `fixtures/gen_gentime.py` because OpenSSL will not emit one. These tests
//! first establish that the hazard is real for this fixture, then show that
//! matching succeeds over the received bytes — so a future change back to
//! re-encoding fails here rather than in a deployment against whichever CAs
//! happen to emit `GeneralizedTime` early.

mod support;

use pkix_dane::{matches, verify_dane_ee, TlsaMatchingType, TlsaSelector, TlsaUsage};
use support::{digest, parse, presented, record, secure, sha256_record, LEAF_DER};
use x509_cert::der::Encode as _;

const GENTIME_DER: &[u8] = include_bytes!("fixtures/gentime-leaf.der");
const GENTIME_SPKI_DER: &[u8] = include_bytes!("fixtures/gentime-leaf.spki.der");

/// The fixture must actually carry `GeneralizedTime` validity fields with
/// pre-2050 dates, or everything below is vacuous.
///
/// Checked structurally rather than through an accessor: tag `0x18` is
/// `GeneralizedTime` and `0x17` is `UTCTime`, and the fixture is built by
/// rewriting the former into the latter's place.
#[test]
fn the_fixture_really_carries_generalized_time() {
    // Validity ::= SEQUENCE { notBefore Time, notAfter Time }, and the only
    // 15-octet GeneralizedTime values in this certificate are those two.
    let gentime_fields = GENTIME_DER
        .windows(2)
        .filter(|w| w[0] == 0x18 && w[1] == 15)
        .count();
    assert_eq!(
        gentime_fields, 2,
        "fixture should hold two 15-octet GeneralizedTime fields; \
         rerun fixtures/gen.sh"
    );
    assert!(
        !GENTIME_DER.windows(2).any(|w| w[0] == 0x17 && w[1] == 13),
        "fixture should hold no UTCTime validity field left"
    );

    // The dates are before 2050, which is what makes x509-cert normalize
    // them. The ASCII year sits immediately after the tag and length.
    let year_positions: Vec<usize> = (0..GENTIME_DER.len() - 2)
        .filter(|&i| GENTIME_DER[i] == 0x18 && GENTIME_DER[i + 1] == 15)
        .map(|i| i + 2)
        .collect();
    for pos in year_positions {
        let year: u32 = core::str::from_utf8(&GENTIME_DER[pos..pos + 4])
            .expect("a GeneralizedTime year should be ASCII")
            .parse()
            .expect("a GeneralizedTime year should be four digits");
        assert!(
            year < 2050,
            "the hazard only applies to pre-2050 dates; got {year}"
        );
    }
}

/// The hazard itself: re-encoding this parsed certificate does **not**
/// reproduce the received bytes.
///
/// If this test ever starts failing because the two are equal, `x509-cert` has
/// stopped normalizing and the byte-exactness rule has lost this particular
/// justification. It would still be the right rule — hashing what you received
/// is correct regardless — but this fixture would no longer demonstrate why,
/// and the comment in `selector.rs` would need revisiting.
#[test]
fn re_encoding_does_not_round_trip_this_certificate() {
    let parsed = parse(GENTIME_DER);
    let re_encoded = parsed.to_der().expect("a parsed certificate should encode");

    assert_ne!(
        re_encoded.as_slice(),
        GENTIME_DER,
        "x509-cert is expected to normalize pre-2050 GeneralizedTime to UTCTime; \
         if it no longer does, see this test's documentation"
    );
    // The normalization shortens each of the two time fields by 2 octets.
    assert_eq!(
        GENTIME_DER.len() - re_encoded.len(),
        4,
        "two GeneralizedTime fields should shrink by 2 octets each"
    );
}

/// For an ordinary certificate the re-encode *does* round-trip, which is why
/// the hazard is easy to miss: it shows up only against the subset of
/// certificates that use `GeneralizedTime` early.
#[test]
fn re_encoding_does_round_trip_an_ordinary_certificate() {
    let parsed = parse(LEAF_DER);
    let re_encoded = parsed.to_der().expect("a parsed certificate should encode");
    assert_eq!(re_encoded.as_slice(), LEAF_DER);
}

/// The payoff: a TLSA record published over the certificate as it exists
/// matches, because matching hashes the received octets.
#[test]
fn matching_succeeds_over_the_received_octets() {
    let parsed = parse(GENTIME_DER);
    let cert = presented(GENTIME_DER, &parsed);
    let response = secure(vec![sha256_record(
        TlsaUsage::DaneEe,
        TlsaSelector::Cert,
        "gentime-leaf",
        "Cert",
    )]);

    verify_dane_ee(&cert, &response).expect("a record over the certificate's own bytes must match");
}

/// The counterfactual, stated as a test: a digest over the re-encoded bytes
/// does **not** match. This is what a `to_der()`-based implementation would
/// have computed, and it is the silent interop failure the design avoids.
#[test]
fn a_digest_over_re_encoded_bytes_would_not_match() {
    use sha2::Digest as _;

    let parsed = parse(GENTIME_DER);
    let re_encoded = parsed.to_der().expect("a parsed certificate should encode");
    let wrong_digest: [u8; 32] = sha2::Sha256::digest(&re_encoded).into();

    // Sanity: this really is a different digest from the correct one.
    let correct = digest("gentime-leaf", "Cert", "sha256");
    assert_ne!(wrong_digest.as_slice(), correct.as_slice());

    let cert = presented(GENTIME_DER, &parsed);
    let bad_record = record(
        TlsaUsage::DaneEe,
        TlsaSelector::Cert,
        TlsaMatchingType::Sha256,
        wrong_digest.to_vec(),
    );
    assert!(
        !matches(&bad_record, &cert).expect("matching should not error"),
        "a digest over re-encoded bytes must not match the received certificate"
    );
}

/// `Full` matching is affected identically — it compares the selected content
/// verbatim, so the received bytes are what must be published.
#[test]
fn full_matching_also_uses_the_received_octets() {
    let parsed = parse(GENTIME_DER);
    let cert = presented(GENTIME_DER, &parsed);

    let good = record(
        TlsaUsage::DaneEe,
        TlsaSelector::Cert,
        TlsaMatchingType::Full,
        GENTIME_DER.to_vec(),
    );
    assert!(matches(&good, &cert).expect("matching should not error"));

    let re_encoded = parsed.to_der().expect("a parsed certificate should encode");
    let bad = record(
        TlsaUsage::DaneEe,
        TlsaSelector::Cert,
        TlsaMatchingType::Full,
        re_encoded,
    );
    assert!(!matches(&bad, &cert).expect("matching should not error"));
}

/// The `Spki` selector is unaffected, which is the claim the re-encode caveat
/// on `selected_content` rests on: a `SubjectPublicKeyInfo` holds an algorithm
/// identifier and a `BIT STRING`, with no `Time` field to normalize. Checked
/// against OpenSSL's extraction from the same rewritten certificate.
#[test]
fn the_spki_selector_is_unaffected_by_the_time_rewrite() {
    let parsed = parse(GENTIME_DER);
    let extracted = presented(GENTIME_DER, &parsed)
        .selected_content(TlsaSelector::Spki)
        .expect("the SPKI should encode");
    assert_eq!(extracted.as_ref(), GENTIME_SPKI_DER);

    let response = secure(vec![sha256_record(
        TlsaUsage::DaneEe,
        TlsaSelector::Spki,
        "gentime-leaf",
        "Spki",
    )]);
    verify_dane_ee(&presented(GENTIME_DER, &parsed), &response)
        .expect("an SPKI record should match");
}

/// Rewriting the validity fields left the public key alone, so the rewritten
/// certificate's SPKI is the original's. This pins the fixture generator's
/// behaviour: if `gen_gentime.py` ever touched more than the time fields,
/// this catches it.
#[test]
fn the_rewrite_changed_only_the_time_fields() {
    assert_eq!(
        GENTIME_SPKI_DER,
        support::LEAF_SPKI_DER,
        "gen_gentime.py should rewrite only validity times, leaving the key"
    );
    assert_eq!(GENTIME_DER.len(), LEAF_DER.len() + 4);
}
