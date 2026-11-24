//! The shipped key, checked against Google's own published artifacts.
//!
//! The central test is the cross-check `gen.sh` performs at generation time:
//! does this key verify the log list Google published alongside it? That is
//! the strongest available statement about this key — Google signs no
//! statement about the key itself and publishes no out-of-band copy — so it
//! belongs in the test suite, where it is a property of every release, rather
//! than only in the generator, where it was a property of one afternoon.

use sha2::{Digest, Sha256};

use pkix_ct::CtLogList;
use pkix_ct_google::{GOOGLE, GOOGLE_SPKI_SHA256_HEX};
use pkix_path::DefaultVerifier;

const SAMPLE_LIST: &[u8] = include_bytes!("../google/sample-log_list.json");
const SAMPLE_SIG: &[u8] = include_bytes!("../google/sample-log_list.sig");
const COMMITTED_DER: &[u8] = include_bytes!("../google/log_list_pubkey.der");

/// The shipped key verifies Google's published signature over Google's
/// published list.
///
/// This is the whole provenance claim of the crate. If it fails, the key is
/// not Google's log-list signing key, whatever else is true of it.
#[test]
fn the_key_verifies_googles_published_list() {
    let list = CtLogList::from_google_log_list_json_verified(
        SAMPLE_LIST,
        SAMPLE_SIG,
        GOOGLE.spki,
        &DefaultVerifier,
    )
    .expect("the shipped key should verify the committed sample list");

    // A floor rather than an exact count, which would change whenever the
    // sample is refreshed.
    assert!(
        list.len() >= 10,
        "the real log list holds many logs, got {}",
        list.len()
    );
}

/// A different key does not verify.
///
/// Without this, a verifier that ignored the key argument would pass the test
/// above and the provenance claim would be vacuous.
#[test]
fn a_modified_key_does_not_verify() {
    // Flip a bit inside the modulus rather than the DER header, so the SPKI
    // still parses and the failure is genuinely the signature check.
    let mut wrong = GOOGLE.spki.to_vec();
    let middle = wrong.len() / 2;
    wrong[middle] ^= 0x01;

    assert!(
        CtLogList::from_google_log_list_json_verified(
            SAMPLE_LIST,
            SAMPLE_SIG,
            &wrong,
            &DefaultVerifier
        )
        .is_err(),
        "a key with a flipped modulus bit must not verify Google's signature"
    );
}

/// A tampered list is rejected by the shipped key.
///
/// The attack this guards against is a substituted log list carrying an
/// attacker-controlled log, after which SCTs from that log would verify.
#[test]
fn the_key_rejects_a_tampered_list() {
    let text = core::str::from_utf8(SAMPLE_LIST).expect("sample is UTF-8");
    // Edit inside the structure so the result is still valid JSON and the only
    // thing able to reject it is the signature.
    let doctored = text.replacen('{', "{\"attacker_note\":\"added\",", 1);
    assert_ne!(doctored.as_bytes(), SAMPLE_LIST);

    assert!(
        CtLogList::from_google_log_list_json_verified(
            doctored.as_bytes(),
            SAMPLE_SIG,
            GOOGLE.spki,
            &DefaultVerifier
        )
        .is_err(),
        "an edited-but-well-formed list must be rejected on its signature"
    );
}

/// The declared digest matches the shipped bytes.
///
/// `GOOGLE_SPKI_SHA256_HEX` is how a reviewer checks a release against
/// Google's published key without parsing DER, so it has to be true. It is
/// generated from the same bytes, which makes this a guard against a
/// hand-edited `generated.rs` — the one way the two could disagree.
#[test]
fn the_declared_digest_matches_the_key() {
    let computed = Sha256::digest(GOOGLE.spki);
    let hex: String = computed.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex, GOOGLE_SPKI_SHA256_HEX,
        "the declared SHA-256 must match the shipped SPKI"
    );
}

/// The generated constant and the committed DER artifact are the same bytes.
///
/// They are generated together, so a divergence means `generated.rs` or the
/// artifact was edited by hand. Both are shipped, and a consumer re-running
/// the offline cross-check uses the artifact while their code uses the
/// constant; if those differed, the audit would not be auditing the key in
/// use.
#[test]
fn the_constant_matches_the_committed_artifact() {
    assert_eq!(
        GOOGLE.spki, COMMITTED_DER,
        "src/generated.rs and google/log_list_pubkey.der must agree"
    );
}

/// Provenance fields say where the key came from and when.
#[test]
fn provenance_is_recorded() {
    assert_eq!(
        GOOGLE.source,
        "https://www.gstatic.com/ct/log_list/v3/log_list_pubkey.pem"
    );

    // YYYY-MM-DD, checked structurally rather than against a fixed value so
    // regeneration does not require editing the test.
    let date = GOOGLE.retrieved;
    assert_eq!(
        date.len(),
        10,
        "retrieved should be YYYY-MM-DD, got {date:?}"
    );
    let parts: Vec<&str> = date.split('-').collect();
    assert_eq!(
        parts.len(),
        3,
        "retrieved should have three parts: {date:?}"
    );
    assert!(
        parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit())),
        "retrieved should be all digits and dashes: {date:?}"
    );
    assert!(
        parts[0] >= "2015",
        "retrieved predates Certificate Transparency's log lists: {date:?}"
    );
}

/// The key is a plausible DER `SubjectPublicKeyInfo`.
///
/// Not a parse — `pkix-ct` does that, and the verification test above would
/// fail if it did not parse. This catches the coarse accident the generator
/// could make: an empty or truncated array, or PEM text captured instead of
/// DER.
#[test]
fn the_key_is_der_not_pem() {
    assert!(!GOOGLE.spki.is_empty(), "the key must not be empty");
    assert_eq!(
        GOOGLE.spki[0], 0x30,
        "a DER SubjectPublicKeyInfo starts with SEQUENCE (0x30), not PEM text"
    );
    assert!(
        GOOGLE.spki.len() > 64,
        "an RSA SPKI is hundreds of octets, got {}",
        GOOGLE.spki.len()
    );
}
