//! Verification of Google's detached signature over the CT log list.
//!
//! The fixtures are the real published artifacts, fetched together — see
//! `fixtures/REFRESH.md`. Using the genuine list rather than a synthetic one
//! is the point: the test asserts this crate agrees with what Google actually
//! signs, which is the only thing a deployment cares about. A hand-rolled key
//! and list would prove the code is self-consistent and nothing more.
//!
//! These tests are not affected by the list going stale. They assert that the
//! signature verifies and that tampering is caught; neither depends on the
//! list being current. Rotation of the *signing key* would break them, which
//! is rare and is exactly the kind of change worth being told about.

#![cfg(feature = "log-list-json")]

use pkix_ct::{CtLogList, Error};
use pkix_path::DefaultVerifier;

const LIST: &[u8] = include_bytes!("fixtures/google-log-list.json");
const SIG: &[u8] = include_bytes!("fixtures/google-log-list.sig");
const KEY: &[u8] = include_bytes!("fixtures/google-log-list-pubkey.der");

/// The published signature verifies over the published list, and the list
/// then parses.
#[test]
fn google_signature_verifies() {
    let list = CtLogList::from_google_log_list_json_verified(LIST, SIG, KEY, &DefaultVerifier)
        .expect("Google's own signature should verify over Google's own list");

    // A sanity floor rather than an exact count, which would change on every
    // refresh: the real list carries dozens of logs.
    assert!(
        list.len() >= 10,
        "expected the real log list to hold many logs, got {}",
        list.len()
    );
}

/// A single flipped byte anywhere in the list is rejected.
///
/// Checked at three positions because a signature scheme that only noticed
/// changes near one end would pass a single-position test.
#[test]
fn a_tampered_list_is_rejected() {
    for position in [0, LIST.len() / 2, LIST.len() - 1] {
        let mut tampered = LIST.to_vec();
        tampered[position] ^= 0x01;

        assert_eq!(
            CtLogList::from_google_log_list_json_verified(&tampered, SIG, KEY, &DefaultVerifier)
                .err(),
            Some(Error::InvalidSignature),
            "a byte flipped at {position} should fail verification"
        );
    }
}

/// The attack this protects against: adding an attacker-controlled log.
///
/// A `log_id` is SHA-256 over the log's SPKI, so a substituted list cannot
/// forge an SCT for a log already present. What it can do is append a log the
/// attacker holds the key for, after which SCTs from that log verify. This
/// asserts such an edit is caught — appending to the JSON changes the bytes
/// the signature covers, so it must fail even though the result is still
/// well-formed JSON.
#[test]
fn appending_a_log_is_rejected() {
    let text = core::str::from_utf8(LIST).expect("fixture is UTF-8");
    // Append inside the structure rather than after it, so the result is
    // valid JSON and the only thing rejecting it can be the signature.
    let doctored = text.replacen('{', "{\"attacker_note\":\"added\",", 1);
    assert_ne!(doctored.as_bytes(), LIST);

    assert_eq!(
        CtLogList::from_google_log_list_json_verified(
            doctored.as_bytes(),
            SIG,
            KEY,
            &DefaultVerifier
        )
        .err(),
        Some(Error::InvalidSignature),
        "an edited-but-valid-JSON list must be rejected on its signature"
    );
}

/// A different key does not verify. Without this, a verifier that ignored the
/// key argument entirely would pass every test above.
#[test]
fn a_wrong_key_does_not_verify() {
    // Flip a byte inside the modulus rather than the DER header, so the SPKI
    // still parses and the failure is genuinely the signature check.
    let mut wrong = KEY.to_vec();
    let middle = wrong.len() / 2;
    wrong[middle] ^= 0x01;

    assert_eq!(
        CtLogList::from_google_log_list_json_verified(LIST, SIG, &wrong, &DefaultVerifier).err(),
        Some(Error::InvalidSignature),
        "a modified key must not verify Google's signature"
    );
}

/// A malformed key is a signature failure, not a parse failure or a panic.
#[test]
fn a_malformed_key_is_a_signature_failure() {
    for key in [&b""[..], &b"not der"[..], &KEY[..KEY.len() / 2]] {
        assert_eq!(
            CtLogList::from_google_log_list_json_verified(LIST, SIG, key, &DefaultVerifier).err(),
            Some(Error::InvalidSignature),
            "a malformed key should report InvalidSignature"
        );
    }
}

/// A truncated or empty signature is rejected rather than treated as absent.
#[test]
fn a_malformed_signature_is_rejected() {
    for sig in [&b""[..], &SIG[..SIG.len() / 2], &b"garbage"[..]] {
        assert_eq!(
            CtLogList::from_google_log_list_json_verified(LIST, sig, KEY, &DefaultVerifier).err(),
            Some(Error::InvalidSignature),
            "a malformed signature should report InvalidSignature"
        );
    }
}

/// Nothing is parsed until the signature verifies.
///
/// Unverified input that is not even JSON must be reported as a signature
/// failure, because that is the honest description: the bytes were never
/// trusted far enough to be parsed. Reporting a parse error would tell a
/// caller the list was authentic but malformed.
#[test]
fn unverified_input_is_not_parsed() {
    assert_eq!(
        CtLogList::from_google_log_list_json_verified(
            b"this is not json at all",
            SIG,
            KEY,
            &DefaultVerifier
        )
        .err(),
        Some(Error::InvalidSignature),
        "signature failure must precede any parse attempt"
    );
}

/// The unverified constructor still exists and still parses the same bytes,
/// so this change is additive rather than a replacement.
#[test]
fn the_unverified_constructor_still_works() {
    let text = core::str::from_utf8(LIST).expect("fixture is UTF-8");
    let unverified = CtLogList::from_google_log_list_json(text).expect("parses");
    let verified = CtLogList::from_google_log_list_json_verified(LIST, SIG, KEY, &DefaultVerifier)
        .expect("verifies");
    assert_eq!(unverified.len(), verified.len());
}
