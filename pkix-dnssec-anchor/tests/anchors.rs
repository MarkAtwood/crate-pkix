//! Checks on the generated anchor set and its provenance.
//!
//! These guard against the ways a generated trust anchor can go wrong:
//! shipping an empty or withdrawn-only set, losing the key material, a
//! generator that silently changed shape, and a committed provenance record
//! that no longer matches what it claims to attest.

use std::process::Command;

use pkix_dnssec_anchor::{RootAnchor, ALL, CURRENT};

/// Unix timestamp for 2026-11-24T00:00:00Z, the day these tests were written.
/// Used where a test needs "roughly now" without reading the clock, so it
/// cannot start failing for an unrelated reason on a future date.
const NOW_2026_11_24: i64 = 1_764_028_800;

#[test]
fn at_least_one_current_anchor_ships() {
    assert!(
        !CURRENT.is_empty(),
        "a crate whose whole purpose is shipping anchors must ship one"
    );
    assert!(!ALL.is_empty());
}

/// IANA publishes a new KSK well before withdrawing the old one, so two
/// anchors are valid during a roll. A validator must accept any of them;
/// honouring only the newest is an outage waiting for the roll to finish.
/// This is a shape check, not a prediction — it only asserts that whatever
/// `CURRENT` holds is internally consistent.
#[test]
fn current_holds_exactly_the_anchors_without_a_withdrawal_date() {
    for anchor in CURRENT {
        assert!(
            !anchor.is_withdrawn(),
            "{} is in CURRENT but carries validUntil {:?}",
            anchor.id,
            anchor.valid_until
        );
    }
    let expected: Vec<&str> = ALL
        .iter()
        .filter(|a| !a.is_withdrawn())
        .map(|a| a.id)
        .collect();
    let actual: Vec<&str> = CURRENT.iter().map(|a| a.id).collect();
    assert_eq!(actual, expected);
}

#[test]
fn every_anchor_is_well_formed() {
    for anchor in ALL {
        assert!(!anchor.id.is_empty(), "anchor has no IANA id");
        assert_ne!(anchor.key_tag, 0, "{}: key tag 0", anchor.id);
        // Every anchor IANA publishes carries a validFrom; only a
        // caller-built one may omit it.
        assert!(
            anchor.valid_from.is_some_and(|s| !s.is_empty()),
            "{}: no validFrom",
            anchor.id
        );
    }
}

/// IANA's older entries are digest-only: the withdrawn 2010 anchor has a key
/// tag and a digest but no `PublicKey` and no `Flags`. Flags are therefore
/// asserted only where IANA stated them, and `flags == 0` is documented as
/// "not stated" rather than as a real flag value.
#[test]
fn anchors_with_stated_flags_are_key_signing_keys() {
    let mut stated = 0;
    for anchor in ALL {
        if anchor.flags == 0 {
            assert!(
                anchor.is_withdrawn(),
                "{}: a current anchor must state its flags",
                anchor.id
            );
            assert!(
                anchor.public_key.is_empty(),
                "{}: key material without flags is a generator bug",
                anchor.id
            );
            continue;
        }
        stated += 1;
        assert!(
            anchor.is_key_signing_key(),
            "{}: flags {} lack the Secure Entry Point bit",
            anchor.id,
            anchor.flags
        );
    }
    assert!(
        stated > 0,
        "no anchor stated its flags; generator is broken"
    );
}

/// Digest length must match the declared digest type. A mismatch would mean
/// the generator mangled the hex, and a validator comparing a SHA-256 of a
/// DNSKEY against a wrong-length digest can never match.
#[test]
fn digests_match_their_declared_algorithm() {
    for anchor in ALL {
        let expected = match anchor.digest_type {
            1 => 20, // SHA-1
            2 => 32, // SHA-256
            4 => 48, // SHA-384
            other => panic!("{}: unexpected digest type {other}", anchor.id),
        };
        assert_eq!(
            anchor.digest.len(),
            expected,
            "{}: digest type {} wants {expected} octets, got {}",
            anchor.id,
            anchor.digest_type,
            anchor.digest.len()
        );
    }
}

/// Current anchors must carry usable key material. A withdrawn entry is
/// allowed to lack it — IANA published digest-only records historically — but
/// an anchor a validator will actually use is useless without the key.
#[test]
fn current_anchors_carry_key_material() {
    for anchor in CURRENT {
        assert!(
            !anchor.public_key.is_empty(),
            "{}: current anchor has no public key",
            anchor.id
        );
        // Algorithm 8 is RSA/SHA-256. DNSKEY RDATA for a 2048-bit RSA key is
        // a few hundred octets; anything tiny means a decode went wrong.
        assert!(
            anchor.public_key.len() > 64,
            "{}: public key is only {} octets",
            anchor.id,
            anchor.public_key.len()
        );
    }
}

/// Key tags should be distinct in practice. They are a 16-bit checksum and may
/// collide in principle, which is why `RootAnchor` documents not using them as
/// a sole identifier — but a collision in IANA's own small set would mean the
/// generator duplicated an entry.
#[test]
fn anchors_are_distinct() {
    let mut ids: Vec<&str> = ALL.iter().map(|a| a.id).collect();
    let before = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), before, "duplicate IANA ids in ALL");

    let mut tags: Vec<u16> = ALL.iter().map(|a| a.key_tag).collect();
    let before = tags.len();
    tags.sort_unstable();
    tags.dedup();
    assert_eq!(tags.len(), before, "duplicate key tags in ALL");
}

// -------------------------------------------------------------------------
// is_valid_at
// -------------------------------------------------------------------------

#[test]
fn current_anchors_are_valid_now_and_withdrawn_ones_are_not() {
    for anchor in ALL {
        let valid = anchor.is_valid_at(NOW_2026_11_24);
        assert_eq!(
            valid,
            !anchor.is_withdrawn(),
            "{}: is_valid_at disagrees with is_withdrawn",
            anchor.id
        );
    }
}

#[test]
fn an_anchor_is_not_valid_before_it_was_published() {
    // 2000-01-01T00:00:00Z, before any root anchor existed.
    for anchor in ALL {
        assert!(
            !anchor.is_valid_at(946_684_800),
            "{}: valid before DNSSEC root signing existed",
            anchor.id
        );
    }
}

/// A malformed timestamp must fail closed: an anchor whose validity window
/// cannot be established is not trusted.
#[test]
fn unparsable_timestamps_fail_closed() {
    let cases = [
        "",
        "not a date",
        "2024-07-18",
        "2024-07-18T00:00",
        // Right length, wrong separators.
        "2024/07/18T00:00:00+00:00",
        // A non-UTC offset is refused rather than converted.
        "2024-07-18T00:00:00+02:00",
        // Out-of-range components.
        "2024-13-18T00:00:00Z",
        "2024-07-32T00:00:00Z",
        "2024-07-18T25:00:00Z",
    ];
    for bad in cases {
        let anchor = RootAnchor::new(1, 8, 2, &[0; 32]).with_validity(Some(bad), None);
        assert!(
            !anchor.is_valid_at(NOW_2026_11_24),
            "validFrom {bad:?} should fail closed"
        );
    }
}

/// The accepted forms must all parse to the same instant, so that a future
/// change in how IANA writes its timestamps does not silently shift a window.
#[test]
fn accepted_timestamp_forms_agree() {
    let make =
        |from: &'static str| RootAnchor::new(1, 8, 2, &[0; 32]).with_validity(Some(from), None);
    // 2024-07-18T00:00:00Z == 1721260800
    let instant = 1_721_260_800;
    for form in [
        "2024-07-18T00:00:00Z",
        "2024-07-18T00:00:00+00:00",
        "2024-07-18T00:00:00-00:00",
        "2024-07-18T00:00:00",
    ] {
        let anchor = make(form);
        assert!(
            anchor.is_valid_at(instant),
            "{form} should be valid at its own instant"
        );
        assert!(
            !anchor.is_valid_at(instant - 1),
            "{form} should not be valid one second earlier"
        );
    }
}

// -------------------------------------------------------------------------
// Provenance
// -------------------------------------------------------------------------

/// The committed IANA artifacts must still verify against each other.
///
/// This is the test that makes the crate auditable rather than merely
/// documented: it re-runs the same signature check `gen.sh` performs, against
/// the files shipped in the crate. If someone edits `iana/root-anchors.xml` to
/// change an anchor without a matching signature, this fails.
///
/// Skips where `openssl` is unavailable — a provenance check that cannot run
/// is an absent check, not a failure of the data.
#[test]
fn committed_iana_artifacts_still_verify() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/iana");
    let xml = format!("{dir}/root-anchors.xml");
    let p7s = format!("{dir}/root-anchors.p7s");
    let bundle = format!("{dir}/icannbundle.pem");

    for path in [&xml, &p7s, &bundle] {
        assert!(
            std::path::Path::new(path).exists(),
            "missing provenance file: {path}"
        );
    }

    let Ok(out) = Command::new("openssl")
        .args([
            "smime",
            "-verify",
            "-inform",
            "DER",
            "-in",
            &p7s,
            "-content",
            &xml,
            "-CAfile",
            &bundle,
            "-out",
            "/dev/null",
        ])
        .output()
    else {
        println!("SKIP: openssl unavailable");
        return;
    };

    assert!(
        out.status.success(),
        "IANA signature over the committed root-anchors.xml did not verify:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Every anchor in the generated source must appear in the committed XML.
///
/// Catches a hand-edited `generated.rs`: the signature test above proves the
/// XML is authentic, and this proves the Rust matches it.
#[test]
fn generated_anchors_match_the_committed_xml() {
    let xml = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/iana/root-anchors.xml"
    ))
    .expect("the committed root-anchors.xml should be readable");

    for anchor in ALL {
        assert!(
            xml.contains(&format!("id=\"{}\"", anchor.id)),
            "{} is in generated.rs but not in the committed XML",
            anchor.id
        );
        assert!(
            xml.contains(&format!("<KeyTag>{}</KeyTag>", anchor.key_tag)),
            "{}: key tag {} not in the committed XML",
            anchor.id,
            anchor.key_tag
        );
        let digest_hex: String = anchor.digest.iter().map(|b| format!("{b:02X}")).collect();
        assert!(
            xml.contains(&digest_hex),
            "{}: digest not in the committed XML",
            anchor.id
        );
    }

    // And nothing in the XML was dropped on the way out.
    let xml_anchors = xml.matches("<KeyDigest ").count();
    assert_eq!(
        ALL.len(),
        xml_anchors,
        "the XML lists {xml_anchors} anchors but generated.rs has {}",
        ALL.len()
    );
}

// -------------------------------------------------------------------------
// Caller-supplied anchors
// -------------------------------------------------------------------------

/// A consumer with a private DNSSEC root must be able to build an anchor.
/// Without this the "caller supplies the trust anchor" design would be a
/// fiction: only the constants this crate happens to ship would be usable.
#[test]
fn a_caller_can_build_their_own_anchor() {
    let anchor = RootAnchor::new(12345, 8, 2, &[0xab; 32])
        .with_id("private-root")
        .with_public_key(&[0xcd; 260]);

    assert_eq!(anchor.key_tag, 12345);
    assert_eq!(anchor.id, "private-root");
    assert_eq!(anchor.digest.len(), 32);
    assert_eq!(anchor.public_key.len(), 260);
    assert!(anchor.is_key_signing_key(), "flags should default to a KSK");
    assert!(!anchor.is_withdrawn());
}

/// An anchor with no stated validity window is accepted at any time. The
/// alternative — treating a missing date as unparsable and failing closed —
/// would reject an anchor the caller deliberately supplied.
#[test]
fn an_anchor_without_a_validity_window_is_always_valid() {
    let anchor = RootAnchor::new(1, 8, 2, &[0; 32]);
    assert_eq!(anchor.valid_from, None);
    assert_eq!(anchor.valid_until, None);

    for instant in [0, 946_684_800, NOW_2026_11_24, i64::MAX / 2] {
        assert!(
            anchor.is_valid_at(instant),
            "an unbounded anchor should be valid at {instant}"
        );
    }
}

/// An upper bound alone still applies.
#[test]
fn an_upper_bound_applies_without_a_lower_one() {
    let anchor =
        RootAnchor::new(1, 8, 2, &[0; 32]).with_validity(None, Some("2020-01-01T00:00:00Z"));
    assert!(anchor.is_valid_at(0));
    assert!(!anchor.is_valid_at(NOW_2026_11_24));
    assert!(anchor.is_withdrawn());
}

#[test]
fn with_flags_can_clear_the_key_signing_bit() {
    let zsk = RootAnchor::new(1, 8, 2, &[0; 32]).with_flags(256);
    assert!(!zsk.is_key_signing_key());
}
