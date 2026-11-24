//! RFC 7672 §3.2 SMTP DANE name checks.
//!
//! Fixtures are the crate's existing DANE test certificates, whose shapes
//! happen to be exactly what these rules need:
//!
//! | Fixture | Subject | SAN |
//! |---|---|---|
//! | `chain-leaf.der` | `CN=dane-test-chained.example.com` | `DNS:dane-test-chained.example.com` |
//! | `leaf.der` | `CN=dane-test-leaf.example.com` | none |
//! | `other.der` | `CN=dane-test-other.example.com` | none |
//!
//! So `chain-leaf` exercises the DNS-ID path and `leaf` / `other` exercise
//! RFC 7672 §3.2.3's CN-ID fallback, which the Web PKI path refuses.

#![cfg(feature = "smtp")]

use der::Decode as _;
use x509_cert::Certificate;

use pkix_dane::record::TlsaUsage;
use pkix_dane::smtp::{verify_smtp_name, SmtpIdentities, SmtpNameCheck, SmtpNameError};

const CHAINED: &str = "dane-test-chained.example.com";
const LEAF: &str = "dane-test-leaf.example.com";
const OTHER: &str = "dane-test-other.example.com";

fn load(name: &str) -> Certificate {
    let path = format!("tests/fixtures/{name}");
    let der = std::fs::read(&path).unwrap_or_else(|e| panic!("fixture not found: {path}: {e}"));
    Certificate::from_der(&der).unwrap_or_else(|e| panic!("invalid DER in {path}: {e}"))
}

// ---------------------------------------------------------------------------
// The reference identifier set, RFC 7672 §3.2.2
// ---------------------------------------------------------------------------

#[test]
fn secure_mx_carries_the_base_domain_then_the_next_hop() {
    let ids = SmtpIdentities::secure_mx("mx1.example.net", "example.com", None);
    assert_eq!(ids.primary(), "mx1.example.net");
    assert_eq!(
        ids.iter().collect::<Vec<_>>(),
        vec!["mx1.example.net", "example.com"]
    );
}

#[test]
fn secure_mx_adds_the_cname_expanded_next_hop_as_a_third() {
    let ids = SmtpIdentities::secure_mx("mx1.example.net", "example.com", Some("mail.example.org"));
    assert_eq!(
        ids.iter().collect::<Vec<_>>(),
        vec!["mx1.example.net", "example.com", "mail.example.org"]
    );
    assert_eq!(ids.len(), 3);
}

/// §3.2.2 asks for the expansion only "if different from the original
/// next-hop domain". A caller that cannot easily tell may pass it anyway.
#[test]
fn an_expansion_equal_to_the_next_hop_is_not_repeated() {
    let ids = SmtpIdentities::secure_mx("mx1.example.net", "example.com", Some("example.com"));
    assert_eq!(
        ids.iter().collect::<Vec<_>>(),
        vec!["mx1.example.net", "example.com"]
    );
}

#[test]
fn deduplication_is_case_insensitive() {
    let ids = SmtpIdentities::secure_mx("mx1.example.net", "Example.COM", Some("example.com"));
    assert_eq!(
        ids.len(),
        2,
        "names differing only in case are one identifier"
    );
}

/// The security property of the insecure-MX case, stated as a test.
///
/// RFC 7672 §3.2.2: "When the client MTA is employing DANE TLS security
/// despite 'insecure' MX redirection, the MX hostname is the only reference
/// identifier."
#[test]
fn insecure_mx_has_exactly_one_identifier() {
    let ids = SmtpIdentities::insecure_mx("mx1.example.net");
    assert_eq!(ids.len(), 1);
    assert_eq!(ids.iter().collect::<Vec<_>>(), vec!["mx1.example.net"]);
}

#[test]
fn non_mx_without_a_cname_is_just_the_base_domain() {
    let ids = SmtpIdentities::non_mx("relay.example.net", None);
    assert_eq!(ids.len(), 1);
    assert_eq!(ids.primary(), "relay.example.net");
}

#[test]
fn non_mx_adds_the_original_next_hop_when_the_base_is_a_cname_expansion() {
    let ids = SmtpIdentities::non_mx("real.example.net", Some("alias.example.com"));
    assert_eq!(
        ids.iter().collect::<Vec<_>>(),
        vec!["real.example.net", "alias.example.com"]
    );
}

// ---------------------------------------------------------------------------
// Usage gating, RFC 7672 §3.2.1 and §3.1.3
// ---------------------------------------------------------------------------

/// §3.2.1: "The SMTP client MUST NOT perform certificate name checks with
/// certificate usage DANE-EE(3)."
///
/// Checked with a certificate that matches nothing in the set, so a name
/// check actually running would fail and be visible.
#[test]
fn dane_ee_skips_the_name_check_entirely() {
    let cert = load("other.der");
    let ids = SmtpIdentities::insecure_mx("completely.unrelated.example");
    assert_eq!(
        verify_smtp_name(TlsaUsage::DaneEe, &cert, &ids),
        Ok(SmtpNameCheck::NotRequired)
    );
}

/// §3.1.3, taking the MAY: PKIX-TA(0) and PKIX-EE(1) are unusable here.
#[test]
fn the_pkix_usages_are_treated_as_unusable() {
    let cert = load("chain-leaf.der");
    let ids = SmtpIdentities::insecure_mx(CHAINED);
    for usage in [TlsaUsage::PkixTa, TlsaUsage::PkixEe] {
        assert_eq!(
            verify_smtp_name(usage, &cert, &ids),
            Err(SmtpNameError::PkixUsageUnusable { usage }),
            "usage {} must be reported as unusable, not silently honoured",
            usage.to_octet()
        );
    }
}

#[test]
fn unassigned_and_private_use_usages_are_unsupported() {
    let cert = load("chain-leaf.der");
    let ids = SmtpIdentities::insecure_mx(CHAINED);
    for usage in [TlsaUsage::from_octet(7), TlsaUsage::PrivateUse] {
        assert_eq!(
            verify_smtp_name(usage, &cert, &ids),
            Err(SmtpNameError::UsageUnsupported { usage })
        );
    }
}

// ---------------------------------------------------------------------------
// DANE-TA(2) matching, RFC 7672 §3.2.2 and §3.2.3
// ---------------------------------------------------------------------------

#[test]
fn dane_ta_matches_the_base_domain_via_a_dns_id() {
    let cert = load("chain-leaf.der");
    let ids = SmtpIdentities::insecure_mx(CHAINED);
    assert_eq!(
        verify_smtp_name(TlsaUsage::DaneTa, &cert, &ids),
        Ok(SmtpNameCheck::Matched(CHAINED))
    );
}

/// §3.2.3's CN-ID fallback, reached through the SMTP entry point.
///
/// `leaf.der` carries its name only in the subject `commonName`. The Web PKI
/// path rejects that; RFC 7672 requires accepting it.
#[test]
fn dane_ta_matches_a_cn_only_certificate() {
    let cert = load("leaf.der");
    let ids = SmtpIdentities::insecure_mx(LEAF);
    assert_eq!(
        verify_smtp_name(TlsaUsage::DaneTa, &cert, &ids),
        Ok(SmtpNameCheck::Matched(LEAF)),
        "RFC 7672 §3.2.3 consults the CN when no DNS-ID is present"
    );
}

/// A match on the *second* identifier — the original next-hop domain.
///
/// This is the half of §3.2.2 a single-hostname API cannot express: the
/// certificate names the next-hop domain rather than the MX hostname, which
/// is legitimate when the MX lookup was secure.
#[test]
fn dane_ta_matches_the_next_hop_domain_when_the_mx_lookup_was_secure() {
    let cert = load("other.der");
    let ids = SmtpIdentities::secure_mx("mx1.example.net", OTHER, None);
    assert_eq!(
        verify_smtp_name(TlsaUsage::DaneTa, &cert, &ids),
        Ok(SmtpNameCheck::Matched(OTHER)),
        "the original next-hop domain is a reference identifier under §3.2.2"
    );
}

/// The same certificate and the same next-hop domain, reached insecurely,
/// must be rejected.
///
/// This pair is the point of modelling the origin rather than just collecting
/// hostnames. An attacker who can tamper with an unsigned MX RRset picks the
/// MX hostname, so a certificate matching the next-hop domain proves nothing
/// about having reached the intended destination. Accepting it would let the
/// delivery be logged as secure delivery to a domain that was never
/// authenticated, which §2.2.1 forbids.
#[test]
fn the_next_hop_domain_is_not_an_identifier_after_insecure_mx_redirection() {
    let cert = load("other.der");
    let insecure = SmtpIdentities::insecure_mx("mx1.example.net");
    assert_eq!(
        verify_smtp_name(TlsaUsage::DaneTa, &cert, &insecure),
        Err(SmtpNameError::NoIdentityMatch),
        "after insecure MX redirection the MX hostname is the only identifier"
    );

    // And the contrast is solely the origin: same cert, same next-hop name.
    let secure = SmtpIdentities::secure_mx("mx1.example.net", OTHER, None);
    assert!(verify_smtp_name(TlsaUsage::DaneTa, &cert, &secure).is_ok());
}

#[test]
fn a_certificate_naming_another_host_does_not_match() {
    let cert = load("other.der");
    let ids = SmtpIdentities::insecure_mx(LEAF);
    assert_eq!(
        verify_smtp_name(TlsaUsage::DaneTa, &cert, &ids),
        Err(SmtpNameError::NoIdentityMatch)
    );
}

/// Which identifier matched is reported, not just that one did.
///
/// RFC 7672 §2.2.1 requires delivery logs to distinguish secure delivery to
/// the intended next-hop domain from authentication via an insecurely
/// determined MX host, and that distinction needs the name.
#[test]
fn the_matched_identifier_is_reported() {
    let cert = load("other.der");
    let ids = SmtpIdentities::secure_mx("mx1.example.net", "example.com", Some(OTHER));
    match verify_smtp_name(TlsaUsage::DaneTa, &cert, &ids) {
        Ok(SmtpNameCheck::Matched(matched)) => assert_eq!(matched, OTHER),
        other => panic!("expected a match on the third identifier, got {other:?}"),
    }
}

/// A malformed reference identifier does not mask a match on another.
#[test]
fn an_unusable_reference_identifier_is_skipped_not_fatal() {
    let cert = load("other.der");
    // An empty next-hop name is not a valid DNS name and cannot be matched.
    let ids = SmtpIdentities::secure_mx(OTHER, "", None);
    assert_eq!(
        verify_smtp_name(TlsaUsage::DaneTa, &cert, &ids),
        Ok(SmtpNameCheck::Matched(OTHER))
    );
}

// ---------------------------------------------------------------------------
// Error shape
// ---------------------------------------------------------------------------

#[test]
fn the_errors_display_without_panicking_and_name_the_rule() {
    let unusable = SmtpNameError::PkixUsageUnusable {
        usage: TlsaUsage::PkixEe,
    };
    let text = std::format!("{unusable}");
    assert!(text.contains('1'), "should name the usage octet: {text}");
    assert!(text.contains("7672"), "should cite the rule: {text}");

    for e in [
        SmtpNameError::NoIdentityMatch,
        SmtpNameError::NoPresentedIdentity,
        SmtpNameError::MalformedSan,
        SmtpNameError::UsageUnsupported {
            usage: TlsaUsage::from_octet(9),
        },
    ] {
        assert!(!std::format!("{e}").is_empty());
    }
}
