//! End-to-end tests for `verify_smtp_server_dane`.
//!
//! Fixtures are the PKITS §4.1.1 certificates, as in `dane_e2e.rs`, and for
//! the same reason: they carry no `dNSName` SAN, so a name check on them
//! fails. That makes the DANE-EE / DANE-TA asymmetry visible — RFC 7672
//! §3.2.1 forbids a name check for DANE-EE(3) and §3.2.2 requires one for
//! DANE-TA(2), and here the first succeeds where the second cannot.
//!
//! Records use `Full` / `Cert`, so association data is the certificate DER
//! itself and no digest is computed. The digest arithmetic is tested in
//! `pkix-dane` against `openssl dgst`; what is under test here is the
//! composition.
//!
//! # The property these tests exist for
//!
//! Authentication failure is a **verdict**, not an error. Every assertion on
//! a failing server checks `Ok(SmtpDaneVerdict::Failed(..))`, because an MTA
//! has to be able to tag, route or queue a message on the strength of a DANE
//! failure — which it cannot do if the failure is indistinguishable from a
//! malformed call.

#![cfg(feature = "dane")]

use pkix_chain::{
    verify_smtp_server_dane, DefaultVerifier, NoAiaFetcher, NoRevocation, SmtpDaneFailure,
    SmtpDaneVerdict,
};
use pkix_dane::record::{TlsaMatchingType, TlsaRecord, TlsaSelector, TlsaUsage};
use pkix_dane::smtp_lookup::{DeliveryTarget, MxAnswer, MxResolution, MxStep, SmtpDaneConfig};
use pkix_dane::DnssecStatus;
use pkix_path::{Profile, ValidationPolicy};
use x509_cert::Certificate;

/// A profile for MTA-to-MTA SMTP: no SubjectAltName requirement.
///
/// `BasicTlsProfile` sets `require_subject_alt_name`, which is right for the
/// Web PKI and wrong here — RFC 7672 §3.2.3 accommodates certificates naming
/// the host only in the `commonName`, and requiring a SAN rejects them during
/// path validation before the name check is reached.
///
/// Defined in the test rather than imported because the workspace ships no
/// SMTP profile yet; that is filed separately.
struct MtaProfile;

impl Profile for MtaProfile {
    fn id(&self) -> &'static str {
        "test-mta"
    }
    fn version(&self) -> &'static str {
        "0"
    }
    fn policy(&self, now_unix: u64) -> ValidationPolicy {
        // require_subject_alt_name defaults to false, which is the point.
        ValidationPolicy::new(now_unix)
    }
    fn policy_oids(&self) -> &[x509_cert::der::asn1::ObjectIdentifier] {
        &[]
    }
}

const PKITS_NOW: u64 = 1_577_836_800;

const TRUST_ANCHOR_DER: &[u8] =
    include_bytes!("../../pkix-path/tests/pkits/certs/TrustAnchorRootCertificate.crt");
const GOOD_CA_DER: &[u8] = include_bytes!("../../pkix-path/tests/pkits/certs/GoodCACert.crt");
const VALID_EE_DER: &[u8] =
    include_bytes!("../../pkix-path/tests/pkits/certs/ValidCertificatePathTest1EE.crt");

fn load(der: &[u8]) -> Certificate {
    use x509_cert::der::Decode as _;
    Certificate::from_der(der).expect("parse cert")
}

/// A `Full` / `Cert` record whose association data is `der`.
fn full_cert_record(usage: TlsaUsage, der: &[u8]) -> TlsaRecord {
    TlsaRecord::new(
        usage,
        TlsaSelector::Cert,
        TlsaMatchingType::Full,
        der.to_vec(),
    )
}

/// Build a `DeliveryTarget` by driving discovery, since its fields are private
/// and only discovery may construct one.
fn target_for(host: &str, records: Vec<TlsaRecord>) -> DeliveryTarget {
    let mut resolution = MxResolution::relay(host, SmtpDaneConfig::new());
    resolution.absorb(MxAnswer::Addresses {
        status: DnssecStatus::Secure,
        found: true,
    });
    resolution.absorb(MxAnswer::Tlsa {
        status: DnssecStatus::Secure,
        records,
    });
    match resolution.next_step() {
        MxStep::Deliver(target) => target,
        other => panic!("expected a delivery target, got {other:?}"),
    }
}

fn verify(
    target: &DeliveryTarget,
    chain: &[Certificate],
    chain_der: &[&[u8]],
) -> Result<SmtpDaneVerdict, pkix_chain::Error> {
    verify_smtp_server_dane(
        target,
        chain,
        chain_der,
        &MtaProfile,
        PKITS_NOW,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
}

// ---------------------------------------------------------------------------
// DANE-EE(3): authenticated, and no name check
// ---------------------------------------------------------------------------

/// A DANE-EE(3) record naming the leaf authenticates it, with no name check
/// and no path — RFC 7671 §5.1, RFC 7672 §3.2.1.
///
/// The PKITS leaf has no `dNSName` SAN and the reference identity is
/// `mail.example`, so a name check would fail. That it succeeds is the
/// evidence the check was genuinely skipped.
#[test]
fn dane_ee_authenticates_without_a_name_check() {
    let leaf = load(VALID_EE_DER);
    let target = target_for(
        "mail.example",
        vec![full_cert_record(TlsaUsage::DaneEe, VALID_EE_DER)],
    );

    let verdict = verify(&target, &[leaf], &[VALID_EE_DER]).expect("well-formed call");
    match verdict {
        SmtpDaneVerdict::Authenticated {
            usage,
            path,
            matched_identity,
            ..
        } => {
            assert_eq!(usage, TlsaUsage::DaneEe);
            assert!(path.is_none(), "DANE-EE builds no path");
            assert!(
                matched_identity.is_none(),
                "§3.2.1 forbids a name check for DANE-EE, so none was matched"
            );
        }
        other => panic!("expected Authenticated, got {other:?}"),
    }
    assert!(verdict_permits(
        &verify(&target, &[load(VALID_EE_DER)], &[VALID_EE_DER]).unwrap()
    ));
}

fn verdict_permits(v: &SmtpDaneVerdict) -> bool {
    v.rfc7672_permits_delivery()
}

// ---------------------------------------------------------------------------
// Failure is a verdict, not an error — the property this design exists for
// ---------------------------------------------------------------------------

/// Usable records that do not match the presented certificate.
///
/// This is the case RFC 7672 §3.2 forbids delivering on, and the one an MTA
/// most needs to be told about: either the receiving server is misconfigured
/// or the connection is intercepted. It must arrive as `Ok(Failed(..))` so
/// the MTA can act on it.
#[test]
fn a_non_matching_record_is_a_verdict_not_an_error() {
    let leaf = load(VALID_EE_DER);
    // The record names a different certificate.
    let target = target_for(
        "mail.example",
        vec![full_cert_record(TlsaUsage::DaneEe, GOOD_CA_DER)],
    );

    let verdict = verify(&target, &[leaf], &[VALID_EE_DER])
        .expect("a mismatch is a verdict, not a malformed call");

    match &verdict {
        SmtpDaneVerdict::Failed(SmtpDaneFailure::NoRecordMatched(_)) => {}
        other => panic!("expected Failed(NoRecordMatched), got {other:?}"),
    }
    assert!(
        !verdict.rfc7672_permits_delivery(),
        "§3.2 forbids delivery once a usable secure record exists and fails"
    );
    assert!(!verdict.is_authenticated());
}

/// The two predicates say different things, and conflating them would let a
/// log claim an authenticated channel for an ordinary cleartext delivery.
#[test]
fn not_applicable_permits_delivery_but_is_not_authenticated() {
    let leaf = load(VALID_EE_DER);
    let target = target_for("mail.example", vec![]);

    let verdict = verify(&target, &[leaf], &[VALID_EE_DER]).expect("well-formed call");
    assert!(matches!(verdict, SmtpDaneVerdict::NotApplicable));
    assert!(
        verdict.rfc7672_permits_delivery(),
        "no records means pre-DANE opportunistic delivery, which is allowed"
    );
    assert!(
        !verdict.is_authenticated(),
        "nothing was authenticated — this must not be logged as a secure channel"
    );
}

// ---------------------------------------------------------------------------
// DANE-TA(2): path validation, then the §3.2.2 name check
// ---------------------------------------------------------------------------

/// A DANE-TA(2) record naming the CA validates a path but fails the name
/// check, because the PKITS leaf carries no name matching `mail.example`.
///
/// Reported as `NameCheckFailed` rather than as a generic mismatch: the
/// distinction tells a postmaster the certificate chains correctly but names
/// the wrong host, which is a different fix from a stale TLSA record.
#[test]
fn dane_ta_reports_a_name_check_failure_distinctly() {
    let leaf = load(VALID_EE_DER);
    let ca = load(GOOD_CA_DER);
    let target = target_for(
        "mail.example",
        vec![full_cert_record(TlsaUsage::DaneTa, GOOD_CA_DER)],
    );

    let verdict =
        verify(&target, &[leaf, ca], &[VALID_EE_DER, GOOD_CA_DER]).expect("well-formed call");

    match &verdict {
        SmtpDaneVerdict::Failed(SmtpDaneFailure::NameCheckFailed(_)) => {}
        other => panic!("expected Failed(NameCheckFailed), got {other:?}"),
    }
    assert!(!verdict.rfc7672_permits_delivery());
}

// ---------------------------------------------------------------------------
// §3.1.3: PKIX usages are unusable, and that is worth reporting
// ---------------------------------------------------------------------------

/// A domain publishing only PKIX-TA(0) / PKIX-EE(1) has published records that
/// cannot authenticate an SMTP connection.
///
/// Reported as a failure rather than as `NotApplicable`, because the
/// receiving domain believes it has configured DANE and has not — which its
/// postmaster would want to hear. It is also the honest reading: records
/// exist, and this profile declines to use them.
#[test]
fn only_pkix_usages_is_reported_as_a_failure() {
    let leaf = load(VALID_EE_DER);
    for usage in [TlsaUsage::PkixTa, TlsaUsage::PkixEe] {
        let target = target_for("mail.example", vec![full_cert_record(usage, VALID_EE_DER)]);
        let verdict = verify(&target, std::slice::from_ref(&leaf), &[VALID_EE_DER])
            .expect("well-formed call");
        match &verdict {
            SmtpDaneVerdict::Failed(SmtpDaneFailure::OnlyPkixUsages) => {}
            other => panic!(
                "usage {}: expected OnlyPkixUsages, got {other:?}",
                usage.to_octet()
            ),
        }
    }
}

/// A usage-3 record that fails to match does not mask usage-2 records that
/// succeed: both usages are tried before any verdict is reached.
#[test]
fn a_failing_usage_3_record_does_not_mask_a_usable_usage_2_record() {
    let leaf = load(VALID_EE_DER);
    let ca = load(GOOD_CA_DER);
    let target = target_for(
        "mail.example",
        vec![
            // Names the wrong certificate for usage 3.
            full_cert_record(TlsaUsage::DaneEe, TRUST_ANCHOR_DER),
            // Correctly names the CA for usage 2.
            full_cert_record(TlsaUsage::DaneTa, GOOD_CA_DER),
        ],
    );

    let verdict =
        verify(&target, &[leaf, ca], &[VALID_EE_DER, GOOD_CA_DER]).expect("well-formed call");

    // The name check still fails on PKITS certificates, but the verdict must
    // be the DANE-TA one — proving usage 2 was reached rather than the usage-3
    // mismatch terminating the search.
    match &verdict {
        SmtpDaneVerdict::Failed(SmtpDaneFailure::NameCheckFailed(_)) => {}
        other => panic!("expected the usage-2 path to be reached, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Malformed calls are errors, not verdicts
// ---------------------------------------------------------------------------

/// A chain that was never received supports no DANE conclusion, so it is an
/// error rather than a verdict.
#[test]
fn an_empty_chain_is_an_error() {
    let target = target_for(
        "mail.example",
        vec![full_cert_record(TlsaUsage::DaneEe, VALID_EE_DER)],
    );
    assert!(verify(&target, &[], &[]).is_err());
}

/// Index-misaligned inputs are a caller bug: matching digests the received
/// octets, so pairing a certificate with the wrong bytes would silently
/// compare the wrong things.
#[test]
fn a_misaligned_chain_der_is_an_error() {
    let leaf = load(VALID_EE_DER);
    let ca = load(GOOD_CA_DER);
    let target = target_for(
        "mail.example",
        vec![full_cert_record(TlsaUsage::DaneEe, VALID_EE_DER)],
    );
    assert!(
        verify(&target, &[leaf, ca], &[VALID_EE_DER]).is_err(),
        "two certificates and one DER entry must not be accepted"
    );
}

// ---------------------------------------------------------------------------
// DANE-TA(2) succeeding end to end
// ---------------------------------------------------------------------------

// The pkix-dane DANE fixtures, which unlike the PKITS set carry a dNSName SAN
// and so can satisfy a §3.2.2 name check. ca.der signs chain-leaf.der
// (verified with `openssl verify`), and chain-leaf carries
// `DNS:dane-test-chained.example.com`.
const DANE_CA_DER: &[u8] = include_bytes!("../../pkix-dane/tests/fixtures/ca.der");
const DANE_LEAF_DER: &[u8] = include_bytes!("../../pkix-dane/tests/fixtures/chain-leaf.der");
const DANE_LEAF_NAME: &str = "dane-test-chained.example.com";

/// Fixture validity starts in late 2026, so these tests use a later clock
/// than the PKITS ones.
const FIXTURE_NOW: u64 = 1_800_000_000; // 2027-01-15

fn verify_at(
    target: &DeliveryTarget,
    chain: &[Certificate],
    chain_der: &[&[u8]],
    now_unix: u64,
) -> Result<SmtpDaneVerdict, pkix_chain::Error> {
    verify_smtp_server_dane(
        target,
        chain,
        chain_der,
        &MtaProfile,
        now_unix,
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )
}

/// The whole DANE-TA(2) path: record names the CA, chain validates to the
/// synthesized anchor, and the leaf satisfies the §3.2.2 name check.
///
/// Without this, every DANE-TA assertion in this file would be a failure
/// case, and an implementation that could never authenticate via usage 2
/// would pass all of them.
#[test]
fn dane_ta_authenticates_a_chain_whose_leaf_matches_the_identity() {
    let leaf = load(DANE_LEAF_DER);
    let ca = load(DANE_CA_DER);
    let target = target_for(
        DANE_LEAF_NAME,
        vec![full_cert_record(TlsaUsage::DaneTa, DANE_CA_DER)],
    );

    let verdict = verify_at(
        &target,
        &[leaf, ca],
        &[DANE_LEAF_DER, DANE_CA_DER],
        FIXTURE_NOW,
    )
    .expect("well-formed call");

    match verdict {
        SmtpDaneVerdict::Authenticated {
            usage,
            path,
            matched_identity,
            ..
        } => {
            assert_eq!(usage, TlsaUsage::DaneTa);
            assert!(path.is_some(), "DANE-TA validates a path to the anchor");
            assert_eq!(
                matched_identity.as_deref(),
                Some(DANE_LEAF_NAME),
                "§3.2.2 requires a name check for usage 2, and it must report \
                 which identifier matched"
            );
        }
        other => panic!("expected Authenticated via DANE-TA, got {other:?}"),
    }
}

/// The same chain against a different reference identity fails the name
/// check, not the path.
///
/// Together with the test above this isolates the name check: the only input
/// that changed is the host discovery was for.
#[test]
fn dane_ta_rejects_the_same_chain_under_a_different_identity() {
    let leaf = load(DANE_LEAF_DER);
    let ca = load(DANE_CA_DER);
    let target = target_for(
        "someone-else.example.com",
        vec![full_cert_record(TlsaUsage::DaneTa, DANE_CA_DER)],
    );

    let verdict = verify_at(
        &target,
        &[leaf, ca],
        &[DANE_LEAF_DER, DANE_CA_DER],
        FIXTURE_NOW,
    )
    .expect("well-formed call");

    match &verdict {
        SmtpDaneVerdict::Failed(SmtpDaneFailure::NameCheckFailed(_)) => {}
        other => panic!("expected a name-check failure, got {other:?}"),
    }
    assert!(!verdict.rfc7672_permits_delivery());
}

/// A DANE-TA(2) record naming a CA that did not issue the chain fails during
/// path building, not during matching.
///
/// Worth asserting precisely, because the intuitive expectation is wrong. A
/// DANE-TA record does not have to name a certificate the peer sent — RFC
/// 7671 lets it designate an anchor by digest alone — so the record is
/// honoured and an anchor is synthesized from it. What then fails is reaching
/// that anchor from the presented chain.
///
/// The resulting verdict is the more useful one: "your chain does not reach
/// the anchor your TLSA record names" rather than "nothing matched".
#[test]
fn dane_ta_with_an_unrelated_anchor_fails_path_building() {
    let leaf = load(DANE_LEAF_DER);
    let ca = load(DANE_CA_DER);
    let target = target_for(
        DANE_LEAF_NAME,
        vec![full_cert_record(TlsaUsage::DaneTa, TRUST_ANCHOR_DER)],
    );

    let verdict = verify_at(
        &target,
        &[leaf, ca],
        &[DANE_LEAF_DER, DANE_CA_DER],
        FIXTURE_NOW,
    )
    .expect("well-formed call");

    match &verdict {
        SmtpDaneVerdict::Failed(SmtpDaneFailure::PathValidationFailed(_)) => {}
        other => panic!("expected PathValidationFailed, got {other:?}"),
    }
    assert!(!verdict.rfc7672_permits_delivery());
}
