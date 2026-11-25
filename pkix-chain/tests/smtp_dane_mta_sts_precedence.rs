//! RFC 8461 §2: MTA-STS must not override a failing DANE validation.
//!
//! > senders who implement MTA-STS validation MUST NOT allow MTA-STS Policy
//! > validation to override a failing DANE validation.
//!
//! The single most important correctness property when both of SMTP's
//! transport-security mechanisms are deployed, and the one whose failure mode
//! is silent: a matching MTA-STS policy quietly rescuing a delivery DANE had
//! already refused is exactly the downgrade DANE was deployed to prevent.
//!
//! Tested here rather than in `pkix-mta-sts`, which never sees a DANE verdict.

#![cfg(feature = "mta-sts")]

use pkix_chain::{
    combine_smtp_transport_security, SmtpDaneFailure, SmtpDaneVerdict, SmtpTransportDenial,
    SmtpTransportSecurity,
};
use pkix_dane::{TlsaMatchingType, TlsaRecord, TlsaSelector, TlsaUsage};
use pkix_mta_sts::PolicyOutcome;

/// A DANE failure. Which failure does not matter to §2.
fn dane_failed() -> SmtpDaneVerdict {
    SmtpDaneVerdict::Failed(SmtpDaneFailure::OnlyPkixUsages)
}

/// A genuinely authenticated DANE verdict.
///
/// `DaneEe`/`Cert`/`Full` is the usual SMTP-DANE shape. `path` is `None`
/// because RFC 7671 §5.1 has DANE-EE relax both identity and validity, so an
/// authenticated DANE-EE connection legitimately has no validated PKIX path.
fn dane_authenticated() -> SmtpDaneVerdict {
    SmtpDaneVerdict::Authenticated {
        usage: TlsaUsage::DaneEe,
        record: TlsaRecord::new(
            TlsaUsage::DaneEe,
            TlsaSelector::Cert,
            TlsaMatchingType::Full,
            vec![0x30, 0x82, 0x01, 0x0a],
        ),
        path: None,
        matched_identity: None,
    }
}

// ---------------------------------------------------------------------------
// §2, the rule itself
// ---------------------------------------------------------------------------

/// The case §2 exists to forbid: DANE fails, MTA-STS matches.
#[test]
fn a_matching_mta_sts_policy_does_not_override_a_dane_failure() {
    let combined = combine_smtp_transport_security(&dane_failed(), Some(PolicyOutcome::Matched));

    assert_eq!(
        combined,
        SmtpTransportSecurity::Forbidden(SmtpTransportDenial::DaneFailed),
        "§2: MTA-STS Policy validation MUST NOT override a failing DANE \
         validation — and the denial must name DANE, not MTA-STS, so an \
         operator can tell which mechanism refused"
    );
    assert!(!combined.permits_delivery());
    assert!(!combined.is_authenticated());
}

/// No MTA-STS outcome rescues a DANE failure, including the permissive ones.
///
/// The exhaustive version of the test above. If any outcome produced a
/// delivery-permitting result, §2 would be violated by that one input, and a
/// test of `Matched` alone would not have caught it.
#[test]
fn no_mta_sts_outcome_whatsoever_rescues_a_dane_failure() {
    for outcome in [
        None,
        Some(PolicyOutcome::Matched),
        Some(PolicyOutcome::FailedEnforce),
        Some(PolicyOutcome::FailedTesting),
        Some(PolicyOutcome::NoActivePolicy),
    ] {
        let combined = combine_smtp_transport_security(&dane_failed(), outcome);
        assert_eq!(
            combined,
            SmtpTransportSecurity::Forbidden(SmtpTransportDenial::DaneFailed),
            "MTA-STS outcome {outcome:?} must not change a DANE failure"
        );
        assert!(!combined.permits_delivery(), "outcome {outcome:?}");
    }
}

/// The precedence runs one way: MTA-STS does not downgrade DANE either.
///
/// §2 protects DANE's verdict. Nothing in RFC 8461 lets a policy failure
/// weaken an authenticated channel, so an `enforce` failure alongside a
/// successful DANE validation still delivers, authenticated.
#[test]
fn an_mta_sts_failure_does_not_downgrade_an_authenticated_dane_channel() {
    let authenticated = dane_authenticated();
    assert!(
        authenticated.is_authenticated(),
        "the fixture must really be authenticated, or this test proves nothing"
    );

    for outcome in [
        None,
        Some(PolicyOutcome::Matched),
        Some(PolicyOutcome::FailedEnforce),
        Some(PolicyOutcome::FailedTesting),
        Some(PolicyOutcome::NoActivePolicy),
    ] {
        let combined = combine_smtp_transport_security(&authenticated, outcome);
        assert_eq!(
            combined,
            SmtpTransportSecurity::DaneAuthenticated,
            "MTA-STS outcome {outcome:?} must not weaken an authenticated \
             DANE channel — §2's precedence protects DANE's verdict and runs \
             one way"
        );
        assert!(combined.permits_delivery(), "outcome {outcome:?}");
        assert!(combined.is_authenticated(), "outcome {outcome:?}");
    }
}

/// With no DANE verdict to defer to, §5's enforce rule applies.
///
/// The complement of the test above: it is MTA-STS that decides when DANE
/// does not apply, which is what makes the precedence rule meaningful rather
/// than MTA-STS being ignored outright.
#[test]
fn mta_sts_decides_when_dane_does_not_apply() {
    let combined = combine_smtp_transport_security(
        &SmtpDaneVerdict::NotApplicable,
        Some(PolicyOutcome::FailedEnforce),
    );
    assert_eq!(
        combined,
        SmtpTransportSecurity::Forbidden(SmtpTransportDenial::MtaStsEnforceFailed)
    );
    assert!(!combined.permits_delivery());
}

// ---------------------------------------------------------------------------
// The mechanisms stay distinguishable
// ---------------------------------------------------------------------------

/// MTA-STS success is reported as MTA-STS, never as DANE.
///
/// The user-facing reason the two variants are separate: a consumer must be
/// able to tell which mechanism authenticated a connection, because they are
/// not equally strong. MTA-STS is CA-rooted with an unsigned TXT record and
/// is trust-on-first-use; DANE is DNSSEC-rooted.
#[test]
fn an_mta_sts_match_is_not_reported_as_dane() {
    let combined = combine_smtp_transport_security(
        &SmtpDaneVerdict::NotApplicable,
        Some(PolicyOutcome::Matched),
    );
    assert_eq!(combined, SmtpTransportSecurity::MtaStsMatched);
    assert_ne!(
        combined,
        SmtpTransportSecurity::DaneAuthenticated,
        "the weaker mechanism must not be reported as the stronger one"
    );
    assert!(combined.is_authenticated());
    assert!(combined.permits_delivery());
}

/// Neither mechanism applying is permitted, not an error.
///
/// The overwhelming majority of SMTP has no transport-security policy. The
/// user's standing requirement is that mail stay deliverable when DANE does
/// not apply, with the fact recorded so it can be tagged or routed — which is
/// what `Unprotected` is.
#[test]
fn neither_mechanism_applying_still_permits_delivery() {
    let combined = combine_smtp_transport_security(&SmtpDaneVerdict::NotApplicable, None);
    assert_eq!(combined, SmtpTransportSecurity::Unprotected);
    assert!(
        combined.permits_delivery(),
        "mail to a domain with no policy must still be deliverable"
    );
    assert!(
        !combined.is_authenticated(),
        "but it must not be reported as authenticated"
    );
}

/// A `testing`-mode failure delivers, unauthenticated.
#[test]
fn a_testing_mode_failure_delivers_without_authentication() {
    let combined = combine_smtp_transport_security(
        &SmtpDaneVerdict::NotApplicable,
        Some(PolicyOutcome::FailedTesting),
    );
    assert_eq!(combined, SmtpTransportSecurity::Unprotected);
    assert!(
        combined.permits_delivery(),
        "§5: deliver as though no failure"
    );
    assert!(!combined.is_authenticated());
}

/// `permits_delivery` is false for exactly the forbidden outcomes.
#[test]
fn only_forbidden_outcomes_block_delivery() {
    assert!(SmtpTransportSecurity::DaneAuthenticated.permits_delivery());
    assert!(SmtpTransportSecurity::MtaStsMatched.permits_delivery());
    assert!(SmtpTransportSecurity::Unprotected.permits_delivery());
    assert!(!SmtpTransportSecurity::Forbidden(SmtpTransportDenial::DaneFailed).permits_delivery());
    assert!(
        !SmtpTransportSecurity::Forbidden(SmtpTransportDenial::MtaStsEnforceFailed)
            .permits_delivery()
    );
}
