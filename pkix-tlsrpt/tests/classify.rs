//! Classifying the workspace's failures into §4.3 result types.

#![cfg(all(feature = "mta-sts-http", feature = "dane"))]

use pkix_tlsrpt::classify::{
    classify_chain_error, classify_dane_failure, classify_fetch_error, classify_path_error,
    classify_policy_outcome,
};
use pkix_tlsrpt::ResultType;

// ---------------------------------------------------------------------------
// MTA-STS policy outcomes
// ---------------------------------------------------------------------------

/// A failed MX match is `certificate-host-mismatch` (§4.3.1).
///
/// And it is the same type in `testing` mode as in `enforce`. That is the
/// point of `testing`: the failure is reported while the mail is delivered
/// anyway, so a domain can see what enforcing would break. A classifier that
/// returned `None` for a testing failure would make the mode useless.
#[test]
fn both_mta_sts_failure_outcomes_classify_the_same_way() {
    use pkix_mta_sts::PolicyOutcome;
    assert_eq!(
        classify_policy_outcome(PolicyOutcome::FailedEnforce),
        Some(ResultType::CertificateHostMismatch)
    );
    assert_eq!(
        classify_policy_outcome(PolicyOutcome::FailedTesting),
        Some(ResultType::CertificateHostMismatch),
        "a testing-mode failure IS reported — that is what the mode is for"
    );
}

/// Successes are not failure details.
#[test]
fn successful_outcomes_produce_no_result_type() {
    use pkix_mta_sts::PolicyOutcome;
    assert_eq!(classify_policy_outcome(PolicyOutcome::Matched), None);
    assert_eq!(classify_policy_outcome(PolicyOutcome::NoActivePolicy), None);
}

// ---------------------------------------------------------------------------
// MTA-STS policy fetching (§4.3.2.2)
// ---------------------------------------------------------------------------

/// A policy that was served and is not a policy is `sts-policy-invalid`.
#[test]
fn a_malformed_policy_is_sts_policy_invalid() {
    use pkix_mta_sts_http::FetchError;
    let (t, _) = classify_fetch_error(&FetchError::Malformed(
        pkix_mta_sts::PolicyError::MissingMode,
    ));
    assert_eq!(t, ResultType::StsPolicyInvalid);
    assert!(t.is_sts_policy_failure());
}

/// Failures to retrieve are `sts-policy-fetch-error`.
#[test]
fn retrieval_failures_are_sts_policy_fetch_error() {
    use pkix_mta_sts_http::FetchError;
    for e in [
        FetchError::HttpStatus(404),
        FetchError::HttpStatus(500),
        FetchError::RedirectRefused(301),
        FetchError::BodyTooLarge(65_536),
        FetchError::DestinationRefused(String::from("mta-sts.x.test")),
        FetchError::Timeout,
        FetchError::Transport(String::from("connection refused")),
    ] {
        let (t, _) = classify_fetch_error(&e);
        assert_eq!(
            t,
            ResultType::StsPolicyFetchError,
            "{e:?} is a failure to retrieve a usable policy"
        );
    }
}

/// The documented gap: `sts-webpki-invalid` is never produced.
///
/// §4.3.2.2 defines it as "the MTA-STS Policy could not be authenticated
/// using PKIX validation", which is the most security-relevant thing a report
/// can say about MTA-STS — the HTTPS certificate is the policy's only
/// authentication.
///
/// `FetchError::Transport` carries both a certificate that did not validate
/// and a connection that was refused, as one opaque string. Classifying it as
/// `sts-webpki-invalid` would tell a domain its certificate is broken
/// whenever its policy host is merely down, so the stronger claim is left
/// unmade.
///
/// Asserted so the limitation is visible in the test suite and not only in a
/// doc comment — and so that whoever adds a TLS-specific `FetchError` variant
/// sees this test fail and updates the mapping.
#[test]
fn sts_webpki_invalid_is_never_produced_and_this_is_deliberate() {
    use pkix_mta_sts_http::FetchError;
    for e in [
        FetchError::Transport(String::from("certificate verify failed")),
        FetchError::Transport(String::from("connection refused")),
        FetchError::Timeout,
        FetchError::HttpStatus(500),
        FetchError::DestinationRefused(String::from("h")),
        FetchError::UnexpectedMediaType(String::from("text/html")),
        FetchError::BodyTooLarge(1),
        FetchError::RedirectRefused(302),
    ] {
        let (t, _) = classify_fetch_error(&e);
        assert_ne!(
            t,
            ResultType::StsWebpkiInvalid,
            "FetchError cannot distinguish a TLS failure from a network one, \
             so claiming sts-webpki-invalid would mislead an operator into \
             chasing a certificate that is fine"
        );
    }
}

/// Reason codes name a class and never quote the error.
///
/// A report travels to an address taken from unsigned DNS (§3), and an error
/// string can carry a URL or a host name. §4.3.3 wants "a short text field...
/// an error code or error text", which is a classification, not a message.
#[test]
fn reason_codes_do_not_leak_the_error_text() {
    use pkix_mta_sts_http::FetchError;
    let secret = "https://mta-sts.internal.corp.example/secret-path";
    for e in [
        FetchError::Transport(String::from(secret)),
        FetchError::DestinationRefused(String::from(secret)),
        FetchError::UnexpectedMediaType(String::from(secret)),
    ] {
        let (_, code) = classify_fetch_error(&e);
        if let Some(code) = code {
            assert!(
                !code.contains("internal") && !code.contains("secret"),
                "reason code {code:?} leaked the error text"
            );
        }
    }
}

/// A status code's class is kept, since it is diagnostic and not sensitive.
#[test]
fn the_http_status_is_kept_in_the_reason_code() {
    use pkix_mta_sts_http::FetchError;
    let (_, code) = classify_fetch_error(&FetchError::HttpStatus(404));
    assert_eq!(code.as_deref(), Some("http-status-404"));
}

// ---------------------------------------------------------------------------
// DANE (§4.3.2.1)
// ---------------------------------------------------------------------------

/// A name-check failure is `certificate-host-mismatch`.
#[test]
fn a_dane_name_check_failure_is_a_host_mismatch() {
    use pkix_chain::SmtpDaneFailure;
    use pkix_dane::smtp::SmtpNameError;
    let (t, _) = classify_dane_failure(&SmtpDaneFailure::NameCheckFailed(
        SmtpNameError::NoIdentityMatch,
    ));
    assert_eq!(t, ResultType::CertificateHostMismatch);
}

/// A TLSA RRset with only PKIX usages has no usable record.
///
/// RFC 7672 §3.1.3 leaves the PKIX usages undefined for SMTP, so §4.3.2.1's
/// `tlsa-invalid` — "None of the records in the RRset were found to be valid"
/// — is exactly the situation.
#[test]
fn only_pkix_usages_is_tlsa_invalid() {
    use pkix_chain::SmtpDaneFailure;
    let (t, code) = classify_dane_failure(&SmtpDaneFailure::OnlyPkixUsages);
    assert_eq!(t, ResultType::TlsaInvalid);
    assert!(t.is_dane_policy_failure());
    assert_eq!(code.as_deref(), Some("only-pkix-usages"));
}

/// An unvalidated DNS answer is `dnssec-invalid`, not `tlsa-invalid`.
///
/// §4.3.2.1 separates them: `dnssec-invalid` is "no valid records were
/// returned from the recursive resolver", while `tlsa-invalid` is a defect in
/// records that did arrive. A domain whose DNSSEC is broken needs to be told
/// that, not that its TLSA records are wrong.
#[test]
fn a_dnssec_problem_is_distinguished_from_a_tlsa_problem() {
    use pkix_chain::SmtpDaneFailure;
    use pkix_dane::DaneError;

    let (t, _) = classify_dane_failure(&SmtpDaneFailure::NoRecordMatched(
        DaneError::ResolutionDisabled,
    ));
    assert_eq!(t, ResultType::DnssecInvalid);

    let (t, _) = classify_dane_failure(&SmtpDaneFailure::NoRecordMatched(
        DaneError::SpkiEncodingFailed,
    ));
    assert_eq!(
        t,
        ResultType::TlsaInvalid,
        "a record-level defect is not a DNSSEC problem"
    );
}

// ---------------------------------------------------------------------------
// Path and chain errors (§4.3.1)
// ---------------------------------------------------------------------------

/// An expired certificate gets its own type rather than the broad label.
///
/// The single most actionable thing a report can tell an operator, so folding
/// it into `certificate-not-trusted` would waste the report.
#[test]
fn an_expired_certificate_is_certificate_expired() {
    let (t, _) = classify_path_error(&pkix_path::Error::ValidityPeriod { index: 0 });
    assert_eq!(t, ResultType::CertificateExpired);
    assert!(!t.wants_reason_code(), "the type says enough on its own");
}

/// Chain failures are `certificate-not-trusted` with a reason code.
///
/// §4.3.1 names these cases directly: "untrusted/unknown certification
/// authorities (CAs), certificate name constraints, certificate chain
/// errors", and asks for a reason code because the label is broad.
#[test]
fn chain_failures_are_certificate_not_trusted_with_a_reason() {
    let (t, code) = classify_path_error(&pkix_path::Error::NoTrustedPath);
    assert_eq!(t, ResultType::CertificateNotTrusted);
    assert_eq!(code.as_deref(), Some("no-trusted-path"));
    assert!(
        t.wants_reason_code(),
        "§4.3.1 asks for a reason code with this label, and one is supplied"
    );
}

/// A missing SAN is an identity failure, not a trust failure.
#[test]
fn a_missing_san_is_a_host_mismatch() {
    let (t, _) = classify_path_error(&pkix_path::Error::MissingSan);
    assert_eq!(t, ResultType::CertificateHostMismatch);
}

/// A chain error delegates to the layer that failed.
#[test]
fn a_chain_error_delegates_to_its_inner_layer() {
    let inner = pkix_path::Error::ValidityPeriod { index: 0 };
    assert_eq!(
        classify_chain_error(&pkix_chain::Error::Path(inner.clone())).0,
        classify_path_error(&inner).0,
        "wrapping a path error must not change its classification"
    );
}

/// Revocation has no §4.3 type, so it takes the broad label with a reason.
///
/// A revoked certificate is one a sender must not trust, and §4.3.1 words
/// `certificate-not-trusted` as covering "multiple certificate-related
/// failures that include, but are not limited to" the cases it lists. The
/// reason code says which this was, since the type alone would suggest a
/// chain problem.
#[test]
fn revocation_takes_the_broad_label_with_a_reason_code() {
    let (t, code) = classify_chain_error(&pkix_chain::Error::Revocation(
        pkix_revocation::Error::CrlIssuerMismatch,
    ));
    assert_eq!(t, ResultType::CertificateNotTrusted);
    assert!(
        code.is_some_and(|c| c.contains("revoke") || c.contains("revocation")),
        "the reason code must say it was revocation, since the type does not"
    );
}

/// Every classification of a broad label supplies the reason code §4.3 asks
/// for.
///
/// The invariant worth holding across the whole mapping: if a result type
/// wants a reason code, the classifier should give one. Checked over a spread
/// of real errors rather than asserted per case.
#[test]
fn broad_labels_always_come_with_a_reason_code() {
    let cases: Vec<(ResultType, Option<String>)> = vec![
        classify_path_error(&pkix_path::Error::NoTrustedPath),
        classify_path_error(&pkix_path::Error::MissingSan),
        classify_path_error(&pkix_path::Error::ValidityPeriod { index: 0 }),
        classify_chain_error(&pkix_chain::Error::Revocation(
            pkix_revocation::Error::CrlIssuerMismatch,
        )),
        classify_fetch_error(&pkix_mta_sts_http::FetchError::Timeout),
        classify_dane_failure(&pkix_chain::SmtpDaneFailure::OnlyPkixUsages),
    ];
    for (t, code) in cases {
        if t.wants_reason_code() {
            assert!(
                code.is_some(),
                "{t} is a broad label and §4.3 asks for a reason code with it"
            );
        }
    }
}
