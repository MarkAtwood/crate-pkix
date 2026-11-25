//! Classifying the workspace's own failures into §4.3 result types.
//!
//! The bridge that makes TLSRPT usable from the rest of the workspace. Each
//! mapping is behind a feature so a DANE-only reporter does not pull in
//! MTA-STS, and a reporter using its own TLS stack pulls in neither.
//!
//! # Why the mapping lives here and not on the errors
//!
//! Every alternative is worse. Putting `fn to_result_type()` on
//! `SmtpDaneFailure` would make `pkix-chain` depend on a reporting crate it
//! otherwise has no use for; scattering `From` impls across the error-owning
//! crates would put one RFC's vocabulary in five places. Here they sit
//! together, so the §4.3 list can be read against what actually produces each
//! value — and the gaps are visible, which matters more than the mappings.
//!
//! # Notes on particular mappings
//!
//! **`sts-webpki-invalid` comes from
//! [`FetchError::TlsValidation`](pkix_mta_sts_http::FetchError::TlsValidation),
//! and only from it.** §4.3.2.2 defines it as "the MTA-STS Policy could not
//! be authenticated using PKIX validation", the most security-relevant thing
//! a report can say about MTA-STS: the HTTPS certificate is the policy's only
//! authentication, so a policy fetched over a connection that did not
//! authenticate is a policy an attacker may have written.
//!
//! `FetchError::Transport` is deliberately **not** mapped to it. A refused
//! connection means the web server is down, and reporting that as a
//! certificate failure would send an operator after a certificate that is
//! fine. The two were one variant until `FetchError::TlsValidation` was
//! added precisely so this distinction could be reported.
//!
//! **Transient failures are not classified.** §4.3.4: "Transient errors due
//! to too-busy networks, TCP timeouts, etc., are not required to be
//! reported." A timeout therefore classifies as a fetch error if a caller
//! asks, but a caller is free to drop it instead, and should.

// Both are used only by the feature-gated classifiers below, so with no
// classification feature enabled they would be unused imports — which the
// bare-metal gate builds with `-D warnings` and rejects.
#[cfg(any(feature = "mta-sts-http", feature = "dane"))]
use alloc::string::ToString;

#[cfg(any(feature = "mta-sts", feature = "mta-sts-http", feature = "dane"))]
use crate::ResultType;

// ---------------------------------------------------------------------------
// MTA-STS policy outcomes
// ---------------------------------------------------------------------------

/// Classify an MTA-STS MX-matching outcome (§4.3.1).
///
/// `None` when nothing failed. A matched policy and an absent policy are both
/// successes as far as a report is concerned, and §4.2.1 counts them in
/// `total-successful-session-count` rather than as details.
///
/// A failed MX match is `certificate-host-mismatch`, which §4.3.1 defines as
/// the certificate not adhering "to the constraints specified in the MTA-STS
/// or DANE policy" — the MX host not matching the policy's `mx` patterns is
/// exactly that constraint.
///
/// Both failure outcomes classify the same way, including the `testing` one.
/// That is the point of `testing` mode: the failure is reported while the mail
/// is delivered anyway, so a domain can see what enforcing would break.
#[cfg(feature = "mta-sts")]
#[cfg_attr(docsrs, doc(cfg(feature = "mta-sts")))]
#[must_use]
pub fn classify_policy_outcome(outcome: pkix_mta_sts::PolicyOutcome) -> Option<ResultType> {
    if outcome.is_validation_failure() {
        Some(ResultType::CertificateHostMismatch)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// MTA-STS policy fetching
// ---------------------------------------------------------------------------

/// Classify an MTA-STS policy fetch failure (§4.3.2.2).
///
/// Returns the result type and, where §4.3.3 asks for one, a short reason
/// code. The code is a classification rather than the error's text, because
/// a report travels to an address from unsigned DNS and an error string can
/// carry a URL or a host name.
///
/// See the module documentation on why `sts-webpki-invalid` is never
/// returned.
#[cfg(feature = "mta-sts-http")]
#[cfg_attr(docsrs, doc(cfg(feature = "mta-sts-http")))]
#[must_use]
pub fn classify_fetch_error(
    error: &pkix_mta_sts_http::FetchError,
) -> (ResultType, Option<alloc::string::String>) {
    use pkix_mta_sts_http::FetchError as E;
    match error {
        // The policy was served and is not a policy. §4.3.2.2's
        // sts-policy-invalid: "a validation error for the overall MTA-STS
        // Policy".
        E::Malformed(_) => (ResultType::StsPolicyInvalid, None),

        // §4.3.2.2 sts-webpki-invalid: "the MTA-STS Policy could not be
        // authenticated using PKIX validation". The most security-relevant
        // thing a report can say about MTA-STS, because the HTTPS
        // certificate is the policy's only authentication — so a policy
        // fetched over a connection that did not authenticate is a policy an
        // attacker may have written.
        E::TlsValidation(_) => (ResultType::StsWebpkiInvalid, None),

        // A body served under the wrong media type is also a defect in what
        // the domain published rather than a failure to reach it, so it is a
        // policy problem and not a fetch problem.
        E::UnexpectedMediaType(_) => (
            ResultType::StsPolicyInvalid,
            Some("unexpected-media-type".to_string()),
        ),

        // Everything else is a failure to retrieve a usable policy. The
        // reason codes name the class, never the host or URL.
        E::HttpStatus(code) => (
            ResultType::StsPolicyFetchError,
            Some(alloc::format!("http-status-{code}")),
        ),
        E::RedirectRefused(_) => (
            ResultType::StsPolicyFetchError,
            Some("redirect-refused".to_string()),
        ),
        E::BodyTooLarge(_) => (
            ResultType::StsPolicyFetchError,
            Some("body-too-large".to_string()),
        ),
        E::DestinationRefused(_) => (
            ResultType::StsPolicyFetchError,
            Some("destination-refused".to_string()),
        ),
        E::Timeout => (ResultType::StsPolicyFetchError, Some("timeout".to_string())),
        E::Transport(_) => (
            ResultType::StsPolicyFetchError,
            Some("transport".to_string()),
        ),
        // FetchError is non_exhaustive; an unknown variant is still a failure
        // to obtain a usable policy, which is the honest default.
        _ => (ResultType::StsPolicyFetchError, None),
    }
}

// ---------------------------------------------------------------------------
// DANE
// ---------------------------------------------------------------------------

/// Classify an SMTP DANE failure (§4.3.1, §4.3.2.1).
///
/// Returns the result type and, where §4.3.3 asks for one, a short reason
/// code naming the class rather than quoting the error.
#[cfg(feature = "dane")]
#[cfg_attr(docsrs, doc(cfg(feature = "dane")))]
#[must_use]
pub fn classify_dane_failure(
    failure: &pkix_chain::SmtpDaneFailure,
) -> (ResultType, Option<alloc::string::String>) {
    use pkix_chain::SmtpDaneFailure as F;
    match failure {
        // §4.3.2.1 tlsa-invalid: "None of the records in the RRset were found
        // to be valid." Except for the DNSSEC case, which has its own type.
        F::NoRecordMatched(e) => classify_dane_error(e),

        // The certificate chain did not validate. Which §4.3.1 label applies
        // depends on why, so defer to the chain classification.
        F::PathValidationFailed(e) => classify_chain_error(e),

        // The certificate does not bind to the MX host.
        F::NameCheckFailed(_) => (ResultType::CertificateHostMismatch, None),

        // RFC 7672 §3.1.3 leaves the PKIX usages undefined for SMTP, so a
        // TLSA RRset containing only those has no usable record — which is
        // what tlsa-invalid says.
        F::OnlyPkixUsages => (
            ResultType::TlsaInvalid,
            Some("only-pkix-usages".to_string()),
        ),
        _ => (ResultType::ValidationFailure, None),
    }
}

/// Classify a TLSA matching failure.
#[cfg(feature = "dane")]
fn classify_dane_error(
    error: &pkix_dane::DaneError,
) -> (ResultType, Option<alloc::string::String>) {
    use pkix_dane::DaneError as E;
    match error {
        // §4.3.2.1 dnssec-invalid: "no valid records were returned from the
        // recursive resolver". Both of these are that: one because the answer
        // was not Secure, one because there was no answer.
        E::DnssecNotSecure { .. } => (ResultType::DnssecInvalid, None),
        E::ResolutionFailed(_) => (
            ResultType::DnssecInvalid,
            Some("resolution-failed".to_string()),
        ),
        E::ResolutionDisabled => (
            ResultType::DnssecInvalid,
            Some("resolution-disabled".to_string()),
        ),
        // Everything else is a TLSA RRset that yielded no valid record.
        _ => (ResultType::TlsaInvalid, None),
    }
}

/// Classify a chain-verification failure (§4.3.1).
///
/// `pkix_chain::Error` wraps the layer that failed, so each arm hands off to
/// the classifier for that layer rather than restating its cases.
#[cfg(feature = "dane")]
#[cfg_attr(docsrs, doc(cfg(feature = "dane")))]
#[must_use]
pub fn classify_chain_error(
    error: &pkix_chain::Error,
) -> (ResultType, Option<alloc::string::String>) {
    use pkix_chain::Error as E;
    match error {
        E::Path(e) => classify_path_error(e),

        // The certificate does not bind to the MX host.
        E::Identity(_) => (ResultType::CertificateHostMismatch, None),

        // Revocation is not among §4.3's result types. A revoked certificate
        // is a certificate a sender must not trust, so certificate-not-trusted
        // is the honest label — §4.3.1 words it as covering "multiple
        // certificate-related failures that include, but are not limited to"
        // the cases it lists, and the reason code says which this was.
        E::Revocation(_) => (
            ResultType::CertificateNotTrusted,
            Some("revoked-or-unknown-revocation-status".to_string()),
        ),

        // A profile rule the sender imposes, not a defect the recipient
        // published. Still reportable: the recipient cannot fix what it does
        // not know about.
        E::ProfileViolation { .. } => (
            ResultType::ValidationFailure,
            Some("profile-violation".to_string()),
        ),
        E::OcspDelegation { .. } => (
            ResultType::CertificateNotTrusted,
            Some("ocsp-delegation".to_string()),
        ),
        E::Aia(_) => (
            ResultType::CertificateNotTrusted,
            Some("aia-fetch-failed".to_string()),
        ),
        _ => (ResultType::ValidationFailure, None),
    }
}

/// Classify a path-validation failure into a §4.3.1 negotiation failure.
///
/// §4.3.1's `certificate-not-trusted` is explicitly broad — "untrusted/
/// unknown certification authorities (CAs), certificate name constraints,
/// certificate chain errors, etc." — so most chain failures land there with a
/// reason code, and only expiry and identity get their own types.
#[cfg(feature = "dane")]
#[cfg_attr(docsrs, doc(cfg(feature = "dane")))]
#[must_use]
pub fn classify_path_error(
    error: &pkix_path::Error,
) -> (ResultType, Option<alloc::string::String>) {
    use pkix_path::Error as E;
    match error {
        // §4.3.1 has its own type for this, so use it rather than folding it
        // into certificate-not-trusted: an expired certificate is the single
        // most actionable thing a report can tell an operator.
        E::ValidityPeriod { .. } => (ResultType::CertificateExpired, None),

        // No identity in the certificate matches the MX host.
        E::MissingSan | E::MissingRfc822San => (ResultType::CertificateHostMismatch, None),

        // The chain itself did not validate. §4.3.1 names these cases
        // directly under certificate-not-trusted.
        E::NoTrustedPath => (
            ResultType::CertificateNotTrusted,
            Some("no-trusted-path".to_string()),
        ),
        E::ChainBroken { .. } => (
            ResultType::CertificateNotTrusted,
            Some("chain-broken".to_string()),
        ),
        E::SignatureInvalid { .. } | E::SignatureNotVerified { .. } => (
            ResultType::CertificateNotTrusted,
            Some("signature-invalid".to_string()),
        ),
        E::NameConstraintViolation { .. } => (
            ResultType::CertificateNotTrusted,
            Some("name-constraint-violation".to_string()),
        ),
        E::PathTooLong => (
            ResultType::CertificateNotTrusted,
            Some("path-too-long".to_string()),
        ),
        E::NotCA { .. } => (
            ResultType::CertificateNotTrusted,
            Some("not-a-ca".to_string()),
        ),

        // §4.3.3: when a negotiation failure fits no category, use
        // validation-failure and supply a reason code. §4.3.3's own example
        // of a reason code is an X.509 error constant, which is the register
        // these are written in.
        E::UnhandledCriticalExtension { .. } => (
            ResultType::ValidationFailure,
            Some("unhandled-critical-extension".to_string()),
        ),
        E::PolicyViolation { .. } => (
            ResultType::ValidationFailure,
            Some("policy-violation".to_string()),
        ),
        E::AlgorithmNotAllowed { .. } => (
            ResultType::ValidationFailure,
            Some("algorithm-not-allowed".to_string()),
        ),
        E::KeyTooSmall { .. } => (
            ResultType::ValidationFailure,
            Some("key-too-small".to_string()),
        ),
        E::MalformedCertificate { .. } | E::Der(_) => (
            ResultType::ValidationFailure,
            Some("malformed-certificate".to_string()),
        ),
        _ => (ResultType::ValidationFailure, None),
    }
}
