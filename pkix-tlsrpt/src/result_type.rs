//! Result types — RFC 8460 §4.3.
//!
//! The vocabulary a report uses to say what went wrong. §4.3 notes the list
//! "will start with the minimal set below and is expected to grow over time
//! based on real-world experience", so the enum is `#[non_exhaustive]` and
//! deserialising preserves a value this version does not know.

use alloc::string::{String, ToString};

/// What went wrong with one session, per §4.3.
///
/// Serialises as the exact wire string §4.3 defines.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ResultType {
    // --- §4.3.1 negotiation failures ---
    /// `starttls-not-supported` — "the recipient MX did not support
    /// STARTTLS".
    StarttlsNotSupported,

    /// `certificate-host-mismatch` — "the certificate presented did not
    /// adhere to the constraints specified in the MTA-STS or DANE policy".
    ///
    /// Covers both an MX host failing MTA-STS's `mx` patterns and a
    /// certificate whose identities do not include the MX hostname.
    CertificateHostMismatch,

    /// `certificate-expired`.
    CertificateExpired,

    /// `certificate-not-trusted` — untrusted or unknown CAs, name-constraint
    /// violations, chain errors.
    ///
    /// §4.3.1: "When using this declaration, the reporting MTA SHOULD utilize
    /// the `failure-reason-code` to provide more information". A deliberately
    /// broad label, so the reason code is where the detail goes.
    CertificateNotTrusted,

    /// `validation-failure` — "a general failure for a reason not matching a
    /// category above".
    ///
    /// §4.3.3 asks a sender to use this rather than inventing a type, and to
    /// supply a `failure-reason-code`. The escape hatch that keeps the
    /// vocabulary stable as TLS changes.
    ValidationFailure,

    // --- §4.3.2.1 DANE-specific policy failures ---
    /// `tlsa-invalid` — "a validation error in the TLSA record associated
    /// with a DANE policy. None of the records in the RRset were found to be
    /// valid."
    TlsaInvalid,

    /// `dnssec-invalid` — "no valid records were returned from the recursive
    /// resolver".
    DnssecInvalid,

    /// `dane-required` — the sender requires DANE for this destination and
    /// no DNSSEC-validated TLSA records were present.
    ///
    /// RFC 7672 §6 mandatory DANE. Not a failure of the recipient's
    /// configuration so much as of an agreement between two organisations,
    /// which is why §4.3.2.1 describes it as arising "by mutual agreement".
    DaneRequired,

    // --- §4.3.2.2 MTA-STS-specific policy failures ---
    /// `sts-policy-fetch-error` — the policy could not be retrieved, "for
    /// example, because the policy host is unreachable".
    StsPolicyFetchError,

    /// `sts-policy-invalid` — "a validation error for the overall MTA-STS
    /// Policy".
    StsPolicyInvalid,

    /// `sts-webpki-invalid` — "the MTA-STS Policy could not be authenticated
    /// using PKIX validation".
    ///
    /// Distinct from [`StsPolicyFetchError`](Self::StsPolicyFetchError)
    /// because it is the one that matters: a policy fetched over a connection
    /// that did not authenticate is a policy an attacker may have written,
    /// and it is the only authentication an MTA-STS policy gets.
    StsWebpkiInvalid,

    /// A result type this version does not know.
    ///
    /// §4.3 expects the list to grow, so a report from a newer sender
    /// round-trips rather than failing to parse. Never produced by this
    /// crate's own classification.
    Other(String),
}

impl ResultType {
    /// The wire string §4.3 defines.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::StarttlsNotSupported => "starttls-not-supported",
            Self::CertificateHostMismatch => "certificate-host-mismatch",
            Self::CertificateExpired => "certificate-expired",
            Self::CertificateNotTrusted => "certificate-not-trusted",
            Self::ValidationFailure => "validation-failure",
            Self::TlsaInvalid => "tlsa-invalid",
            Self::DnssecInvalid => "dnssec-invalid",
            Self::DaneRequired => "dane-required",
            Self::StsPolicyFetchError => "sts-policy-fetch-error",
            Self::StsPolicyInvalid => "sts-policy-invalid",
            Self::StsWebpkiInvalid => "sts-webpki-invalid",
            Self::Other(s) => s,
        }
    }

    /// Whether this is a DANE policy failure (§4.3.2.1).
    #[must_use]
    pub const fn is_dane_policy_failure(&self) -> bool {
        matches!(
            self,
            Self::TlsaInvalid | Self::DnssecInvalid | Self::DaneRequired
        )
    }

    /// Whether this is an MTA-STS policy failure (§4.3.2.2).
    #[must_use]
    pub const fn is_sts_policy_failure(&self) -> bool {
        matches!(
            self,
            Self::StsPolicyFetchError | Self::StsPolicyInvalid | Self::StsWebpkiInvalid
        )
    }

    /// Whether §4.3.1/§4.3.3 ask for a `failure-reason-code` alongside this.
    ///
    /// True for the two deliberately broad labels, where the type alone does
    /// not tell the recipient enough to act.
    #[must_use]
    pub const fn wants_reason_code(&self) -> bool {
        matches!(self, Self::CertificateNotTrusted | Self::ValidationFailure)
    }
}

impl core::fmt::Display for ResultType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for ResultType {
    fn from(s: &str) -> Self {
        match s {
            "starttls-not-supported" => Self::StarttlsNotSupported,
            "certificate-host-mismatch" => Self::CertificateHostMismatch,
            "certificate-expired" => Self::CertificateExpired,
            "certificate-not-trusted" => Self::CertificateNotTrusted,
            "validation-failure" => Self::ValidationFailure,
            "tlsa-invalid" => Self::TlsaInvalid,
            "dnssec-invalid" => Self::DnssecInvalid,
            "dane-required" => Self::DaneRequired,
            "sts-policy-fetch-error" => Self::StsPolicyFetchError,
            "sts-policy-invalid" => Self::StsPolicyInvalid,
            "sts-webpki-invalid" => Self::StsWebpkiInvalid,
            other => Self::Other(other.to_string()),
        }
    }
}

impl serde::Serialize for ResultType {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ResultType {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(Self::from(s.as_str()))
    }
}
