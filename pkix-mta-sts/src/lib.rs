//! MTA-STS policy parsing and MX matching — RFC 8461.
//!
//! No DNS, no HTTP, no clock. A caller fetches the policy text and passes it
//! in, exactly as `pkix-dane` takes TLSA records rather than resolving them.
//! That keeps this crate `no_std` and leaves the fetching — which needs HTTPS,
//! certificate validation and a cache — to an adapter.
//!
//! ```
//! use pkix_mta_sts::{Mode, StsPolicy};
//!
//! let policy = StsPolicy::parse(
//!     "version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmx: *.example.net\r\nmax_age: 604800\r\n"
//! ).unwrap();
//!
//! assert_eq!(policy.mode(), Mode::Enforce);
//! assert!(policy.permits_mx("mail.example.com"));
//! assert!(policy.permits_mx("backup.example.net"));
//! assert!(!policy.permits_mx("example.net"));        // wildcard needs a label
//! assert!(!policy.permits_mx("evil.example.org"));
//! ```
//!
//! # MTA-STS is weaker than DANE, and the docs say so rather than implying parity
//!
//! Both upgrade opportunistic SMTP TLS into something downgrade-resistant, and
//! they do it from different roots of trust. RFC 8461 §1 is direct about the
//! trade:
//!
//! > DANE requires DNSSEC \[RFC4033\] for authentication; the mechanism
//! > described here instead relies on certification authorities (CAs) and does
//! > not require DNSSEC, at a cost of risking malicious downgrades.
//!
//! An MTA-STS policy is authenticated by the Web PKI plus an **unsigned** DNS
//! TXT record. First contact is therefore trust-on-first-use, and the
//! protection comes from caching a policy for up to a year. §10.2 names what
//! is lost: resistance to that class of downgrade "is a feature of DANE, due
//! to its use of DNSSEC for policy discovery".
//!
//! That is a reason to implement MTA-STS, not to refuse it — it deploys where
//! DNSSEC does not, which is most of the mail system. But a consumer should be
//! able to tell which mechanism authenticated a connection, so this crate
//! never reports a result that could be mistaken for a DANE one.
//!
//! # MTA-STS must not override a failing DANE validation
//!
//! RFC 8461 §2, verbatim:
//!
//! > senders who implement MTA-STS validation MUST NOT allow MTA-STS Policy
//! > validation to override a failing DANE validation.
//!
//! So a sender doing both consults DANE first. Where
//! `pkix_chain::verify_smtp_server_dane` returns
//! `SmtpDaneVerdict::Failed`, no MTA-STS result may rescue the delivery —
//! [`PolicyOutcome::Matched`] included. This crate cannot enforce that, since
//! it never sees a DANE verdict; the ordering belongs to whoever holds both.
//!
//! # Certificate validation wants a SAN, unlike SMTP DANE
//!
//! RFC 8461 §4.2 requires the MX certificate to carry "a subject alternative
//! name (SAN) \[RFC5280\] with a DNS-ID \[RFC6125\] matching the hostname".
//! That is ordinary Web PKI, so `pkix_profiles::BasicTlsProfile` is the right
//! profile here — the opposite of SMTP DANE, where RFC 7672 §3.2.3 consults
//! the `commonName` and a SAN-requiring profile rejects valid deployments.
//! Two SMTP transport-security mechanisms, two different correct profiles.

#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

// `#![no_std]` does not link std, so the `std` feature must ask for it
// explicitly. Only `InMemoryPolicyStore` uses it; every rule in this crate
// stays no_std.
#[cfg(feature = "std")]
extern crate std;

pub mod discovery;
pub mod store;

pub use discovery::{
    plan, policy_host, policy_to_apply, policy_url, txt_name, CachedPolicy, DiscoveryPlan,
    StsTxtRecord, TxtError,
};

pub use store::{
    in_backoff, newer_policy_published, note_failed_fetch, plan_with_store, record_fetched_policy,
    DiscoveryConfig, PolicyStore,
};

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub use store::InMemoryPolicyStore;

use alloc::string::String;
use alloc::vec::Vec;

/// RFC 8461 §3.2: `max_age` upper bound, in seconds.
///
/// "plaintext non-negative integer seconds, maximum value of 31557600" —
/// a Julian year. A policy declaring more is malformed.
pub const MAX_AGE_LIMIT: u64 = 31_557_600;

/// What a sender should do when policy validation fails (RFC 8461 §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Mode {
    /// `enforce`: "Sending MTAs MUST NOT deliver the message to hosts that
    /// fail MX matching or certificate validation or that do not support
    /// STARTTLS."
    Enforce,

    /// `testing`: report the failure where TLSRPT is implemented, and deliver
    /// "as though there were no MTA-STS validation failure".
    ///
    /// A deployment ramp, equivalent in spirit to DMARC `p=none`.
    Testing,

    /// `none`: "treat the Policy Domain as though it does not have any active
    /// policy".
    ///
    /// §8.3 uses this to withdraw MTA-STS without a window in which senders
    /// hold a cached policy for a domain that has stopped honouring it.
    None,
}

impl Mode {
    /// Whether this mode forbids delivery on a validation failure.
    ///
    /// True only for [`Enforce`](Self::Enforce). `Testing` and `None` both
    /// permit delivery; they differ in whether a report is expected.
    #[must_use]
    pub const fn forbids_delivery_on_failure(self) -> bool {
        matches!(self, Self::Enforce)
    }
}

/// Why a policy could not be parsed.
///
/// Every variant means the text is not a usable RFC 8461 policy. A sender
/// SHOULD treat an unparsable policy as absent rather than guessing, and
/// §5 requires such failures be treated as transient and retried.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyError {
    /// No `version` field. Required exactly once (§3.2).
    MissingVersion,

    /// `version` is not `STSv1`.
    ///
    /// The value is carried so a caller can log what a domain published; a
    /// future version is a reason to ignore the policy, not to fail loudly.
    UnsupportedVersion(String),

    /// No `mode` field. Required exactly once.
    MissingMode,

    /// `mode` is not `enforce`, `testing` or `none`.
    UnknownMode(String),

    /// No `max_age` field. Required exactly once.
    MissingMaxAge,

    /// `max_age` is not a non-negative integer, or exceeds
    /// [`MAX_AGE_LIMIT`].
    InvalidMaxAge(String),

    /// No `mx` field, in a mode that requires one.
    ///
    /// §3.2: `mx` is "required at least once, except when mode is `none`".
    MissingMx,

    /// A line is neither blank nor `key: value`.
    MalformedLine(String),
}

impl core::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingVersion => f.write_str("policy has no version field"),
            Self::UnsupportedVersion(v) => {
                write!(f, "unsupported policy version {v:?}, expected STSv1")
            }
            Self::MissingMode => f.write_str("policy has no mode field"),
            Self::UnknownMode(m) => {
                write!(f, "unknown mode {m:?}, expected enforce, testing or none")
            }
            Self::MissingMaxAge => f.write_str("policy has no max_age field"),
            Self::InvalidMaxAge(v) => {
                write!(f, "max_age {v:?} is not an integer in 0..={MAX_AGE_LIMIT}")
            }
            Self::MissingMx => f.write_str("policy has no mx field, which only mode none permits"),
            Self::MalformedLine(l) => write!(f, "line is not key: value: {l:?}"),
        }
    }
}

impl core::error::Error for PolicyError {}

/// A parsed MTA-STS policy (RFC 8461 §3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StsPolicy {
    mode: Mode,
    max_age: u64,
    mx: Vec<String>,
}

impl StsPolicy {
    /// Parse policy text.
    ///
    /// # Format
    ///
    /// CRLF-separated `key: value` pairs. Lines are also accepted with bare
    /// LF, because a policy is served over HTTP by arbitrary web servers and
    /// rejecting a policy over line endings would fail deployments that work
    /// everywhere else. Blank lines and surrounding whitespace are ignored.
    ///
    /// `version`, `mode` and `max_age` are required. `mx` is required at
    /// least once unless the mode is `none`. Repeated `mx` lines accumulate,
    /// each one its own `mx:` key as §3.2 requires.
    ///
    /// Unrecognized keys are **ignored**, not rejected: §3.2's ABNF admits
    /// `sts-policy-extension`, so a sender that refused unknown fields would
    /// break on the first extension anyone deploys.
    ///
    /// `max_age` is `1*10(DIGIT)` per the ABNF — digits only, so a leading
    /// `+`, an underscore separator and anything else `u64::from_str` would
    /// accept are rejected.
    ///
    /// Keywords are matched case-insensitively, deviating from the ABNF's
    /// case-sensitive `%s` literals. The reasoning is in the implementation:
    /// rejecting `mode: Enforce` would report no policy, and a sender with no
    /// policy applies no protection, so strictness fails in the dangerous
    /// direction.
    ///
    /// A repeated `version`, `mode` or `max_age` takes the last value. The
    /// ABNF says "required once", but no sender benefit comes from rejecting
    /// a domain's duplicate when the intent is unambiguous.
    ///
    /// # Errors
    ///
    /// See [`PolicyError`]. All of them mean the text is not a usable policy.
    pub fn parse(text: &str) -> Result<Self, PolicyError> {
        let mut version: Option<String> = None;
        let mut mode: Option<Mode> = None;
        let mut max_age: Option<u64> = None;
        let mut mx: Vec<String> = Vec::new();

        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            let Some((key, value)) = line.split_once(':') else {
                return Err(PolicyError::MalformedLine(String::from(line)));
            };
            let key = key.trim();
            let value = value.trim();

            // Keys and keyword values are matched case-INSENSITIVELY, which
            // deviates from the grammar. §3.2's ABNF writes every keyword with
            // RFC 7405's `%s` prefix — `%s"version"`, `%s"STSv1"`,
            // `%s"enforce"` — and `%s` means case-sensitive, so a conforming
            // policy spells them exactly as shown.
            //
            // Deviating deliberately, because strictness here fails in the
            // dangerous direction. A policy whose only defect is `mode:
            // Enforce` is unambiguous about what the domain wants; rejecting
            // it leaves the parser reporting no policy at all, and a sender
            // with no policy applies no protection. Leniency yields enforce,
            // strictness yields plaintext. The same holds for a miscased
            // field name.
            //
            // It costs nothing elsewhere: no two keywords in the grammar
            // differ only by case, so nothing becomes ambiguous. `STSv1`
            // matched case-insensitively still cannot swallow a future
            // `STSv2`, which differs in a digit.
            if key.eq_ignore_ascii_case("version") {
                version = Some(String::from(value));
            } else if key.eq_ignore_ascii_case("mode") {
                mode = Some(if value.eq_ignore_ascii_case("enforce") {
                    Mode::Enforce
                } else if value.eq_ignore_ascii_case("testing") {
                    Mode::Testing
                } else if value.eq_ignore_ascii_case("none") {
                    Mode::None
                } else {
                    return Err(PolicyError::UnknownMode(String::from(value)));
                });
            } else if key.eq_ignore_ascii_case("max_age") {
                // §3.2 ABNF: sts-policy-max-age-value = 1*10(DIGIT). Digits
                // and nothing else, so this rejects what u64::from_str would
                // otherwise accept — a leading `+`, and underscores — as well
                // as the signs, floats and suffixes the grammar excludes.
                if value.is_empty()
                    || value.len() > 10
                    || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(PolicyError::InvalidMaxAge(String::from(value)));
                }
                let parsed: u64 = value
                    .parse()
                    .map_err(|_| PolicyError::InvalidMaxAge(String::from(value)))?;
                if parsed > MAX_AGE_LIMIT {
                    return Err(PolicyError::InvalidMaxAge(String::from(value)));
                }
                max_age = Some(parsed);
            } else if key.eq_ignore_ascii_case("mx") && !value.is_empty() {
                // An empty `mx:` contributes no pattern. Not an error: it
                // permits nothing, so a policy carrying one is either still
                // rejected by the MissingMx check below or has other patterns
                // that stand on their own.
                mx.push(String::from(value));
            }
            // Anything else is an extension field. Ignored, per the ABNF.
        }

        let version = version.ok_or(PolicyError::MissingVersion)?;
        if !version.eq_ignore_ascii_case("STSv1") {
            return Err(PolicyError::UnsupportedVersion(version));
        }
        let mode = mode.ok_or(PolicyError::MissingMode)?;
        let max_age = max_age.ok_or(PolicyError::MissingMaxAge)?;
        if mx.is_empty() && mode != Mode::None {
            return Err(PolicyError::MissingMx);
        }

        Ok(Self { mode, max_age, mx })
    }

    /// The policy's mode.
    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.mode
    }

    /// `max_age` in seconds, at most [`MAX_AGE_LIMIT`].
    #[must_use]
    pub const fn max_age(&self) -> u64 {
        self.max_age
    }

    /// The `mx` patterns, in the order the policy listed them.
    #[must_use]
    pub fn mx_patterns(&self) -> &[String] {
        &self.mx
    }

    /// Whether `mx_host` is permitted by this policy (RFC 8461 §4.1).
    ///
    /// Matching is RFC 6125's, restricted so a `*` may only be the entire
    /// left-most label: `*.example.com` matches `mail.example.com` but neither
    /// `example.com` nor `foo.bar.example.com`. The rule comes from
    /// [`pkix_identity::dns_name_matches_pattern`] rather than being restated
    /// here.
    ///
    /// **Always false in [`Mode::None`]**, where a policy permits nothing
    /// because §5 says to treat the domain as having no active policy. A
    /// caller that reached this function in that mode has skipped the mode
    /// check; returning false is the safe answer, though
    /// [`evaluate`](Self::evaluate) is the better entry point.
    #[must_use]
    pub fn permits_mx(&self, mx_host: &str) -> bool {
        if self.mode == Mode::None {
            return false;
        }
        self.mx
            .iter()
            .any(|p| pkix_identity::dns_name_matches_pattern(p, mx_host))
    }

    /// Whether a policy fetched at `fetched_at_unix` is still live at
    /// `now_unix`.
    ///
    /// `max_age` runs "from the last policy fetch time" (§3.2). Takes the
    /// instant rather than reading a clock, so a caller pinning time — an
    /// offline replay, an audit — gets the same answer every run. The same
    /// reason `pkix-path` takes `now_unix`.
    ///
    /// A clock that has gone backwards past the fetch time yields `false`:
    /// treating an unmeasurable age as fresh would extend a policy
    /// indefinitely.
    #[must_use]
    pub const fn is_live_at(&self, fetched_at_unix: u64, now_unix: u64) -> bool {
        match now_unix.checked_sub(fetched_at_unix) {
            Some(age) => age < self.max_age,
            None => false,
        }
    }

    /// Apply the policy to one candidate MX host.
    ///
    /// The entry point a sender wants: it folds the mode check and the MX
    /// match into one answer, so neither can be forgotten.
    #[must_use]
    pub fn evaluate(&self, mx_host: &str) -> PolicyOutcome {
        match self.mode {
            Mode::None => PolicyOutcome::NoActivePolicy,
            _ if self.permits_mx(mx_host) => PolicyOutcome::Matched,
            Mode::Enforce => PolicyOutcome::FailedEnforce,
            Mode::Testing => PolicyOutcome::FailedTesting,
        }
    }
}

/// What a policy says about one candidate MX host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PolicyOutcome {
    /// The host matches an `mx` pattern.
    ///
    /// MX matching passed. Certificate validation and STARTTLS support are
    /// separate requirements (§4.2, §5) and this says nothing about them.
    ///
    /// It also says nothing about DANE. §2 forbids an MTA-STS result from
    /// overriding a failing DANE validation, so a sender doing both must
    /// consult DANE first.
    Matched,

    /// The host matches no pattern, and the mode is `enforce`.
    ///
    /// §5: "Sending MTAs MUST NOT deliver the message to hosts that fail MX
    /// matching". §5 also requires such a failure be treated as transient and
    /// retried, after re-checking DNS for an updated policy, rather than
    /// bounced.
    FailedEnforce,

    /// The host matches no pattern, and the mode is `testing`.
    ///
    /// Delivery may proceed "as though there were no MTA-STS validation
    /// failure". A sender implementing TLSRPT should report it.
    FailedTesting,

    /// The mode is `none`: the domain has no active policy.
    NoActivePolicy,
}

impl PolicyOutcome {
    /// Whether MTA-STS alone permits delivery to this host.
    ///
    /// False only for [`FailedEnforce`](Self::FailedEnforce).
    ///
    /// **Not sufficient on its own.** §4.2 still requires certificate
    /// validation, §5 requires STARTTLS, and §2 forbids this from overriding
    /// a failing DANE validation. True means "MTA-STS raises no objection",
    /// not "deliver".
    #[must_use]
    pub const fn mta_sts_permits_delivery(self) -> bool {
        !matches!(self, Self::FailedEnforce)
    }

    /// Whether this is a validation failure, whatever the mode does about it.
    ///
    /// True for both [`FailedEnforce`](Self::FailedEnforce) and
    /// [`FailedTesting`](Self::FailedTesting). A sender implementing TLSRPT
    /// reports on this rather than on the delivery decision, which is the
    /// distinction `testing` mode exists to create.
    #[must_use]
    pub const fn is_validation_failure(self) -> bool {
        matches!(self, Self::FailedEnforce | Self::FailedTesting)
    }
}
