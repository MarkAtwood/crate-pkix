//! The report schema — RFC 8460 §4.4 — and the filename — §5.1.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::{rfc3339_utc, ResultType};

/// Which mechanism's policy was applied (§4.4 `policy-type`).
///
/// "Presently, the only three valid choices are `tlsa`, `sts`, and the
/// literal string `no-policy-found`."
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PolicyType {
    /// A DANE TLSA policy.
    Tlsa,
    /// An MTA-STS policy.
    Sts,
    /// Neither applied.
    ///
    /// Still worth reporting: §4.2 counts successful sessions too, so a
    /// domain can see how much of its mail arrives with no policy in force.
    NoPolicyFound,
    /// A policy type this version does not know, preserved on round trip.
    Other(String),
}

impl PolicyType {
    /// The wire string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Tlsa => "tlsa",
            Self::Sts => "sts",
            Self::NoPolicyFound => "no-policy-found",
            Self::Other(s) => s,
        }
    }
}

impl core::fmt::Display for PolicyType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for PolicyType {
    fn from(s: &str) -> Self {
        match s {
            "tlsa" => Self::Tlsa,
            "sts" => Self::Sts,
            "no-policy-found" => Self::NoPolicyFound,
            other => Self::Other(other.to_string()),
        }
    }
}

impl serde::Serialize for PolicyType {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for PolicyType {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(Self::from(s.as_str()))
    }
}

/// The report's time range (§4.1).
///
/// "The report should be for a full UTC day, 00:00-24:00."
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DateRange {
    /// RFC 3339 UTC start.
    #[serde(rename = "start-datetime")]
    pub start_datetime: String,
    /// RFC 3339 UTC end.
    #[serde(rename = "end-datetime")]
    pub end_datetime: String,
}

impl DateRange {
    /// A range from two Unix instants, formatted as §4.4 requires.
    #[must_use]
    pub fn from_unix(start_unix: u64, end_unix: u64) -> Self {
        Self {
            start_datetime: rfc3339_utc(start_unix),
            end_datetime: rfc3339_utc(end_unix),
        }
    }
}

/// The policy a session was attempted under (§4.4 `policy`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PolicyDescriptor {
    /// Which mechanism applied.
    #[serde(rename = "policy-type")]
    pub policy_type: PolicyType,

    /// The policy itself, as §4.5 defines for each type.
    ///
    /// For MTA-STS, the policy's own lines — `version: STSv1`, each `mx:`
    /// separately, `max_age:` — "including any errors that may be present",
    /// which is the point: a domain whose policy is malformed learns that
    /// from the report.
    ///
    /// For DANE, each TLSA record's RDATA as its four fields space-separated
    /// in presentation format.
    ///
    /// Omitted when the policy type is `no-policy-found`.
    #[serde(rename = "policy-string", skip_serializing_if = "Option::is_none")]
    pub policy_string: Option<Vec<String>>,

    /// The policy domain, Punycode A-labels rather than Unicode U-labels.
    #[serde(rename = "policy-domain")]
    pub policy_domain: String,

    /// For an MTA-STS policy, its `mx` patterns.
    #[serde(rename = "mx-host", skip_serializing_if = "Option::is_none")]
    pub mx_host: Option<Vec<String>>,
}

/// Session counts for one policy (§4.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Summary {
    /// Successfully negotiated TLS sessions (§4.2.1).
    #[serde(rename = "total-successful-session-count")]
    pub total_successful_session_count: u64,
    /// Sessions that failed to negotiate TLS (§4.2.2).
    #[serde(rename = "total-failure-session-count")]
    pub total_failure_session_count: u64,
}

/// One failure class within a policy (§4.4 `failure-details`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FailureDetail {
    /// What went wrong.
    #[serde(rename = "result-type")]
    pub result_type: ResultType,

    /// The sending MTA's IP address.
    #[serde(rename = "sending-mta-ip", skip_serializing_if = "Option::is_none")]
    pub sending_mta_ip: Option<String>,

    /// The receiving MX hostname the session was to.
    #[serde(
        rename = "receiving-mx-hostname",
        skip_serializing_if = "Option::is_none"
    )]
    pub receiving_mx_hostname: Option<String>,

    /// The HELO/EHLO banner string, if one was seen.
    #[serde(rename = "receiving-mx-helo", skip_serializing_if = "Option::is_none")]
    pub receiving_mx_helo: Option<String>,

    /// The destination IP actually connected to.
    #[serde(rename = "receiving-ip", skip_serializing_if = "Option::is_none")]
    pub receiving_ip: Option<String>,

    /// How many sessions failed this way.
    #[serde(rename = "failed-session-count")]
    pub failed_session_count: u64,

    /// A URI with more detail, if the sender publishes one.
    #[serde(
        rename = "additional-information",
        skip_serializing_if = "Option::is_none"
    )]
    pub additional_information: Option<String>,

    /// A short error code or text (§4.3.3).
    ///
    /// "This is intended to be a short text field, and the contents of the
    /// field should be an error code or error text, such as
    /// `X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION`."
    ///
    /// # What not to put here
    ///
    /// The only free-text field in the schema, and it travels to an address
    /// taken from **unsigned** DNS (§3), so an attacker able to forge that
    /// answer receives it. Keep it to a classification — an error constant,
    /// a short reason — and out of it: message identifiers, recipient or
    /// sender addresses, internal hostnames or paths, certificate contents,
    /// and anything naming a particular message. §7 is the general warning;
    /// this field is where a sender would most easily disregard it.
    #[serde(
        rename = "failure-reason-code",
        skip_serializing_if = "Option::is_none"
    )]
    pub failure_reason_code: Option<String>,
}

impl FailureDetail {
    /// A detail with only the required fields.
    #[must_use]
    pub fn new(result_type: ResultType, failed_session_count: u64) -> Self {
        Self {
            result_type,
            sending_mta_ip: None,
            receiving_mx_hostname: None,
            receiving_mx_helo: None,
            receiving_ip: None,
            failed_session_count,
            additional_information: None,
            failure_reason_code: None,
        }
    }

    /// Name the receiving MX host.
    #[must_use]
    pub fn with_receiving_mx_hostname(mut self, host: impl Into<String>) -> Self {
        self.receiving_mx_hostname = Some(host.into());
        self
    }

    /// Set the short reason code (§4.3.3).
    ///
    /// Read [`failure_reason_code`](Self::failure_reason_code) on what not to
    /// put here before using this.
    #[must_use]
    pub fn with_failure_reason_code(mut self, code: impl Into<String>) -> Self {
        self.failure_reason_code = Some(code.into());
        self
    }

    /// Set the sending MTA's IP.
    #[must_use]
    pub fn with_sending_mta_ip(mut self, ip: impl Into<String>) -> Self {
        self.sending_mta_ip = Some(ip.into());
        self
    }

    /// Set the receiving IP.
    #[must_use]
    pub fn with_receiving_ip(mut self, ip: impl Into<String>) -> Self {
        self.receiving_ip = Some(ip.into());
        self
    }
}

/// One policy's results within a report (§4.4 `policies` element).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PolicyBlock {
    /// The policy applied.
    pub policy: PolicyDescriptor,
    /// Its session counts.
    pub summary: Summary,
    /// How the failures broke down.
    ///
    /// Empty when nothing failed, and §4.2.1 still has the successes
    /// counted — a report of all-successful sessions is useful, because it
    /// tells a domain in `testing` mode that enforcing is safe.
    #[serde(rename = "failure-details", default)]
    pub failure_details: Vec<FailureDetail>,
}

/// An aggregate TLS report (§4.4).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Report {
    /// The organisation responsible for the report.
    #[serde(rename = "organization-name")]
    pub organization_name: String,

    /// The reporting period.
    #[serde(rename = "date-range")]
    pub date_range: DateRange,

    /// Contact for the party responsible, an RFC 5322 addr-spec.
    #[serde(rename = "contact-info")]
    pub contact_info: String,

    /// A unique identifier for this report.
    ///
    /// §4.4: "Report authors may use whatever scheme they prefer". No
    /// generator here, because a sender's own identifiers are better than
    /// anything this crate could invent without a clock or randomness — and
    /// `#[no_std]` leaves it with neither.
    #[serde(rename = "report-id")]
    pub report_id: String,

    /// One block per policy the period covered.
    pub policies: Vec<PolicyBlock>,
}

impl Report {
    /// Serialise to JSON.
    ///
    /// # Errors
    ///
    /// Whatever `serde_json` reports, which for these types means only an
    /// allocation failure.
    #[cfg(feature = "json")]
    #[cfg_attr(docsrs, doc(cfg(feature = "json")))]
    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Serialise to pretty-printed JSON, for a human reading a report.
    ///
    /// # Errors
    ///
    /// As [`to_json_string`](Self::to_json_string).
    #[cfg(feature = "json")]
    #[cfg_attr(docsrs, doc(cfg(feature = "json")))]
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Parse a report from JSON.
    ///
    /// # Errors
    ///
    /// Whatever `serde_json` reports for malformed or non-conforming input.
    #[cfg(feature = "json")]
    #[cfg_attr(docsrs, doc(cfg(feature = "json")))]
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Total successful sessions across every policy.
    #[must_use]
    pub fn total_successful_sessions(&self) -> u64 {
        self.policies
            .iter()
            .map(|p| p.summary.total_successful_session_count)
            .sum()
    }

    /// Total failed sessions across every policy.
    #[must_use]
    pub fn total_failed_sessions(&self) -> u64 {
        self.policies
            .iter()
            .map(|p| p.summary.total_failure_session_count)
            .sum()
    }

    /// Whether the report records any failure.
    ///
    /// §4.3.4: "Transient errors due to too-busy networks, TCP timeouts,
    /// etc., are not required to be reported." So a report with no failures
    /// is the normal case and still worth sending — it tells a domain in
    /// `testing` mode that enforcing is safe, which is the whole purpose of
    /// that mode.
    #[must_use]
    pub fn has_failures(&self) -> bool {
        self.total_failed_sessions() > 0
            || self.policies.iter().any(|p| !p.failure_details.is_empty())
    }
}

/// A report filename, per §5.1's recommended ABNF.
///
/// `sender!policy-domain!begin-timestamp!end-timestamp[!unique-id].extension`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportFilename {
    /// The sending domain, used as the `contact-info` address's domain.
    pub sender: String,
    /// The domain the report is about.
    pub policy_domain: String,
    /// Start of the range, Unix seconds.
    pub begin_unix: u64,
    /// End of the range, Unix seconds.
    pub end_unix: u64,
    /// An optional discriminator (§5.1 `unique-id`), alphanumeric.
    ///
    /// "allows an optional unique ID generated by the Sending MTA to
    /// distinguish among multiple reports generated simultaneously by
    /// different sources for the same Policy Domain."
    pub unique_id: Option<String>,
    /// Whether the body is gzipped.
    ///
    /// §5.1: the extension "MUST be `json` for a plain JSON file or
    /// `json.gz` for a JSON file compressed using gzip". §5.2 says a report
    /// SHOULD be compressed, since "a commonly observed receiver limit is ten
    /// megabytes".
    pub compressed: bool,
}

impl ReportFilename {
    /// A filename for an uncompressed report.
    #[must_use]
    pub fn new(
        sender: impl Into<String>,
        policy_domain: impl Into<String>,
        begin_unix: u64,
        end_unix: u64,
    ) -> Self {
        Self {
            sender: sender.into(),
            policy_domain: policy_domain.into(),
            begin_unix,
            end_unix,
            unique_id: None,
            compressed: false,
        }
    }

    /// Mark the body as gzipped, changing the extension to `json.gz`.
    #[must_use]
    pub const fn compressed(mut self) -> Self {
        self.compressed = true;
        self
    }

    /// Add a `unique-id`.
    ///
    /// Non-alphanumeric characters are dropped, because §5.1's ABNF is
    /// `1*(ALPHA / DIGIT)` and `!` or `.` in this field would make the
    /// filename ambiguous to a receiver splitting on those delimiters.
    #[must_use]
    pub fn with_unique_id(mut self, id: &str) -> Self {
        let filtered: String = id.chars().filter(char::is_ascii_alphanumeric).collect();
        self.unique_id = (!filtered.is_empty()).then_some(filtered);
        self
    }

    /// The extension, `json` or `json.gz` (§5.1).
    #[must_use]
    pub const fn extension(&self) -> &'static str {
        if self.compressed {
            "json.gz"
        } else {
            "json"
        }
    }
}

impl core::fmt::Display for ReportFilename {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}!{}!{}!{}",
            self.sender, self.policy_domain, self.begin_unix, self.end_unix
        )?;
        if let Some(id) = &self.unique_id {
            write!(f, "!{id}")?;
        }
        write!(f, ".{}", self.extension())
    }
}

/// Build the MTA-STS `policy-string` §4.5 wants from a policy's own fields.
///
/// "an array of JSON strings that represents the policy that is declared by
/// the receiving site, including any errors that may be present. Note that
/// where there are multiple `mx` values, they must be listed as separate `mx`
/// elements in the policy array rather than as a single nested `mx`
/// sub-array."
///
/// That note is the trap: the obvious encoding groups the `mx` patterns into
/// one array element, and §4.5 forbids it.
#[must_use]
pub fn sts_policy_string(mode: &str, mx_patterns: &[String], max_age: u64) -> Vec<String> {
    let mut lines = Vec::with_capacity(mx_patterns.len() + 3);
    lines.push(String::from("version: STSv1"));
    lines.push(format!("mode: {mode}"));
    for mx in mx_patterns {
        lines.push(format!("mx: {mx}"));
    }
    lines.push(format!("max_age: {max_age}"));
    lines
}
