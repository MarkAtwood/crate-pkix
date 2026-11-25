//! The `_smtp._tls` TXT record — RFC 8460 §3.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::join_txt_strings;

/// Why a `_smtp._tls` TXT record is not usable.
///
/// §3 treats the counting cases alike: "If the number of resulting records is
/// not one, senders MUST assume the recipient domain does not implement
/// TLSRPT." The distinctions are for diagnosis.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TlsRptError {
    /// No record began with `v=TLSRPTv1`.
    NoTlsRptRecord,

    /// More than one record began with the version tag.
    ///
    /// Not resolved by picking one: a domain with two reporting policies has
    /// not said where reports should go, and guessing could send a domain's
    /// failure reports to whichever endpoint happened to sort first.
    MultipleTlsRptRecords(usize),

    /// No `rua` field, which §3's ABNF requires.
    ///
    /// A record without one declares TLSRPT support and names nowhere to
    /// report, so there is nothing a sender can do with it.
    MissingRua,

    /// A `rua` value is not a `mailto:` or `https:` URI.
    ///
    /// §3 supports exactly those two schemes. Carries the offending value so
    /// an operator can see what was published.
    UnsupportedUriScheme(String),

    /// The `rua` field was present but contained no usable URI.
    EmptyRua,

    /// A field is neither the version tag nor `key=value`.
    MalformedField(String),
}

impl core::fmt::Display for TlsRptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoTlsRptRecord => f.write_str("no TXT record begins with v=TLSRPTv1"),
            Self::MultipleTlsRptRecords(n) => write!(
                f,
                "{n} TXT records begin with v=TLSRPTv1, which is ambiguous; \
                 §3 requires exactly one"
            ),
            Self::MissingRua => {
                f.write_str("TLSRPT record has no rua field, so names nowhere to report")
            }
            Self::UnsupportedUriScheme(uri) => write!(
                f,
                "rua URI {uri:?} is neither mailto: nor https:, the only two \
                 schemes §3 supports"
            ),
            Self::EmptyRua => f.write_str("rua field contains no URI"),
            Self::MalformedField(field) => {
                write!(f, "TLSRPT field is not key=value: {field:?}")
            }
        }
    }
}

impl core::error::Error for TlsRptError {}

/// Where a domain wants its reports sent (§3).
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum ReportingEndpoint {
    /// `mailto:` — deliver the report as mail.
    ///
    /// §3 imposes two requirements a sender must not miss. The report "MUST
    /// contain a valid DomainKeys Identified Mail (DKIM) signature by the
    /// reporting domain", without the `l=` body-length attribute, "this
    /// ensures attackers cannot append extraneous or misleading data to a
    /// report without breaking the signature" — an unsigned report MUST be
    /// ignored by the recipient, so sending one is wasted work. And a sender
    /// "MUST deliver reports despite any TLS-related failures", which means
    /// a report about a domain's broken TLS may have to travel unencrypted to
    /// that same domain.
    ///
    /// The address, without the `mailto:` scheme.
    Mailto(String),

    /// `https:` — POST the report.
    ///
    /// §3: "Report submitters MAY ignore certificate validation errors when
    /// submitting reports via HTTPS POST." Unusual in this workspace and
    /// deliberate in the RFC: a report is diagnostic data about a failure, so
    /// refusing to deliver it because of a certificate problem would suppress
    /// exactly the reports most worth sending.
    ///
    /// The full URI, scheme included.
    Https(String),
}

impl ReportingEndpoint {
    /// The URI as published, scheme included.
    #[must_use]
    pub fn as_uri(&self) -> String {
        match self {
            Self::Mailto(addr) => alloc::format!("mailto:{addr}"),
            Self::Https(uri) => uri.clone(),
        }
    }

    /// Parse one `rua` URI.
    fn parse(raw: &str) -> Result<Self, TlsRptError> {
        let uri = raw.trim();
        if let Some(addr) = strip_prefix_ascii_case(uri, "mailto:") {
            if addr.is_empty() {
                return Err(TlsRptError::UnsupportedUriScheme(uri.to_string()));
            }
            return Ok(Self::Mailto(addr.to_string()));
        }
        if strip_prefix_ascii_case(uri, "https://").is_some() {
            return Ok(Self::Https(uri.to_string()));
        }
        Err(TlsRptError::UnsupportedUriScheme(uri.to_string()))
    }
}

/// Case-insensitive prefix strip. URI schemes are case-insensitive per
/// RFC 3986 §3.1, so `MAILTO:` is the same scheme as `mailto:`.
fn strip_prefix_ascii_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    s.get(..prefix.len())
        .filter(|head| head.eq_ignore_ascii_case(prefix))
        .map(|_| &s[prefix.len()..])
}

/// Whether `record` begins with the version tag, per §3's discard rule.
///
/// Matched case-insensitively although §3's ABNF writes `%s"v=TLSRPTv1"`,
/// which RFC 7405 makes case-sensitive. The same reasoning as the MTA-STS
/// parser, and the realistic failure decides it: discarding a single
/// miscased record leaves zero records, which §3 has a sender read as the
/// domain not implementing TLSRPT, so its reports silently stop. Accepting it
/// sends the reports the domain asked for.
fn begins_with_version_tag(record: &str) -> bool {
    let rest = record.trim_start();
    let Some(rest) = strip_prefix_ascii_case(rest, "v=TLSRPTv") else {
        return false;
    };
    let mut chars = rest.chars();
    if chars.next() != Some('1') {
        return false;
    }
    matches!(chars.as_str().trim_start().chars().next(), None | Some(';'))
}

/// A parsed `_smtp._tls` TXT record (§3).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TlsRptRecord {
    endpoints: Vec<ReportingEndpoint>,
}

impl TlsRptRecord {
    /// Parse one TXT record's text.
    ///
    /// # Format
    ///
    /// Semicolon-separated `key=value` pairs beginning with the version tag:
    /// `v=TLSRPTv1; rua=mailto:reports@example.com`. A `rua` may carry a
    /// comma-separated list, as DMARC does, and every usable endpoint is
    /// kept.
    ///
    /// Unknown fields are ignored, which §3 requires rather than merely
    /// permits: "Parsers MUST accept TXT records that are syntactically valid
    /// ... and implement a superset of this specification, in which case
    /// unknown fields SHALL be ignored."
    ///
    /// # Errors
    ///
    /// See [`TlsRptError`]. A record naming only unsupported schemes yields
    /// [`TlsRptError::UnsupportedUriScheme`] rather than being treated as
    /// absent, so an operator who published a `ftp:` endpoint can tell why no
    /// reports arrive.
    pub fn parse(text: &str) -> Result<Self, TlsRptError> {
        if !begins_with_version_tag(text) {
            return Err(TlsRptError::NoTlsRptRecord);
        }

        let mut rua: Option<&str> = None;
        for raw in text.split(';') {
            let field = raw.trim();
            if field.is_empty() {
                continue;
            }
            let Some((key, value)) = field.split_once('=') else {
                return Err(TlsRptError::MalformedField(field.to_string()));
            };
            let key = key.trim();
            if key.eq_ignore_ascii_case("v") {
                continue; // already checked
            }
            if key.eq_ignore_ascii_case("rua") {
                rua = Some(value.trim());
            }
            // Anything else is an extension field. Ignored, per §3.
        }

        let rua = rua.ok_or(TlsRptError::MissingRua)?;
        if rua.is_empty() {
            return Err(TlsRptError::EmptyRua);
        }

        let mut endpoints = Vec::new();
        let mut first_error: Option<TlsRptError> = None;
        for part in rua.split(',') {
            if part.trim().is_empty() {
                continue;
            }
            match ReportingEndpoint::parse(part) {
                Ok(e) => endpoints.push(e),
                Err(e) => {
                    first_error.get_or_insert(e);
                }
            }
        }

        if endpoints.is_empty() {
            return Err(first_error.unwrap_or(TlsRptError::EmptyRua));
        }
        Ok(Self { endpoints })
    }

    /// Parse one TXT record given as its separate character-strings (§3).
    ///
    /// See [`join_txt_strings`] for why they are joined with nothing.
    ///
    /// # Errors
    ///
    /// [`TlsRptError::NoTlsRptRecord`] if the joined bytes are not UTF-8,
    /// since §3's ABNF admits only ASCII and §3 treats an unusable record as
    /// the domain not implementing TLSRPT. Otherwise as [`parse`](Self::parse).
    pub fn from_txt_strings(strings: &[&[u8]]) -> Result<Self, TlsRptError> {
        let text = join_txt_strings(strings).ok_or(TlsRptError::NoTlsRptRecord)?;
        Self::parse(&text)
    }

    /// Whether these character-strings, joined, look like a TLSRPT record.
    ///
    /// §3's discard test, for a caller filtering a resolver's answer.
    #[must_use]
    pub fn is_tlsrpt_txt_strings(strings: &[&[u8]]) -> bool {
        join_txt_strings(strings).is_some_and(|t| begins_with_version_tag(&t))
    }

    /// Select the single TLSRPT record from a resolver's answer (§3).
    ///
    /// "If multiple TXT records for `_smtp._tls` are returned by the
    /// resolver, records that do not begin with `v=TLSRPTv1;` are discarded.
    /// If the number of resulting records is not one, senders MUST assume the
    /// recipient domain does not implement TLSRPT."
    ///
    /// # Errors
    ///
    /// [`TlsRptError::NoTlsRptRecord`] or
    /// [`TlsRptError::MultipleTlsRptRecords`] when the surviving count is not
    /// one, else whatever [`parse`](Self::parse) reports.
    pub fn select<'a, I>(records: I) -> Result<Self, TlsRptError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let candidates: Vec<&str> = records
            .into_iter()
            .filter(|r| begins_with_version_tag(r))
            .collect();
        match candidates.as_slice() {
            [] => Err(TlsRptError::NoTlsRptRecord),
            [one] => Self::parse(one),
            many => Err(TlsRptError::MultipleTlsRptRecords(many.len())),
        }
    }

    /// Every usable endpoint, in the order published.
    ///
    /// §3: "The record supports the ability to declare more than one rua, and
    /// if there exists more than one, the reporter MAY attempt to deliver to
    /// each of the supported rua destinations. A receiver MAY opt to only
    /// attempt delivery to one of the endpoints; however, the report SHOULD
    /// NOT be considered successfully delivered until one of the endpoints
    /// accepts delivery."
    ///
    /// So a sender may stop at the first that accepts, but must not treat a
    /// report as delivered until one does.
    #[must_use]
    pub fn endpoints(&self) -> &[ReportingEndpoint] {
        &self.endpoints
    }
}
