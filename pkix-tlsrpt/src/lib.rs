//! TLSRPT — SMTP TLS Reporting, RFC 8460.
//!
//! A recipient domain publishes a reporting endpoint; senders send it daily
//! summaries of TLS negotiation and policy-validation failures. This crate
//! holds the `_smtp._tls` record (§3), the report schema (§4.4), the result
//! types (§4.3) and the report filename (§5.1).
//!
//! No DNS, no HTTP, no SMTP, no clock — the same shape as `pkix-mta-sts`.
//!
//! # Why a sender should bother
//!
//! MTA-STS's `testing` mode exists so a domain can deploy a policy and find
//! out what would break **before** enforcing it. Without senders that report,
//! `testing` tells the domain nothing: it is a policy that never applies.
//!
//! So a sender implementing MTA-STS or DANE without TLSRPT is a free rider on
//! the domains that do report — it takes the protection and contributes
//! nothing to anyone else's rollout. That is the argument for implementing
//! this, and it is not a security argument: a report protects the *recipient's
//! deployment*, not the sender's mail.
//!
//! # What a report says about someone else
//!
//! A report states which of a domain's MX hosts failed TLS, how, and from
//! which sending IP. That is operational detail about a third party, sent to
//! an address that third party nominated in **unsigned** DNS (§3 — the
//! `_smtp._tls` record carries no authentication, exactly like `_mta-sts`).
//!
//! §7 covers the consequences. Two follow directly:
//!
//! - A `rua` address is not trustworthy merely because it came from the
//!   domain it describes. An attacker who can forge the TXT answer redirects
//!   a domain's failure reports to themselves.
//! - A report is a map of which of a domain's hosts have broken TLS, which is
//!   reconnaissance if it reaches the wrong party.
//!
//! This crate therefore carries only what §4.4 defines and nothing more
//! helpful. In particular [`FailureDetail::failure_reason_code`] is the only
//! free-text field, it is optional, and its documentation says what not to
//! put in it.
//!
//! # Scope
//!
//! Report **delivery** is not here, and that is deliberate rather than
//! unfinished — see the crate README. In short: `mailto` delivery MUST carry
//! a DKIM signature by the reporting domain (§3), which means a mail library
//! and a signing key inside a PKI library, and §5.3 requires a sender to
//! ignore its own MTA-STS and DANE failures when delivering a report, which
//! is MTA policy rather than PKI. `https` delivery is a POST a caller with an
//! HTTP client writes in a line.
//!
//! Compression (§5.2, a SHOULD) is likewise the caller's: it needs a gzip
//! dependency this crate does not otherwise want, and
//! [`ReportFilename::extension`] already distinguishes the two cases.

// Documentation links to `pkix_mta_sts_http::FetchError`, which sits
// behind `mta-sts-http`. Without it the item does not exist, so the
// link cannot resolve and `cargo doc` on a consumer's own feature
// selection reports an error.
//
// Allowing the lint only where it cannot tell a gated item from a
// mistake loses no signal: a mistyped link is broken with every feature
// enabled too, and the all-features doc build is what the quality gate
// runs under RUSTDOCFLAGS=-D warnings. Demoting the links to code spans
// instead would cost every docs.rs reader a working link, to spare a
// configuration nobody publishes documentation from.
#![cfg_attr(not(feature = "mta-sts-http"), allow(rustdoc::broken_intra_doc_links))]
#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub mod classify;
mod record;
mod report;
mod result_type;

pub use record::{ReportingEndpoint, TlsRptError, TlsRptRecord};
pub use report::{
    sts_policy_string, DateRange, FailureDetail, PolicyBlock, PolicyDescriptor, PolicyType, Report,
    ReportFilename, Summary,
};
pub use result_type::ResultType;

/// The DNS label pair prefixed to a policy domain to find the record (§3).
///
/// For `example.com`, query `_smtp._tls.example.com`.
pub const TXT_PREFIX: &str = "_smtp._tls";

/// The DNS name to query for a domain's reporting policy (§3).
///
/// A trailing dot on an absolute name is not carried through, so the result
/// is always relative-form.
#[must_use]
pub fn txt_name(policy_domain: &str) -> String {
    format!("{TXT_PREFIX}.{}", policy_domain.trim_end_matches('.'))
}

/// The MIME type for a gzipped report attached to a mail message (§5.3).
pub const GZIP_MEDIA_TYPE: &str = "application/tlsrpt+gzip";

/// The MIME type for an uncompressed JSON report (§5.4).
pub const JSON_MEDIA_TYPE: &str = "application/tlsrpt+json";

/// Format `unix_secs` as the RFC 3339 UTC timestamp §4.4 requires.
///
/// "formatted according to Internet Date/Time Format, Section 5.6 of
/// RFC 3339. The report should be for a full UTC day, 00:00-24:00."
///
/// Written here rather than taken from a date library because this crate
/// needs exactly one format and owes nothing to leap seconds or time zones:
/// §4.4 wants UTC, and a dependency for `strftime` would be the largest thing
/// in the crate.
#[must_use]
pub fn rfc3339_utc(unix_secs: u64) -> String {
    let (y, mo, d, h, mi, s) = civil_from_unix(unix_secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Unix seconds to civil UTC date and time.
///
/// Howard Hinnant's `civil_from_days` algorithm, shifting the era to start in
/// March so the leap day lands at the end of a year and the month-length
/// pattern becomes a simple formula. Correct for the proleptic Gregorian
/// calendar, which covers every timestamp a report can carry.
fn civil_from_unix(unix_secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (unix_secs / 86_400) as i64;
    let secs_of_day = (unix_secs % 86_400) as u32;

    // Shift to an era beginning 0000-03-01.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11], March = 0
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };

    (
        y,
        m,
        d,
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    )
}

/// Join a TXT record's character-strings without inserting anything (§3).
///
/// "If the resulting TXT record contains multiple strings... then the record
/// MUST be treated as if those strings are concatenated without adding
/// spaces."
///
/// A DNS TXT record is length-prefixed character-strings of at most 255 bytes
/// each, so a record with several `rua` URIs arrives split. Joining with a
/// space — the intuitive thing — would corrupt whichever URI straddles the
/// boundary, and the reports would go nowhere.
///
/// The same rule as RFC 8461 §3.1, implemented separately rather than shared
/// with `pkix-mta-sts`: TLSRPT reports on DANE as well as MTA-STS, so
/// depending on the MTA-STS crate to read a TXT record would make every DANE
/// reporter pull in MTA-STS. Four lines of byte copying is the cheaper of the
/// two costs, and a divergence here is a correctness bug rather than a
/// security one — a report misrouted, not a connection downgraded.
#[must_use]
pub fn join_txt_strings(strings: &[&[u8]]) -> Option<String> {
    let mut joined = Vec::with_capacity(strings.iter().map(|s| s.len()).sum());
    for s in strings {
        joined.extend_from_slice(s);
    }
    core::str::from_utf8(&joined).ok().map(ToString::to_string)
}
