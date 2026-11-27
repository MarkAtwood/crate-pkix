//! MTA-STS policy fetching over HTTPS — RFC 8461 §3.3.
//!
//! `pkix-mta-sts` parses a policy and decides when one is needed. This crate
//! performs the fetch, enforcing the §3.3 requirements that make the fetched
//! policy worth trusting.
//!
//! ```no_run
//! use pkix_mta_sts_http::PolicyFetcher;
//!
//! let fetcher = PolicyFetcher::new();
//! // Fetches https://mta-sts.example.com/.well-known/mta-sts.txt
//! let policy = fetcher.fetch("example.com")?;
//! println!("mode: {:?}, max_age: {}", policy.mode(), policy.max_age());
//! # Ok::<(), pkix_mta_sts_http::FetchError>(())
//! ```
//!
//! # What §3.3 requires, and why each one matters
//!
//! The policy's only authentication is this HTTPS connection. The `_mta-sts`
//! TXT record is unsigned, so every requirement below is load-bearing rather
//! than hygiene.
//!
//! - **The certificate MUST be valid for `mta-sts.<policy-domain>`**, chain
//!   to a trusted root, and be unexpired. Matching is against DNS-IDs only,
//!   with a wildcard permitted as the complete left-most label. This is the
//!   whole trust basis; without it anyone on the path writes the policy.
//! - **Only HTTP 200 is a policy.** A 404 is not an empty policy, and a 500
//!   is not "no MTA-STS".
//! - **3xx redirects MUST NOT be followed.** A followed redirect lets
//!   whoever controls the policy host move the fetch elsewhere, including
//!   somewhere whose certificate says nothing about the policy domain.
//! - **HTTP caching MUST NOT be used.** The policy has its own freshness
//!   model in `max_age`; an HTTP cache layered under it would extend a stale
//!   policy by an interval the sender never agreed to.
//! - **The media type SHOULD be `text/plain`** (§3.2), "to guard against
//!   cases where web servers allow untrusted users to host non-text content
//!   at a user-defined path". A shared host that lets a user upload to a
//!   path is otherwise a way to publish a policy for someone else's domain.
//!
//! This crate enforces all of them. The media-type check is on by default
//! although §3.2 words it as SHOULD, because the failure it prevents is
//! someone else's policy being accepted for your domain; see
//! [`FetcherConfig::require_text_plain`] to relax it.
//!
//! # Limits
//!
//! §3.3 permits a timeout and a size cap and suggests one minute and 64
//! kilobytes. Both are applied by default, because a policy host that never
//! finishes responding would otherwise hold a delivery attempt open.
//!
//! # Destination policy
//!
//! The host is `mta-sts.` prepended to a **recipient domain**, so a sender
//! fetches from a host chosen by whoever it is sending mail to. That is an
//! outbound request an attacker has some say over, which is the shape of a
//! server-side request forgery.
//!
//! Non-public addresses are refused at resolution time by
//! [`pkix_net_guard`], shared with `pkix-aia-http`. Filtering inside the
//! resolver leaves no window for DNS rebinding, which a pre-flight check on
//! the host name would.
//!
//! # What this crate does not do
//!
//! **The TXT lookup.** `_mta-sts.<domain>` is a DNS query, and §3.1 requires
//! following CNAMEs. A sender already has a resolver; this crate does not
//! bring a second one. [`pkix_mta_sts::txt_name`] builds the name and
//! [`pkix_mta_sts::StsTxtRecord::select`] applies §3.1's record selection to
//! whatever the resolver returns.
//!
//! **The cache.** [`pkix_mta_sts::plan`] and
//! [`pkix_mta_sts::policy_to_apply`] hold the §3.3 and §5.1 rules, and the
//! storage is the caller's — there is no filesystem or OS dependency here.
//!
//! **Certificate validation is the HTTP client's.** Both backends validate
//! against the platform or bundled Web PKI roots as configured. A sender that
//! needs a specific trust store, or revocation checking as §3.3's MAY
//! permits, configures the client itself and passes it in.

#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
// `fetch_and_record` and `PolicyFetcher::fetch` are gated on
// `client-ureq`, and the `client-reqwest` functions' documentation links
// to them as the synchronous counterpart — so `--features client-reqwest`
// alone cannot resolve them. Same shape as `pkix-path`'s attribute.
#![cfg_attr(not(feature = "client-ureq"), allow(rustdoc::broken_intra_doc_links))]

use pkix_mta_sts::discovery::{
    SUGGESTED_FETCH_TIMEOUT_SECS, SUGGESTED_MAX_POLICY_BYTES, WELL_KNOWN_PATH,
};
use pkix_mta_sts::{policy_url, PolicyError};

#[cfg(feature = "client-reqwest")]
mod r#async;
#[cfg(feature = "client-reqwest")]
#[cfg_attr(docsrs, doc(cfg(feature = "client-reqwest")))]
pub use r#async::AsyncPolicyFetcher;

#[cfg(feature = "client-ureq")]
mod sync;
#[cfg(feature = "client-ureq")]
#[cfg_attr(docsrs, doc(cfg(feature = "client-ureq")))]
pub use sync::PolicyFetcher;

/// Why a policy could not be fetched.
///
/// §3.3 treats every one of these the same way for delivery: "If a valid TXT
/// record is found but no policy can be fetched via HTTPS (for any reason),
/// and there is no valid (non-expired) previously cached policy, senders MUST
/// continue with delivery as though the domain has not implemented MTA-STS."
///
/// So these variants are for diagnostics and for the §3.3 backoff, not for
/// deciding whether to deliver. Pass the failure to
/// [`pkix_mta_sts::policy_to_apply`] as `None` and it applies that rule.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FetchError {
    /// The response status was not 200 (§3.3).
    ///
    /// Carries the status so a caller can distinguish a domain that has no
    /// policy host (404) from one whose policy host is broken (5xx) — which
    /// matters for §3.3's "SHOULD alert administrators" and for how long to
    /// back off.
    HttpStatus(u16),

    /// The response was a 3xx redirect, which §3.3 forbids following.
    ///
    /// Reported distinctly rather than as [`HttpStatus`](Self::HttpStatus)
    /// because it is a misconfiguration a domain operator can fix, and
    /// because a sender seeing it should not conclude the domain has no
    /// policy.
    RedirectRefused(u16),

    /// The `Content-Type` was not `text/plain` (§3.2).
    UnexpectedMediaType(String),

    /// The body exceeded the configured size cap.
    BodyTooLarge(usize),

    /// The body was not a valid policy.
    Malformed(PolicyError),

    /// The host resolved only to non-public addresses.
    ///
    /// Distinct from [`Transport`](Self::Transport) because it is a refusal
    /// by this crate rather than a network failure, and because it usually
    /// means either a misconfigured domain or an attempt to make the sender
    /// reach its own internal network.
    DestinationRefused(String),

    /// The request timed out.
    Timeout,

    /// The policy host's certificate did not validate (§3.3).
    ///
    /// §3.3 requires the certificate to be "valid for the `mta-sts` DNS-ID",
    /// chain "to a root CA that is trusted by the Sending MTA", and be
    /// non-expired. This is that check failing — expired, untrusted issuer,
    /// wrong host, bad chain.
    ///
    /// Reported separately from [`Transport`](Self::Transport) because this
    /// is the one failure with security meaning rather than operational.
    /// The HTTPS certificate is an MTA-STS policy's **only** authentication:
    /// the `_mta-sts` TXT record is unsigned and the policy body carries no
    /// signature. So this means "the policy may have been written by
    /// whoever is on the path", where `Transport` means "the web server is
    /// down". RFC 8460 §4.3.2.2 reports them as `sts-webpki-invalid` and
    /// `sts-policy-fetch-error` respectively, and an operator who cannot
    /// tell them apart cannot alert on the first without the second.
    ///
    /// Carries the underlying description.
    TlsValidation(String),

    /// Any other transport failure — connection refused or reset, DNS
    /// failure, a protocol error.
    ///
    /// A string because the two backends report incompatible error types and
    /// §3.3 draws no distinction among them. Does **not** include a
    /// certificate that failed to validate; see
    /// [`TlsValidation`](Self::TlsValidation).
    Transport(String),
}

impl core::fmt::Display for FetchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::HttpStatus(code) => {
                write!(f, "policy host returned HTTP {code}; only 200 is a policy")
            }
            Self::RedirectRefused(code) => write!(
                f,
                "policy host returned HTTP {code}; RFC 8461 §3.3 forbids \
                 following redirects"
            ),
            Self::UnexpectedMediaType(ct) => {
                write!(f, "policy served as {ct:?}, expected text/plain")
            }
            Self::BodyTooLarge(cap) => {
                write!(f, "policy body exceeds the {cap} byte limit")
            }
            Self::Malformed(e) => write!(f, "policy body is not a valid policy: {e}"),
            Self::DestinationRefused(host) => write!(f, "refused to fetch from {host}"),
            Self::TlsValidation(e) => write!(f, "policy host certificate did not validate: {e}"),
            Self::Timeout => f.write_str("policy fetch timed out"),
            Self::Transport(e) => write!(f, "policy fetch failed: {e}"),
        }
    }
}

impl core::error::Error for FetchError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Malformed(e) => Some(e),
            _ => None,
        }
    }
}

/// How a fetcher behaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FetcherConfig {
    /// Maximum policy body size in bytes. Default
    /// [`SUGGESTED_MAX_POLICY_BYTES`].
    pub max_body_bytes: usize,

    /// Request timeout in seconds. Default [`SUGGESTED_FETCH_TIMEOUT_SECS`].
    pub timeout_secs: u64,

    /// Whether to require `text/plain` (§3.2). Default `true`.
    ///
    /// §3.2 words this as SHOULD, and it is on by default anyway because the
    /// failure it prevents is specific and bad: a web server that lets
    /// untrusted users host content at a user-defined path becomes a way to
    /// publish an MTA-STS policy for a domain you do not control.
    ///
    /// Set `false` only for a policy host known to serve a correct body under
    /// a wrong content type. The parser still rejects non-policy bodies, so
    /// this is a second line rather than the only one.
    pub require_text_plain: bool,

    /// Whether to refuse non-public addresses. Default `true`.
    ///
    /// Set `false` only to fetch from a policy host on a private network,
    /// such as in a test. Leaving it on in production is what prevents a
    /// recipient domain steering the sender at its own internal network.
    pub refuse_non_public_addresses: bool,
}

impl Default for FetcherConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: SUGGESTED_MAX_POLICY_BYTES,
            timeout_secs: SUGGESTED_FETCH_TIMEOUT_SECS,
            require_text_plain: true,
            refuse_non_public_addresses: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Shared response checks
// ---------------------------------------------------------------------------

/// Apply §3.3's status rules to an HTTP status code.
///
/// Shared by both backends so they cannot diverge on which statuses are
/// acceptable — a difference that would make one quietly less safe than the
/// other. Public so a sender using its own HTTP client applies the same rule
/// rather than restating it.
///
/// # Errors
///
/// [`FetchError::RedirectRefused`] for 3xx, which §3.3 forbids following, and
/// [`FetchError::HttpStatus`] for anything else that is not 200.
pub fn check_status(status: u16) -> Result<(), FetchError> {
    match status {
        200 => Ok(()),
        300..=399 => Err(FetchError::RedirectRefused(status)),
        other => Err(FetchError::HttpStatus(other)),
    }
}

/// Apply §3.2's media-type rule.
///
/// "All parameters other than charset=utf-8 or charset=us-ascii are ignored.
/// Additional `Content-Type` parameters are also ignored." So the check is on
/// the type and subtype only, and a `; charset=utf-8` suffix is fine.
///
/// A missing `Content-Type` is accepted: §3.2 asks senders to validate the
/// type when present, and refusing a policy host that omits the header
/// entirely would reject deployments the RFC does not.
///
/// Public for the same reason as [`check_status`].
///
/// # Errors
///
/// [`FetchError::UnexpectedMediaType`] when `require` is set and the type is
/// present but is not `text/plain`.
pub fn check_media_type(content_type: Option<&str>, require: bool) -> Result<(), FetchError> {
    if !require {
        return Ok(());
    }
    let Some(ct) = content_type else {
        return Ok(());
    };
    let essence = ct.split(';').next().unwrap_or("").trim();
    if essence.eq_ignore_ascii_case("text/plain") {
        Ok(())
    } else {
        Err(FetchError::UnexpectedMediaType(essence.to_owned()))
    }
}

// ---------------------------------------------------------------------------
// Recognising a certificate failure
// ---------------------------------------------------------------------------

/// Walk an error chain for a certificate-validation failure.
///
/// Returns the rustls description when one is found. Shared by both backends
/// so they cannot disagree about what counts, which would make one of them
/// quietly unable to report RFC 8460 §4.3.2.2's `sts-webpki-invalid`.
///
/// # How this is determined, and how reliable each way is
///
/// Two passes, in order of trustworthiness.
///
/// **A downcast to [`rustls::Error`].** Exact, no guessing. `ureq` reports a
/// handshake failure as `Error::Io` whose `get_ref()` is the concrete
/// `rustls::Error`, so this pass catches every `ureq` case.
///
/// **The `"invalid peer certificate"` prefix.** A fallback, needed because
/// `reqwest` does not preserve the type: its chain reaches an `io::Error`
/// whose inner value is an opaque wrapper, not a `rustls::Error`, with only
/// the rendered string left. The prefix is rustls's own `Display` for
/// `Error::InvalidCertificate` (`"invalid peer certificate: {e}"`), which is
/// specific to certificate validation — exactly the scope of
/// `sts-webpki-invalid` — and is not a phrase a connection failure produces.
///
/// String matching is fragile, so it is bounded: the marker is specific, it
/// is tried only after the exact pass, and the tests assert both directions —
/// that a bad certificate is recognised, and that a refused connection and a
/// DNS failure are not. If `reqwest` or `hyper-rustls` ever preserves the
/// type, the first pass starts catching it and the fallback becomes dead
/// weight rather than a behaviour change.
///
/// Public for the same reason as [`check_status`]: a sender using its own
/// HTTP client has to make the same determination, and RFC 8460 §4.3.2.2
/// gives it a distinct report type, so restating this walk is exactly the
/// kind of duplication that ends with one caller unable to report a
/// man-in-the-middle.
///
/// Needs a backend feature, because the exact pass downcasts to
/// [`rustls::Error`] and `rustls` arrives with whichever HTTP client is
/// enabled. [`FetchError::TlsValidation`] itself is always present, so a
/// consumer such as `pkix-tlsrpt` can classify one without either backend.
#[cfg(any(feature = "client-ureq", feature = "client-reqwest"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "client-ureq", feature = "client-reqwest")))
)]
#[must_use]
pub fn certificate_failure(start: &(dyn std::error::Error + 'static)) -> Option<String> {
    /// rustls's `Display` prefix for `Error::InvalidCertificate`.
    const MARKER: &str = "invalid peer certificate";

    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(start);
    let mut fallback: Option<String> = None;

    while let Some(err) = cur {
        if let Some(r) = err.downcast_ref::<rustls::Error>() {
            return Some(r.to_string());
        }
        if let Some(io) = err.downcast_ref::<std::io::Error>() {
            if let Some(inner) = io.get_ref() {
                if let Some(r) = inner.downcast_ref::<rustls::Error>() {
                    return Some(r.to_string());
                }
                let text = inner.to_string();
                if text.contains(MARKER) {
                    fallback.get_or_insert(text);
                }
            }
        }
        let text = err.to_string();
        if text.contains(MARKER) {
            fallback.get_or_insert(text);
        }
        cur = err.source();
    }
    fallback
}

/// The URL to fetch, and the host its certificate must be valid for.
///
/// Re-exported from `pkix-mta-sts` so a caller building a request by hand
/// uses the same construction the fetchers do.
#[must_use]
pub fn policy_request_url(policy_domain: &str) -> String {
    policy_url(policy_domain)
}

/// The well-known path, for a caller building a request by hand.
#[must_use]
pub const fn well_known_path() -> &'static str {
    WELL_KNOWN_PATH
}

// ---------------------------------------------------------------------------
// Fetch and record, in one call
// ---------------------------------------------------------------------------

/// Fetch a policy and record the outcome in `store`, whichever way it went.
///
/// Every fetch must be followed by one of two bookkeeping steps: store the
/// policy, or record the failure for §3.3's backoff. Leaving that to the
/// caller makes the second one easy to omit, and omitting it disables the
/// backoff **silently** — the sender keeps retrying a failing policy host
/// every delivery attempt, which is precisely the "cascading failures"
/// against "resource-constrained recipients" that §3.3 asks senders to
/// avoid. Nothing would look broken from the sender's side.
///
/// So this does both. `policy_id` is the id from the `_mta-sts` TXT record
/// the fetch is for; it keys both the stored policy and the failure record,
/// because §3.3's limit is per version id.
///
/// # Errors
///
/// Whatever [`PolicyFetcher::fetch`] reports, after recording it. §3.3 has a
/// sender continue as though the domain has no MTA-STS policy unless a live
/// cached one exists, which is [`pkix_mta_sts::policy_to_apply`].
#[cfg(feature = "client-ureq")]
#[cfg_attr(docsrs, doc(cfg(feature = "client-ureq")))]
pub fn fetch_and_record<S>(
    fetcher: &PolicyFetcher,
    store: &S,
    policy_domain: &str,
    policy_id: &str,
    now_unix: u64,
) -> Result<pkix_mta_sts::StsPolicy, FetchError>
where
    S: pkix_mta_sts::PolicyStore + ?Sized,
{
    match fetcher.fetch(policy_domain) {
        Ok(policy) => {
            pkix_mta_sts::record_fetched_policy(
                store,
                policy_domain,
                policy.clone(),
                policy_id,
                now_unix,
            );
            Ok(policy)
        }
        Err(e) => {
            pkix_mta_sts::note_failed_fetch(store, policy_domain, policy_id, now_unix);
            Err(e)
        }
    }
}

/// [`fetch_and_record`] for the asynchronous fetcher.
///
/// # Errors
///
/// As [`fetch_and_record`].
#[cfg(feature = "client-reqwest")]
#[cfg_attr(docsrs, doc(cfg(feature = "client-reqwest")))]
pub async fn fetch_and_record_async<S>(
    fetcher: &AsyncPolicyFetcher,
    store: &S,
    policy_domain: &str,
    policy_id: &str,
    now_unix: u64,
) -> Result<pkix_mta_sts::StsPolicy, FetchError>
where
    S: pkix_mta_sts::PolicyStore + ?Sized,
{
    match fetcher.fetch(policy_domain).await {
        Ok(policy) => {
            pkix_mta_sts::record_fetched_policy(
                store,
                policy_domain,
                policy.clone(),
                policy_id,
                now_unix,
            );
            Ok(policy)
        }
        Err(e) => {
            pkix_mta_sts::note_failed_fetch(store, policy_domain, policy_id, now_unix);
            Err(e)
        }
    }
}
