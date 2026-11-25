//! Synchronous policy fetching via `ureq`.

use std::io::Read as _;
use std::sync::Arc;
use std::time::Duration;

use pkix_mta_sts::{policy_url, StsPolicy};
use pkix_net_guard::{GuardedResolver, RefusedDestination};

use crate::{check_media_type, check_status, FetchError, FetcherConfig};

/// Fetches MTA-STS policies over HTTPS, enforcing RFC 8461 §3.3.
///
/// Holds a `ureq::Agent` configured to refuse redirects and non-public
/// destinations, so the §3.3 rules cannot be lost by a caller reusing the
/// agent for something else.
#[derive(Debug, Clone)]
pub struct PolicyFetcher {
    agent: ureq::Agent,
    config: FetcherConfig,
}

impl Default for PolicyFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyFetcher {
    /// A fetcher with §3.3's suggested limits and both guards on.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(FetcherConfig::default())
    }

    /// A fetcher with explicit configuration.
    #[must_use]
    pub fn with_config(config: FetcherConfig) -> Self {
        // max_redirects(0) is the §3.3 requirement, set on the agent rather
        // than checked afterwards: a redirect must not be followed, and the
        // only way to be sure is to never allow one.
        let builder = ureq::Agent::config_builder()
            .max_redirects(0)
            .timeout_global(Some(Duration::from_secs(config.timeout_secs)));

        let agent = if config.refuse_non_public_addresses {
            ureq::Agent::with_parts(
                builder.build(),
                ureq::unversioned::transport::DefaultConnector::new(),
                GuardedResolver,
            )
        } else {
            builder.build().into()
        };

        Self { agent, config }
    }

    /// The configuration in force.
    #[must_use]
    pub const fn config(&self) -> &FetcherConfig {
        &self.config
    }

    /// Fetch and parse the policy for `policy_domain`.
    ///
    /// Fetches `https://mta-sts.<policy_domain>/.well-known/mta-sts.txt`. The
    /// TLS handshake validates the certificate against `ureq`'s configured
    /// roots for that host, which is §3.3's trust basis.
    ///
    /// # Errors
    ///
    /// See [`FetchError`]. §3.3 treats every failure alike for delivery:
    /// continue as though the domain has not implemented MTA-STS, unless a
    /// live cached policy exists. Pass `None` to
    /// [`pkix_mta_sts::policy_to_apply`] and it applies that rule.
    pub fn fetch(&self, policy_domain: &str) -> Result<StsPolicy, FetchError> {
        let url = policy_url(policy_domain);
        let mut response = match self.agent.get(&url).call() {
            Ok(r) => r,
            Err(e) => return Err(map_ureq_error(e, policy_domain)),
        };

        check_status(response.status().as_u16())?;

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        check_media_type(content_type.as_deref(), self.config.require_text_plain)?;

        // Read one byte past the cap so an oversized body is detected rather
        // than silently truncated into a policy that parses.
        let cap = self.config.max_body_bytes;
        let mut body = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(cap as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|e| FetchError::Transport(e.to_string()))?;
        if body.len() > cap {
            return Err(FetchError::BodyTooLarge(cap));
        }

        let text = String::from_utf8(body)
            .map_err(|_| FetchError::UnexpectedMediaType(String::from("non-UTF-8 body")))?;
        StsPolicy::parse(&text).map_err(FetchError::Malformed)
    }
}

/// Map a `ureq` error, recovering what is buried inside it.
///
/// Two things hide in `Error::Io`'s payload and must be dug out before the
/// error is flattened to a string: this crate's own destination refusal, and
/// a `rustls::Error` from a failed handshake. Both carry more meaning than
/// "transport failed".
fn map_ureq_error(e: ureq::Error, policy_domain: &str) -> FetchError {
    if let ureq::Error::Io(io) = &e {
        if let Some(refused) = io
            .get_ref()
            .and_then(|i| i.downcast_ref::<RefusedDestination>())
        {
            return FetchError::DestinationRefused(refused.0.clone());
        }
        // ureq reports a handshake failure here, with the concrete
        // rustls::Error as the payload, so this is an exact determination.
        if let Some(inner) = io.get_ref() {
            if let Some(cert) = crate::certificate_failure(inner) {
                return FetchError::TlsValidation(cert);
            }
        }
    }
    if let Some(cert) = crate::certificate_failure(&e) {
        return FetchError::TlsValidation(cert);
    }
    match e {
        // A 3xx with max_redirects(0) surfaces as a status code rather than
        // being followed, which is exactly what §3.3 requires.
        ureq::Error::StatusCode(code) if (300..=399).contains(&code) => {
            FetchError::RedirectRefused(code)
        }
        ureq::Error::StatusCode(code) => FetchError::HttpStatus(code),
        ureq::Error::Timeout(_) => FetchError::Timeout,
        other => FetchError::Transport(format!("{policy_domain}: {other}")),
    }
}

// Send + Sync, per AGENTS.md non-negotiable #6: a fetcher is shared across
// delivery threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PolicyFetcher>();
    let _ = Arc::new(PolicyFetcher::new());
};
