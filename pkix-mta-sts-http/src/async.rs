//! Asynchronous policy fetching via `reqwest`.
//!
//! Parity with the synchronous fetcher on everything that matters for safety:
//! redirects refused, non-public destinations refused at resolution time, a
//! timeout, a body cap, and the same status and media-type checks — which are
//! shared functions rather than two implementations, so the backends cannot
//! drift into one being less safe than the other.

use std::sync::Arc;
use std::time::Duration;

use pkix_mta_sts::{policy_url, StsPolicy};
use pkix_net_guard::GuardedAsyncResolver;

use crate::{check_media_type, check_status, FetchError, FetcherConfig};

/// Fetches MTA-STS policies over HTTPS, asynchronously.
#[derive(Debug, Clone)]
pub struct AsyncPolicyFetcher {
    client: reqwest::Client,
    config: FetcherConfig,
}

impl AsyncPolicyFetcher {
    /// A fetcher with §3.3's suggested limits and both guards on.
    ///
    /// # Panics
    ///
    /// If the underlying `reqwest::Client` cannot be built, which indicates a
    /// missing TLS backend in the build rather than anything about the
    /// arguments — a condition a caller cannot act on at runtime.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(FetcherConfig::default())
    }

    /// A fetcher with explicit configuration.
    ///
    /// # Panics
    ///
    /// As [`new`](Self::new).
    #[must_use]
    pub fn with_config(config: FetcherConfig) -> Self {
        let mut builder = reqwest::Client::builder()
            // §3.3: 3xx MUST NOT be followed.
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(config.timeout_secs));
        if config.refuse_non_public_addresses {
            builder = builder.dns_resolver(Arc::new(GuardedAsyncResolver));
        }
        let client = builder
            .build()
            .expect("reqwest client should build with a TLS backend compiled in");
        Self { client, config }
    }

    /// The configuration in force.
    #[must_use]
    pub const fn config(&self) -> &FetcherConfig {
        &self.config
    }

    /// Fetch and parse the policy for `policy_domain`.
    ///
    /// # Errors
    ///
    /// See [`FetchError`], and [`crate::PolicyFetcher::fetch`] for how §3.3
    /// has a sender treat a failure.
    pub async fn fetch(&self, policy_domain: &str) -> Result<StsPolicy, FetchError> {
        let url = policy_url(policy_domain);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| map_reqwest_error(&e, policy_domain))?;

        check_status(response.status().as_u16())?;

        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        check_media_type(content_type.as_deref(), self.config.require_text_plain)?;

        // Check Content-Length first where present, so an oversized body is
        // refused before it is transferred rather than after.
        let cap = self.config.max_body_bytes;
        if response.content_length().is_some_and(|n| n > cap as u64) {
            return Err(FetchError::BodyTooLarge(cap));
        }

        let body = response
            .bytes()
            .await
            .map_err(|e| map_reqwest_error(&e, policy_domain))?;
        if body.len() > cap {
            return Err(FetchError::BodyTooLarge(cap));
        }

        let text = core::str::from_utf8(&body)
            .map_err(|_| FetchError::UnexpectedMediaType(String::from("non-UTF-8 body")))?;
        StsPolicy::parse(text).map_err(FetchError::Malformed)
    }
}

impl Default for AsyncPolicyFetcher {
    fn default() -> Self {
        Self::new()
    }
}

fn map_reqwest_error(e: &reqwest::Error, policy_domain: &str) -> FetchError {
    if e.is_timeout() {
        return FetchError::Timeout;
    }
    // A destination refusal arrives as a connect error wrapping the
    // resolver's PermissionDenied. reqwest erases the type, so the message is
    // what identifies it — matched on the phrase pkix-net-guard builds.
    let text = e.to_string();
    let chain = {
        let mut s = text.clone();
        let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(e);
        while let Some(inner) = src {
            s.push_str("; ");
            s.push_str(&inner.to_string());
            src = inner.source();
        }
        s
    };
    if chain.contains("non-public addresses") {
        return FetchError::DestinationRefused(chain);
    }
    FetchError::Transport(format!("{policy_domain}: {chain}"))
}

const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<AsyncPolicyFetcher>();
};
