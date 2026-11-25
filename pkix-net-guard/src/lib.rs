//! Destination policy for HTTP fetches from caller-influenced URLs.
//!
//! Several PKIX mechanisms fetch over HTTP from a host derived from data a
//! relying party did not choose: an AIA `caIssuers` URI in a certificate, a
//! CRL distribution point, an MTA-STS policy host built from a recipient
//! domain. Each is an outbound request whose destination an attacker has some
//! say over, which is the shape of a server-side request forgery.
//!
//! This crate is the shared answer: refuse non-public addresses, and refuse
//! them **at resolution time**.
//!
//! # Why resolution time, and not a check on the host name
//!
//! Checking the host or its address before issuing the request leaves a
//! window. The name can resolve to a public address when checked and to
//! `127.0.0.1` when connected — DNS rebinding. Both resolvers here filter
//! inside the resolver the HTTP client itself calls, and a client connects
//! only to addresses its resolver returns, so there is no interval between
//! the decision and the connection.
//!
//! # What counts as non-public
//!
//! [`is_public`] refuses loopback, private (RFC 1918), link-local (including
//! `169.254.169.254`, the cloud metadata address), RFC 6598 shared address
//! space, multicast, `0.0.0.0/8`, `240.0.0.0/4`, IPv6 unique-local,
//! link-local and the deprecated site-local range.
//!
//! It also judges the addresses that *reach* an IPv4 destination through an
//! IPv6 one by the embedded IPv4 address: IPv4-mapped (`::ffff:a.b.c.d`),
//! IPv4-compatible (`::a.b.c.d`) and the NAT64 well-known prefix
//! (`64:ff9b::a.b.c.d`). Missing those is the standard way an address filter
//! is bypassed, since `::ffff:127.0.0.1` is loopback to the kernel but is not
//! an `Ipv4Addr` to a naive check.
//!
//! # This is not a complete SSRF defence
//!
//! It stops an outbound request reaching a private network. It does not stop
//! a request to a public address the operator would rather not contact, and
//! it knows nothing about proxies: a client configured with an HTTP proxy
//! resolves nothing itself, so the policy does not apply. A deployment that
//! needs an allow-list rather than a deny-list should supply its own
//! resolver.

#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Marker error for a refusal by one of this crate's resolvers.
///
/// Carried inside the HTTP client's own I/O error so a caller can recognise
/// a destination refusal and distinguish it from an ordinary network failure
/// — which matters, because the two call for different operator action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedDestination(pub String);

impl std::fmt::Display for RefusedDestination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RefusedDestination {}

/// Build the refusal message for a host that resolved only to refused
/// addresses.
///
/// Shared so the sync and async resolvers report identically; an operator
/// reading a log should not be able to tell which backend refused.
#[must_use]
pub fn refusal_message(host: &str, resolved: &[SocketAddr]) -> String {
    let addrs: Vec<String> = resolved.iter().map(|a| a.ip().to_string()).collect();
    format!(
        "{host} resolves only to non-public addresses [{}]",
        addrs.join(", ")
    )
}

/// Whether `addr` is a public address this crate will allow a fetch to.
#[must_use]
pub fn is_public(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    !(ip.is_unspecified()
        || a == 0 // 0.0.0.0/8 "this network"
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || (a == 100 && (b & 0xc0) == 64) // 100.64.0.0/10 shared (RFC 6598)
        || ip.is_multicast()
        || a >= 240) // 240.0.0.0/4 reserved, incl. 255.255.255.255
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let seg = ip.segments();
    // IPv4-mapped (::ffff:a.b.c.d), IPv4-compatible (::a.b.c.d) and NAT64
    // well-known-prefix (64:ff9b::a.b.c.d) addresses reach the embedded
    // IPv4 address; judge them by it.
    let embedded = Ipv4Addr::new(
        (seg[6] >> 8) as u8,
        seg[6] as u8,
        (seg[7] >> 8) as u8,
        seg[7] as u8,
    );
    if seg[..5] == [0, 0, 0, 0, 0] && (seg[5] == 0xffff || seg[5] == 0) {
        // `::` and `::1` fall in the IPv4-compatible range; reject them
        // via the IPv6 checks below rather than as 0.0.0.x.
        if seg[5] == 0xffff || !(ip.is_unspecified() || ip.is_loopback()) {
            return is_public_v4(embedded);
        }
    }
    if seg[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return is_public_v4(embedded);
    }
    !(ip.is_unspecified()
        || ip.is_loopback()
        || (seg[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
        || (seg[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        || (seg[0] & 0xffc0) == 0xfec0 // fec0::/10 site-local (deprecated)
        || ip.is_multicast())
}

// ---------------------------------------------------------------------------
// ureq
// ---------------------------------------------------------------------------

#[cfg(feature = "ureq")]
#[cfg_attr(docsrs, doc(cfg(feature = "ureq")))]
mod sync_resolver {
    use super::{is_public, refusal_message, RefusedDestination};
    use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
    use ureq::unversioned::transport::NextTimeout;

    /// `ureq` resolver that drops non-public addresses.
    ///
    /// Wraps [`DefaultResolver`]. `ureq` connects only to the addresses a
    /// resolver returns, so filtering here rather than checking the host name
    /// before the request leaves no window for DNS rebinding.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct GuardedResolver;

    impl Resolver for GuardedResolver {
        fn resolve(
            &self,
            uri: &ureq::http::Uri,
            config: &ureq::config::Config,
            timeout: NextTimeout,
        ) -> Result<ResolvedSocketAddrs, ureq::Error> {
            let resolved = DefaultResolver::default().resolve(uri, config, timeout)?;
            let mut allowed = self.empty();
            let mut any_allowed = false;
            for addr in resolved.iter().filter(|a| is_public(a)) {
                allowed.push(*addr);
                any_allowed = true;
            }
            if !any_allowed {
                let host = uri.host().unwrap_or("");
                let all: Vec<_> = resolved.iter().copied().collect();
                return Err(ureq::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    RefusedDestination(refusal_message(host, &all)),
                )));
            }
            Ok(allowed)
        }
    }
}

#[cfg(feature = "ureq")]
pub use sync_resolver::GuardedResolver;

// ---------------------------------------------------------------------------
// reqwest
// ---------------------------------------------------------------------------

#[cfg(feature = "reqwest")]
#[cfg_attr(docsrs, doc(cfg(feature = "reqwest")))]
mod async_resolver {
    use super::{is_public, refusal_message};
    use reqwest::dns::{Addrs, Name, Resolve, Resolving};
    use std::net::SocketAddr;

    /// `reqwest` resolver that drops non-public addresses.
    ///
    /// Applied at resolution rather than as a pre-flight check on the name,
    /// for the reason in the crate documentation: a name could resolve to a
    /// public address at check time and a loopback address at connect time.
    ///
    /// Name lookup uses `tokio::net::lookup_host`, which is asynchronous.
    /// `std::net::ToSocketAddrs` would be simpler and is what the sync
    /// resolver ultimately uses, but it blocks, and blocking inside an async
    /// fn starves the executor.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct GuardedAsyncResolver;

    impl Resolve for GuardedAsyncResolver {
        fn resolve(&self, name: Name) -> Resolving {
            Box::pin(async move {
                let host = name.as_str().to_owned();
                // Port 0 is a placeholder; reqwest substitutes the real port.
                let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                    .await
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
                    .collect();

                let allowed: Vec<SocketAddr> = resolved.iter().copied().filter(is_public).collect();

                if allowed.is_empty() {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        refusal_message(&host, &resolved),
                    ))
                        as Box<dyn std::error::Error + Send + Sync>);
                }
                Ok(Box::new(allowed.into_iter()) as Addrs)
            })
        }
    }
}

#[cfg(feature = "reqwest")]
pub use async_resolver::GuardedAsyncResolver;
