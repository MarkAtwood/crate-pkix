//! Discovering which upstream DNS server to query.
//!
//! Resolution order, decided for this workspace and recorded under
//! `PKIX-j32w.5`:
//!
//! 1. the `PKIX_DANE_RESOLVER` environment variable, if set;
//! 2. otherwise the system configuration — `/etc/resolv.conf` on Unix, the
//!    platform API elsewhere.
//!
//! No hardcoded public resolvers. Pointing at `1.1.1.1` or `8.8.8.8` by
//! default would break split-horizon networks where internal names resolve
//! only internally, and would send the hostname of every certificate being
//! verified to a third party — a privacy leak the consumer never asked for
//! from a certificate-validation library.
//!
//! # This is not a trust decision
//!
//! Reading the environment for a server address looks like the kind of
//! ambient dependency the rest of this workspace avoids. It is not, because
//! no trust flows from it: the resolver validates DNSSEC signatures itself, so
//! a hostile or misconfigured upstream can cause a lookup to fail or to come
//! back [`Bogus`](pkix_dane::DnssecStatus::Bogus), but it cannot cause a
//! forged record to be accepted. The trust anchor — the thing that *is* a
//! trust decision — is supplied by the caller and read from nowhere.
//!
//! The environment override exists for a specific operational case: an
//! organization whose own resolver strips or mangles DNSSEC records, where
//! DANE queries need to go somewhere else without the consumer changing code.

use std::net::{IpAddr, SocketAddr};

use crate::ResolverError;

/// Name of the environment variable that overrides upstream server discovery.
pub const ENV_VAR: &str = "PKIX_DANE_RESOLVER";

/// Default DNS port, used for an override entry that names no port.
const DEFAULT_PORT: u16 = 53;

/// Where a resolver should send its queries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpstreamConfig {
    /// Explicit servers, from the environment override.
    ///
    /// Queried in the order given.
    Servers(Vec<SocketAddr>),

    /// Whatever the operating system is configured to use.
    ///
    /// Read by the DNS stack at construction time: `/etc/resolv.conf` on
    /// Unix, the platform API on Windows and macOS.
    System,
}

/// Determines the upstream configuration from the environment.
///
/// Returns [`UpstreamConfig::Servers`] when [`ENV_VAR`] is set to a usable
/// value, and [`UpstreamConfig::System`] otherwise.
///
/// The variable holds one or more addresses separated by commas or
/// whitespace. Each is an IP address with an optional port: `9.9.9.9`,
/// `9.9.9.9:53`, `[2620:fe::fe]:53`. A bare IPv6 address needs no brackets;
/// brackets are required only when a port follows.
///
/// # Errors
///
/// [`ResolverError::UpstreamUnavailable`] if the variable is set but no entry
/// parses. A set-but-unusable override is an error rather than a silent
/// fallback to system configuration: an operator who set it meant to redirect
/// DANE queries, and quietly ignoring a typo would send them somewhere they
/// specifically chose to avoid.
///
/// An empty or whitespace-only value is treated as unset, so clearing the
/// variable works as expected.
///
/// # Examples
///
/// ```
/// use pkix_dane_resolver::{upstream_from_environment, UpstreamConfig};
///
/// // With the variable unset, the system configuration is used.
/// # unsafe { std::env::remove_var("PKIX_DANE_RESOLVER") };
/// assert_eq!(upstream_from_environment()?, UpstreamConfig::System);
/// # Ok::<(), pkix_dane_resolver::ResolverError>(())
/// ```
pub fn upstream_from_environment() -> Result<UpstreamConfig, ResolverError> {
    match std::env::var(ENV_VAR) {
        Ok(raw) => parse_upstream(&raw),
        Err(_) => Ok(UpstreamConfig::System),
    }
}

/// Parses the environment override's value.
///
/// Split out from [`upstream_from_environment`] so it is testable without
/// mutating process-global state, which is not safe to do from concurrent
/// tests.
///
/// # Errors
///
/// [`ResolverError::UpstreamUnavailable`] if no entry parses. See
/// [`upstream_from_environment`] for why that is an error.
pub fn parse_upstream(raw: &str) -> Result<UpstreamConfig, ResolverError> {
    let entries: Vec<&str> = raw
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .collect();

    if entries.is_empty() {
        // Set-but-empty is indistinguishable from the operator clearing it.
        return Ok(UpstreamConfig::System);
    }

    let mut servers = Vec::with_capacity(entries.len());
    let mut rejected = Vec::new();
    for entry in entries {
        match parse_server(entry) {
            Some(addr) => servers.push(addr),
            None => rejected.push(entry),
        }
    }

    if servers.is_empty() {
        return Err(ResolverError::UpstreamUnavailable(format!(
            "{ENV_VAR} is set but no entry parsed as an address: {}",
            rejected.join(", ")
        )));
    }
    Ok(UpstreamConfig::Servers(servers))
}

/// Parses one entry as an IP address with an optional port.
fn parse_server(entry: &str) -> Option<SocketAddr> {
    // `addr:port`, including the bracketed IPv6 form.
    if let Ok(addr) = entry.parse::<SocketAddr>() {
        return Some(addr);
    }
    // A bare address, bracketed or not.
    let bare = entry
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(entry);
    bare.parse::<IpAddr>()
        .ok()
        .map(|ip| SocketAddr::new(ip, DEFAULT_PORT))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn an_unset_or_empty_value_means_system_configuration() {
        for raw in ["", "   ", "\t\n", ",,", " , , "] {
            assert_eq!(
                parse_upstream(raw).expect("empty should not error"),
                UpstreamConfig::System,
                "{raw:?} should mean system configuration"
            );
        }
    }

    #[test]
    fn a_bare_address_gets_the_default_dns_port() {
        let config = parse_upstream("9.9.9.9").expect("valid");
        assert_eq!(
            config,
            UpstreamConfig::Servers(vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                53
            )])
        );
    }

    #[test]
    fn an_explicit_port_is_honoured() {
        let config = parse_upstream("9.9.9.9:5353").expect("valid");
        assert_eq!(
            config,
            UpstreamConfig::Servers(vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                5353
            )])
        );
    }

    #[test]
    fn ipv6_works_bare_bracketed_and_with_a_port() {
        let expected = IpAddr::V6(Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0xfe));
        for (raw, port) in [
            ("2620:fe::fe", 53),
            ("[2620:fe::fe]", 53),
            ("[2620:fe::fe]:5353", 5353),
        ] {
            let config = parse_upstream(raw).expect("valid");
            assert_eq!(
                config,
                UpstreamConfig::Servers(vec![SocketAddr::new(expected, port)]),
                "{raw:?} should parse"
            );
        }
    }

    #[test]
    fn several_servers_keep_their_order() {
        for separator in [",", " ", ", ", "\t"] {
            let raw = format!("9.9.9.9{separator}1.0.0.1");
            let config = parse_upstream(&raw).expect("valid");
            assert_eq!(
                config,
                UpstreamConfig::Servers(vec![
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 53),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)), 53),
                ]),
                "separator {separator:?} should work"
            );
        }
    }

    /// A set-but-unparsable override is an error, not a silent fallback. An
    /// operator who set it meant to redirect DANE queries; ignoring a typo
    /// would send them to the resolver they chose to avoid.
    #[test]
    fn a_wholly_unparsable_override_is_an_error() {
        for raw in ["not-an-address", "example.com", "999.999.999.999", "1.2.3"] {
            let err = parse_upstream(raw).expect_err("should be rejected");
            assert!(
                matches!(err, ResolverError::UpstreamUnavailable(_)),
                "{raw:?} gave {err:?}"
            );
            assert!(
                err.to_string().contains(raw),
                "diagnostic should name the entry"
            );
        }
    }

    /// Hostnames are refused rather than resolved. Resolving the address of
    /// the resolver would need a resolver, and the bootstrap is the caller's
    /// problem to state explicitly.
    #[test]
    fn hostnames_are_not_accepted() {
        assert!(parse_upstream("dns.example.com").is_err());
        assert!(parse_upstream("dns.example.com:53").is_err());
    }

    /// One good entry carries the override even if another is malformed, so a
    /// typo in a list does not take DANE down entirely. The rejected entries
    /// are still named in no diagnostic here — they are simply skipped, which
    /// is why the all-bad case is the one that errors.
    #[test]
    fn a_partly_valid_list_keeps_the_valid_entries() {
        let config = parse_upstream("garbage, 9.9.9.9").expect("one entry is valid");
        assert_eq!(
            config,
            UpstreamConfig::Servers(vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                53
            )])
        );
    }
}
