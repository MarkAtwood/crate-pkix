//! The address policy, including the IPv6-reaching-IPv4 forms.
//!
//! Moved here with the code it tests when this crate was extracted from
//! `pkix-aia-http` to serve a second consumer (`pkix-mta-sts-http`).

use pkix_net_guard::{is_public, refusal_message};
use std::net::SocketAddr;

fn addr(ip: &str) -> SocketAddr {
    SocketAddr::new(ip.parse().expect("test address should parse"), 80)
}

/// Every address class a fetch must not reach.
#[test]
fn non_public_addresses_are_refused() {
    let blocked = [
        "0.0.0.0",
        "0.1.2.3",
        "127.0.0.1",
        "10.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "169.254.169.254", // cloud metadata
        "100.64.0.1",      // RFC 6598 shared, low end
        "100.127.255.255", // RFC 6598 shared, high end
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "fc00::1",
        "fd12:3456::1",
        "fe80::1",
        "fec0::1",
        "ff02::1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "::ffff:10.0.0.1",
        "::10.0.0.1",
        "64:ff9b::7f00:1",
    ];
    for ip in blocked {
        assert!(!is_public(&addr(ip)), "{ip} must be refused");
    }
}

/// Public addresses, including the near-misses that bound the ranges above.
#[test]
fn public_addresses_are_allowed() {
    let allowed = [
        "8.8.8.8",
        "1.1.1.1",
        "100.128.0.1", // just outside 100.64.0.0/10
        "172.32.0.1",  // just outside 172.16.0.0/12
        "2001:4860:4860::8888",
        "::ffff:8.8.8.8",
        "64:ff9b::808:808",
    ];
    for ip in allowed {
        assert!(is_public(&addr(ip)), "{ip} must be allowed");
    }
}

/// An IPv6 form that reaches an IPv4 address is judged by the IPv4 address.
///
/// The standard bypass for an address filter: `::ffff:127.0.0.1` is loopback
/// to the kernel but is not an `Ipv4Addr`, so a check that only looked at
/// `Ipv6Addr::is_loopback` would pass it. Asserted as a pair so the mapping
/// is shown to work in both directions rather than only refusing.
#[test]
fn ipv6_forms_reaching_ipv4_are_judged_by_the_embedded_address() {
    for (mapped, v4) in [
        ("::ffff:127.0.0.1", "127.0.0.1"),
        ("::ffff:10.0.0.1", "10.0.0.1"),
        ("::ffff:8.8.8.8", "8.8.8.8"),
        ("64:ff9b::7f00:1", "127.0.0.1"),
        ("64:ff9b::808:808", "8.8.8.8"),
    ] {
        assert_eq!(
            is_public(&addr(mapped)),
            is_public(&addr(v4)),
            "{mapped} must be judged exactly as {v4}"
        );
    }
}

/// The refusal message names the host and every address it resolved to.
///
/// An operator reading a log needs both: the host to know what was being
/// fetched, and the addresses to know why it was refused.
#[test]
fn the_refusal_message_names_the_host_and_the_addresses() {
    let msg = refusal_message(
        "mta-sts.example.com",
        &[addr("127.0.0.1"), addr("10.0.0.1")],
    );
    assert!(msg.contains("mta-sts.example.com"), "{msg}");
    assert!(msg.contains("127.0.0.1"), "{msg}");
    assert!(msg.contains("10.0.0.1"), "{msg}");
}
