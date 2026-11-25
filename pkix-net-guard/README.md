# pkix-net-guard

Destination policy for HTTP fetches from caller-influenced URLs: refuse
non-public addresses, **at resolution time**.

```rust
use pkix_net_guard::is_public;
use std::net::SocketAddr;

let metadata: SocketAddr = "169.254.169.254:80".parse()?;
assert!(!is_public(&metadata));

// An IPv6 form that reaches an IPv4 address is judged by that address.
let mapped: SocketAddr = "[::ffff:127.0.0.1]:80".parse()?;
assert!(!is_public(&mapped));
# Ok::<(), std::net::AddrParseError>(())
```

## Why this exists

Several PKIX mechanisms fetch over HTTP from a host derived from data the
relying party did not choose:

- an AIA `caIssuers` URI, from a certificate someone else issued
- a CRL distribution point, likewise
- an MTA-STS policy host, built from a recipient domain

Each is an outbound request whose destination an attacker has some say over,
which is the shape of a server-side request forgery.

## Why resolution time

Checking the host name or its address *before* issuing the request leaves a
window: the name can resolve to a public address when checked and to
`127.0.0.1` when connected. That is DNS rebinding.

Both resolvers here filter inside the resolver the HTTP client itself calls,
and a client connects only to addresses its resolver returns, so there is no
interval between the decision and the connection.

## What counts as non-public

Loopback, private (RFC 1918), link-local — including `169.254.169.254`, the
cloud metadata address — RFC 6598 shared space, multicast, `0.0.0.0/8`,
`240.0.0.0/4`, IPv6 unique-local, link-local, and the deprecated site-local
range.

And the forms that *reach* an IPv4 destination through an IPv6 one, judged by
the embedded IPv4 address: IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible
(`::a.b.c.d`), and the NAT64 well-known prefix (`64:ff9b::a.b.c.d`).

Missing those is the standard way an address filter is bypassed:
`::ffff:127.0.0.1` is loopback to the kernel but is not an `Ipv4Addr`, so a
check that only asked `Ipv6Addr::is_loopback` would pass it.

## This is not a complete SSRF defence

It stops an outbound request reaching a private network. It does not stop a
request to a public address the operator would rather not contact, and it
knows nothing about proxies — a client configured with an HTTP proxy resolves
nothing itself, so the policy does not apply.

A deployment that needs an allow-list rather than a deny-list should supply
its own resolver.

## Why it is its own crate

It was `pkix-aia-http`'s, until MTA-STS policy fetching needed the same
policy. The address classification above is subtle and its whole job is
refusing a request, so a second copy would be a divergence hazard on exactly
the wrong code. `pkix-aia-http` re-exports both resolvers, so its public API
is unchanged.

## Features

- `ureq` — `GuardedResolver`, for synchronous clients
- `reqwest` — `GuardedAsyncResolver`, for asynchronous clients

Neither is on by default; `is_public` and `refusal_message` need no feature.

## License

Apache-2.0 OR MIT, at your option.
