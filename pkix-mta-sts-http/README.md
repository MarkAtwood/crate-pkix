# pkix-mta-sts-http

MTA-STS policy fetching over HTTPS, per [RFC 8461] §3.3.

`pkix-mta-sts` parses a policy and decides when one is needed. This crate
performs the fetch, enforcing the §3.3 requirements that make the fetched
policy worth trusting.

```rust,no_run
use pkix_mta_sts_http::PolicyFetcher;

let fetcher = PolicyFetcher::new();
// https://mta-sts.example.com/.well-known/mta-sts.txt
let policy = fetcher.fetch("example.com")?;
println!("mode: {:?}, max_age: {}", policy.mode(), policy.max_age());
# Ok::<(), pkix_mta_sts_http::FetchError>(())
```

## What §3.3 requires, and why each one is load-bearing

The policy's only authentication is this HTTPS connection — the `_mta-sts` TXT
record is unsigned. So none of these is hygiene:

| Requirement | What goes wrong without it |
|---|---|
| Certificate valid for `mta-sts.<domain>`, trusted, unexpired | Anyone on the path writes the policy |
| Only HTTP 200 is a policy | A 404 becomes "an empty policy"; a 500 becomes "no MTA-STS" |
| 3xx **MUST NOT** be followed | Whoever controls the policy host moves the fetch somewhere whose certificate says nothing about the domain |
| HTTP caching **MUST NOT** be used | A stale policy is extended by an interval the sender never agreed to |
| `Content-Type` should be `text/plain` | A shared host that lets users upload to a path becomes a way to publish a policy for someone else's domain |

All five are enforced. The media-type check is on by default although §3.2
words it as SHOULD, because the failure it prevents is someone else's policy
being accepted for your domain.

§3.3's suggested limits — one minute, 64 kilobytes — are applied by default,
because a policy host that never finishes responding would otherwise hold a
delivery attempt open.

## Destination policy

The host is `mta-sts.` prepended to a **recipient domain**, so a sender
fetches from a host chosen by whoever it is sending mail to.

Non-public addresses are refused at resolution time by
[`pkix-net-guard`](../pkix-net-guard), shared with `pkix-aia-http`. Filtering
inside the resolver leaves no window for DNS rebinding, which a pre-flight
check on the host name would. Tested end to end against a loopback policy
host, with the complement asserted so the refusal is shown to come from the
guard rather than from the host being unreachable.

## What this crate deliberately does not do

**The TXT lookup.** `_mta-sts.<domain>` is a DNS query and §3.1 requires
following CNAMEs. A sender already has a resolver; this crate does not bring a
second one. `pkix_mta_sts::txt_name` builds the name and
`StsTxtRecord::select` applies §3.1's record selection to whatever comes back.

**The cache.** `pkix_mta_sts::plan` and `policy_to_apply` hold the §3.3 and
§5.1 rules, and the storage is the caller's — no filesystem, no OS dependency.

Which matters more than it sounds: the cache *is* MTA-STS's security
mechanism. First contact is trust-on-first-use, so everything the mechanism
protects comes from having cached a policy before an attacker arrived. A
fetcher without the cache rules is not a shortcut to MTA-STS.

**Certificate validation is the HTTP client's.** Both backends validate
against their configured Web PKI roots. A sender needing a specific trust
store, or revocation checking as §3.3's MAY permits, configures the client.

## Features

- `client-ureq` (default) — `PolicyFetcher`, synchronous
- `client-reqwest` — `AsyncPolicyFetcher`

`check_status` and `check_media_type` are public and need no feature, so a
sender using its own HTTP client applies the same rules rather than restating
them.

## License

Apache-2.0 OR MIT, at your option.

[RFC 8461]: https://www.rfc-editor.org/rfc/rfc8461
