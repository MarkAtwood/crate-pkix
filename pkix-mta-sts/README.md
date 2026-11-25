# pkix-mta-sts

MTA-STS policy parsing and MX matching, per [RFC 8461].

No DNS, no HTTP, no clock, no filesystem. A caller fetches the policy text and
passes it in, exactly as `pkix-dane` takes TLSA records rather than resolving
them. That keeps the crate `no_std` and leaves fetching — which needs HTTPS,
certificate validation and a cache — to an adapter.

```rust
use pkix_mta_sts::{Mode, PolicyOutcome, StsPolicy};

let policy = StsPolicy::parse(
    "version: STSv1\r\n\
     mode: enforce\r\n\
     mx: mail.example.com\r\n\
     mx: *.example.net\r\n\
     max_age: 604800\r\n",
)?;

assert_eq!(policy.mode(), Mode::Enforce);
assert_eq!(policy.evaluate("mail.example.com"), PolicyOutcome::Matched);
assert_eq!(policy.evaluate("evil.example.org"), PolicyOutcome::FailedEnforce);
# Ok::<(), pkix_mta_sts::PolicyError>(())
```

## What this is for

SMTP's `STARTTLS` is opportunistic: an active attacker strips the advertisement
and the message goes in plaintext, with no signal to either end. MTA-STS and
DANE both close that, from different roots of trust.

MTA-STS is **weaker than DANE**, and this crate's documentation says so rather
than implying parity. RFC 8461 §1 is direct about the trade:

> DANE requires DNSSEC [RFC4033] for authentication; the mechanism described
> here instead relies on certification authorities (CAs) and does not require
> DNSSEC, at a cost of risking malicious downgrades.

A policy is authenticated by the Web PKI plus an **unsigned** DNS TXT record,
so first contact is trust-on-first-use and the protection comes from caching a
policy for up to a year. §10.2 names what is lost: resistance to that class of
downgrade "is a feature of DANE, due to its use of DNSSEC for policy
discovery".

That is a reason to implement MTA-STS, not to refuse it. It deploys where
DNSSEC does not, which is most of the mail system — Gmail, Outlook and Fastmail
publish MTA-STS policies, and a DANE-only sender protects none of that mail.

## MTA-STS must not override a failing DANE validation

RFC 8461 §2, verbatim:

> senders who implement MTA-STS validation MUST NOT allow MTA-STS Policy
> validation to override a failing DANE validation.

A sender doing both consults DANE first. Where
`pkix_chain::verify_smtp_server_dane` returns `SmtpDaneVerdict::Failed`, no
MTA-STS result may rescue the delivery — `PolicyOutcome::Matched` included.

This crate cannot enforce that, because it never sees a DANE verdict. The
ordering belongs to whoever holds both, and `PolicyOutcome`'s documentation
says so at the point a caller would otherwise get it wrong.

## Certificate validation wants a SAN, unlike SMTP DANE

RFC 8461 §4.2 requires the MX certificate to carry "a subject alternative name
(SAN) [RFC5280] with a DNS-ID [RFC6125] matching the hostname". That is
ordinary Web PKI, so `pkix_profiles::BasicTlsProfile` is the right profile.

The opposite of SMTP DANE, where RFC 7672 §3.2.3 consults the `commonName` and
a SAN-requiring profile rejects valid deployments — which is why
`pkix_profiles::BasicSmtpMtaProfile` requires neither a SAN nor an EKU. Two
SMTP transport-security mechanisms, two different correct profiles, and
choosing the wrong one fails real mail.

## MX matching is `pkix-identity`'s rule, not a second copy

RFC 8461 §4.1 defines matching by reference to RFC 6125, "with the restriction
that the wildcard character `*` may only be used to match the entire left-most
label". That is `pkix_identity::dns_name_matches_pattern`, and this crate
delegates to it.

Restating a security-relevant matching rule would be a divergence hazard, and a
wildcard bug is a security bug. A test asserts the two agree.

## What is deliberately not here

**Policy discovery.** The `_mta-sts.<domain>` TXT lookup and the HTTPS GET of
`https://mta-sts.<domain>/.well-known/mta-sts.txt` need a resolver, a TLS
client and a cache. They belong in an adapter, which does not exist yet.

**TLSRPT (RFC 8460).** `PolicyOutcome::is_validation_failure` is the hook a
reporter needs — it is true for `testing` failures, which is the distinction
that mode exists to create — but this crate emits no reports.

**Persistent policy storage.** `PolicyStore` is the trait, and
`InMemoryPolicyStore` (feature `std`) is a complete in-process
implementation — it survives the life of the process, which covers a
long-running MTA, but not a restart. Since MTA-STS's protection comes from
holding a policy across the moment an attacker shows up, a process that
restarts often wants something durable; implement the trait over whatever the
deployment already has. Enable `serde` to persist a `CachedPolicy`.

## Known deviations from the grammar

Two, both deliberate and both tested:

- **Keywords are matched case-insensitively.** §3.2's ABNF writes every
  keyword with RFC 7405's `%s` prefix, which means case-sensitive, so `mode:
  Enforce` is strictly non-conforming. Rejecting it would report *no policy*,
  and a sender with no policy applies no protection: leniency yields enforce,
  strictness yields plaintext. No two keywords differ only by case, so nothing
  becomes ambiguous.

- **Bare LF is accepted alongside CRLF.** A policy is served over HTTP by
  arbitrary web servers, and failing a domain over line endings would break
  deployments that work everywhere else.

`max_age` is *not* lenient: the ABNF says `1*10(DIGIT)` and that is enforced,
so a leading `+` or an underscore separator is rejected even though
`u64::from_str` would take it.

## License

Apache-2.0 OR MIT, at your option.

[RFC 8461]: https://www.rfc-editor.org/rfc/rfc8461
