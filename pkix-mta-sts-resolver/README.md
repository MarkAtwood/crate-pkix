# pkix-mta-sts-resolver

`_mta-sts` TXT record lookup, per [RFC 8461] §3.1.

The DNS half of MTA-STS policy discovery. `pkix-mta-sts` holds §3.1's parsing
and record-selection rules; this crate performs the query and applies them.

```rust,no_run
use pkix_mta_sts_resolver::MtaStsResolver;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let resolver = MtaStsResolver::from_system()?;
// Queries _mta-sts.example.com TXT
let record = resolver.lookup("example.com").await?;
println!("policy id: {}", record.id());
# Ok(())
# }
```

## DNSSEC is not required here, unlike DANE

The workspace's other resolver insists on it: `pkix-dane-resolver` sets
hickory's `validate` option and refuses an unvalidated answer, because
RFC 7672 §2.1.1 makes an indeterminate TLSA lookup equivalent to an insecure
one — DANE's whole trust basis is DNSSEC.

MTA-STS's is not. RFC 8461 §1 "relies on certification authorities (CAs) and
does not require DNSSEC, at a cost of risking malicious downgrades". The TXT
record carries no authentication at all: it is a change token pointing at a
policy whose trust comes from the HTTPS certificate.

So this resolver does **not** require DNSSEC, and requiring it would refuse
policies from the overwhelming majority of conforming domains. A deployment
that wants it anyway can pass a validating resolver to `from_resolver` — but
it should know it is imposing a requirement RFC 8461 does not, and that the
protection is small, since an attacker who cannot touch DNS can still serve
the policy.

## What §3.1 requires

- The name is `_mta-sts.<policy-domain>`, and §3.4 forbids falling back to a
  parent zone, so the domain is used unchanged
- A CNAME **MUST** be followed, directly or through further CNAMEs; §8.2 uses
  that for policy delegation. Hickory follows CNAMEs itself
- Records not beginning with the version tag are discarded, so a domain may
  publish other TXT records at the same name
- If the surviving count is not one there is no usable policy — ambiguity is
  not resolved by picking one, since which policy is current is exactly what
  the id exists to settle
- Several character-strings in one record join **without spaces**. A TXT
  record is length-prefixed strings of at most 255 bytes each, so a long
  record arrives split, and joining with a space — the intuitive thing —
  would corrupt whichever field straddles the boundary

## A failed lookup does not mean "no policy"

§3.1: "the absence of a usable TXT record is not by itself sufficient to
remove a sender's previously cached policy".

So pass `LookupError::as_txt_error` to `pkix_mta_sts::plan` rather than
deciding from the failure yourself. That function returns `UseCached` when a
live cached policy exists, not `NoPolicy` — and getting this backwards would
strip up to a year of protection on one failed DNS query.

`LookupError::kind` separates a domain with no policy from a broken resolver.
Identical for delivery; different for diagnosis, which §3.3 asks for: "MTAs
SHOULD alert administrators... when such attempts fail".

## Testing

The offline tests cover construction and the error bridge. Three live tests
are `#[ignore]`d; run them with `cargo test -- --ignored` when a network is
available. §3.1's selection rules are tested in `pkix-mta-sts`'s `discovery`
suite against the character-string forms a resolver produces, so the wire
rules are covered without DNS.

## License

Apache-2.0 OR MIT, at your option.

[RFC 8461]: https://www.rfc-editor.org/rfc/rfc8461
