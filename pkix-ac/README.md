# pkix-ac

RFC 5755 X.509 attribute certificate validation.

An attribute certificate binds attributes — a role, a group, a clearance —
to a holder, and carries no public key of its own. It is issued by an
Attribute Authority (AA) whose own certificate is an ordinary public-key
certificate.

```rust
use pkix_ac::{AcRevocation, AttributeCertificate};

let ac = AttributeCertificate::from_der(ac_der)?;

// Everything RFC 5755 §5 asks except the two certification paths.
// `aa_cert` is the Attribute Authority's and `holder_cert` the
// presenter's, and the caller must already have validated both — see
// below.
let targeting = ac.validate(
    &aa_cert,
    &holder_cert,
    now_unix,
    &my_names,
    &my_groups,
    AcRevocation::NeverRevokeOnly,
    &pkix_path::DefaultVerifier,
)?;

for attr in ac.attributes() {
    let _oid = attr.r#type;
}
# Ok::<(), pkix_ac::Error>(())
```

`check_profile` and `verify` are available separately, for a caller that
wants to report on a certificate rather than accept it. Do not reach for
that pair as the normal path: it runs neither §4.5 on the authority nor
the §4.3.2 targeting check, so it will accept an attribute certificate
scoped to somebody else's service.

## What this crate does not do, and why

It does not validate the Attribute Authority's certification path, and it
takes no trust anchors. The AA's chain is an ordinary public-key chain, so
validating it belongs to [`pkix-path`](../pkix-path) and composing the two
belongs to [`pkix-chain`](../pkix-chain).

`verify` therefore takes the AA's certificate and trusts the caller to have
validated it. **Passing an unvalidated certificate makes the answer
meaningless**: the signature will check out against whatever key is handed
over, an attacker's included.

Use `pkix_chain::verify_attribute_cert` unless you are doing the path
validation yourself. It validates both chains and then calls `validate`,
so it is the only entry point that covers the whole of §5 including rules
1 and 2.

## Attributes are parsed, not interpreted

§4.4 profiles six attribute types — `Role`, `Group`, `Clearance`,
`ChargingIdentity`, `AccessIdentity` and `ServiceAuthenticationInfo` — and
this crate hands all of them back as an OID and a set of unparsed values.
It does not decide what any of them mean.

That is deliberate. What a `Clearance` permits is security policy belonging
to the application: it turns on a policy identifier the application owns, a
lattice it defines, and often a classification scheme this library has no
business encoding. Match on the attribute type and decode the values your
deployment understands.

## Supported profile

The §4.2 and §4.3 rules are enforced, with each refusal naming the rule it
broke rather than reporting a generic parse failure — a certificate that
violates the profile should be readable and refusable with a reason. The
§4.1 syntax is accepted even where the profile forbids it, which is why
parsing and profile checking are separate calls.

Known limitations, each with its reasoning in the rustdoc:

- `objectDigestInfo` holders are not supported (§7.3 calls the feature
  optional, and §4.2.2 does not profile it).
- `targetCert` targets are refused rather than evaluated, per §4.3.2's
  "MUST NOT be used".
- Several names in a holder's `entityName` are refused, which is stricter
  than §4.2.2's SHOULD — see `ProfileViolation::HolderNameNotSingular`.

## License

Apache-2.0 OR MIT
