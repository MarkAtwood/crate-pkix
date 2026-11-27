# pkix-ac

RFC 5755 X.509 attribute certificate validation.

An attribute certificate binds attributes — a role, a group, a clearance —
to a holder, and carries no public key of its own. It is issued by an
Attribute Authority (AA) whose own certificate is an ordinary public-key
certificate.

```rust
use pkix_ac::AttributeCertificate;

let ac = AttributeCertificate::from_der(ac_der)?;
ac.check_profile()?;

// `aa_cert` is the Attribute Authority's certificate, which the caller
// must already have validated — see below.
ac.verify(&aa_cert, now_unix, &pkix_path::DefaultVerifier)?;

for attr in ac.attributes() {
    let _oid = attr.r#type;
}
# Ok::<(), pkix_ac::Error>(())
```

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
validation yourself. It runs the whole of RFC 5755 §5 — both certification
paths, the §4.5 profile on the authority's own certificate, the AC
signature, validity, targeting, the §4.2/§4.3 profile, and the holder
binding — and is the only entry point that does.

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
