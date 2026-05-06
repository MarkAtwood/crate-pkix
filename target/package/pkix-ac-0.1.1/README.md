# pkix-ac

RFC 5755 X.509 attribute certificate validation.

**Status: planned (not yet implemented).**

## What this will do

Validate X.509 v2 attribute certificates (ACs) per RFC 5755. Attribute
certificates bind a set of attributes — roles, clearances, group
memberships, capabilities — to a subject without containing a public key.
They are issued by an Attribute Authority (AA) and validated against a
separate chain of AA certificates, distinct from the public key
infrastructure used by `pkix-path`.

## Attribute certificates vs public key certificates

| | Public Key Cert | Attribute Cert |
|---|---|---|
| Contains public key | yes | no |
| Subject identified by | distinguished name | holder reference (PKC issuer+serial) |
| Issued by | Certification Authority (CA) | Attribute Authority (AA) |
| Validated by | `pkix-path` | `pkix-ac` (uses `pkix-path` for AA chain) |
| RFC | 5280 | 5755 |
| Use case | identity, authentication | authorisation, role, clearance |

## Planned API

```rust
use pkix_ac::{validate_attribute_cert, AttributeCertificate};
use pkix_path::{DefaultVerifier, TrustAnchor, ValidationPolicy};

let ac = AttributeCertificate { der: ac_der_bytes };

// AA trust anchors are separate from PKC trust anchors
let aa_anchors = vec![TrustAnchor::from_der(aa_root_der)?];

let policy = ValidationPolicy {
    current_time_unix: unix_now(),
    ..Default::default()
};

validate_attribute_cert(&ac, &aa_anchors, unix_now(), &DefaultVerifier)?;

// Then inspect the attributes from the parsed AC
```

## How it will work

1. Parse the DER-encoded `AttributeCertificate` structure (RFC 5755 §4.1).
2. Check the validity period (`notBefore ≤ now ≤ notAfter`).
3. Identify the Attribute Authority via the `issuer` field.
4. Use `pkix-path` to validate the AA's public key certificate chain
   against the provided AA trust anchors.
5. Verify the AC signature against the AA's validated SPKI.
6. Return the parsed attributes for the caller to inspect.

## Standards

- [RFC 5755] — An Internet Attribute Certificate Profile for Authorization
- [RFC 5280] §6 — used internally to validate the AA's PKC chain

## License

Apache-2.0 OR MIT
