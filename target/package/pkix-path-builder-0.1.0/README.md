# pkix-path-builder

RFC 4158 certification path building for `pkix-path`.

**Status: planned (not yet implemented). See issue PKIX-y2j.**

## What this will do

`pkix-path` validates a caller-ordered `&[Certificate]` (leaf first). This
crate handles the step before that: given an unordered collection of
candidate certificates, find and return a valid ordered chain from a target
certificate to one of the provided trust anchors.

This enables:
- Processing certificate bags from PKCS#7/CMS envelopes
- Handling cross-certificates and bridge CA topologies
- Path discovery when the chain order is not known in advance

## Planned API

```rust
use pkix_path_builder::{build_path, CertPool};
use pkix_path::{validate_path, DefaultVerifier, TrustAnchor, ValidationPolicy};

// Collect candidate intermediates into a pool
let mut pool = CertPool::new();
pool.add(Certificate::from_der(intermediate_a)?);
pool.add(Certificate::from_der(intermediate_b)?);
pool.add(Certificate::from_der(cross_cert)?);

// Build the path — returns ordered [target, intermediates...] ready for validate_path
let chain = build_path(&target_cert, &pool, &trust_anchors)?;

// Validate as normal
let validated = validate_path(&chain, &trust_anchors, &policy, &DefaultVerifier)?;
```

## How it will work

The path builder implements a depth-first search over candidate issuers per
RFC 4158 §2. At each step, candidates are selected by matching the current
certificate's `issuer` field against candidate `subject` fields
(and optionally `AuthorityKeyIdentifier` against `SubjectKeyIdentifier`).
Cycles are detected and pruned. The first path that reaches a trust anchor
is returned.

## Standards

- [RFC 4158] — Internet X.509 PKI: Certification Path Building
- [RFC 5280] §3.2 — Cross-certificates and bridge CA topology
- [RFC 5280] §6.1 — Path validation (consumes the output of this crate)

## License

Apache-2.0 OR MIT
