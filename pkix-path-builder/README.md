# pkix-path-builder

RFC 4158 certification path building for `pkix-path`.

Turns an unordered pool of candidate certificates into an ordered chain ready
for `pkix_path::validate_path`. Use this when you receive a PKCS#7/CMS
envelope, a TLS handshake, or any bag of certificates whose chain order is not
known in advance.

## When to use this crate

`pkix-path::validate_path` expects a caller-ordered `&[Certificate]` (leaf
first). This crate handles the step before that: given a target leaf and a pool
of candidate intermediates, find and return a valid ordering from the target to
one of the provided trust anchors.

Cross-certificates and bridge CA topologies are handled here, not in
`pkix-path`.

## Usage

```rust
use pkix_path_builder::{build_path, CertPool};
use pkix_path::{validate_path, DefaultVerifier, TrustAnchor, ValidationPolicy};

// Collect candidate intermediates into a pool
let mut pool = CertPool::new();
pool.add(Certificate::from_der(intermediate_a)?);
pool.add(Certificate::from_der(intermediate_b)?);
pool.add(Certificate::from_der(cross_cert)?);

// Build the path — returns ordered [target, intermediate..., anchor-issued]
// ready for validate_path
let chain = build_path(&target_cert, &pool, &trust_anchors)?;

// Validate as normal
let validated = validate_path(&chain, &trust_anchors, &policy, &DefaultVerifier)?;
```

## How it works

`build_path` performs a single depth-first pass of up to 10 intermediates,
per RFC 4158 §2.5 — there is no iterative deepening, so shortest-first is
not guaranteed. At each step, candidates are selected by matching the current
certificate's `issuer` field against candidate `subject` fields, and ranked by
AKI/SKI match.
`build_first_valid_path` additionally checks each link's signature
before descending (so same-name decoys in an untrusted bag are pruned
immediately) and tries anchor-issued candidates first.

Cycle detection compares each candidate's OID and public key bytes against
the certificates already in the current path, correctly handling encoding
variants (e.g. RSA with and without explicit `NULL` parameters).

Each search pass starts with a fresh budget of 10,000 units (one per
frame entered and per candidate examined) to bound worst-case work
against adversarial or oversized certificate pools. Byte-identical pool
certificates are considered once.

`build_path` and `build_path_candidates` do **not** verify signatures;
that is the responsibility of the caller via `validate_path`
(`build_first_valid_path` does both).

## Errors

| Error | Meaning |
|-------|---------|
| `NoPathFound` | No topologically valid path through `pool` reaches any trust anchor |
| `DepthExceeded` | A path exists but requires more than 10 intermediates |
| `BudgetExceeded` | The search budget was exhausted; pool may be adversarially large |

## Standards

- [RFC 4158] — Internet X.509 PKI: Certification Path Building
- [RFC 5280] §3.2 — Cross-certificates and bridge CA topology
- [RFC 5280] §6.1 — Path validation (consumes the output of this crate)

## License

Apache-2.0 OR MIT
