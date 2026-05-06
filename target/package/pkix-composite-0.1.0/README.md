# pkix-composite

Composite classical+PQC signature verifier for `pkix-path`.

**Status: planned (not yet implemented). OIDs are subject to change until
`draft-ietf-lamps-pq-composite-sigs` is published as an RFC.**

## What this will do

Implement [`pkix_path::SignatureVerifier`] for composite public keys and
signatures as defined in `draft-ietf-lamps-pq-composite-sigs`. A composite
certificate contains both a classical public key (e.g. ECDSA P-256) and a
post-quantum public key (e.g. ML-DSA-65) combined in a single SPKI. The
composite signature is only valid if **both** component signatures verify.

This provides a hybrid transition strategy during the move to post-quantum
cryptography: security holds as long as either algorithm remains unbroken.

## Planned API

```rust
use pkix_composite::CompositeVerifier;
use pkix_path::DefaultVerifier;
// For the PQ component: wolfcrypt_pkix::WolfCryptVerifier, or an ML-DSA-specific verifier

let verifier = CompositeVerifier::new(
    DefaultVerifier,    // classical: RSA / ECDSA
    my_pq_verifier,     // post-quantum: ML-DSA
);

pkix_chain::verify_chain(&chain, &anchors, &policy, &verifier, &NoRevocation)?;
```

## How it will work

The composite SPKI contains two component public keys encoded in a
`SEQUENCE OF SubjectPublicKeyInfo`. The composite signature contains two
component signatures in a corresponding `SEQUENCE OF BIT STRING`. On
verification:

1. Split the composite SPKI into classical and PQ component SPKIs.
2. Split the composite signature into classical and PQ component signatures.
3. Verify the classical component with `C::verify_signature(...)`.
4. Verify the PQ component with `P::verify_signature(...)`.
5. Return `Ok(())` only if both succeed.

## Standards

- `draft-ietf-lamps-pq-composite-sigs` (see `specs/draft-ietf-lamps-pq-composite-sigs-*.txt`)
- [FIPS 204] — Module-Lattice-Based Digital Signature Standard (ML-DSA)
- [FIPS 186-5] — Digital Signature Standard (ECDSA)

## License

Apache-2.0 OR MIT
