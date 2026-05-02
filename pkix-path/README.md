# pkix-path

RFC 5280 X.509 certification path validation — pure Rust, `no_std`.

The core validation engine. Implements the RFC 5280 §6.1 path validation
algorithm with a pluggable cryptography interface so you can swap in any
signature backend without changing validation logic.

## When to use this crate directly

Use `pkix-path` directly when you need:
- `no_std` (firmware, embedded, Caliptra/DPE)
- A custom signature backend (FIPS, hardware HSM, wolfCrypt)
- Fine-grained control over validation without revocation

For most applications, use [`pkix-chain`] instead, which wraps this crate
together with revocation checking in a single ergonomic API.

## Usage

```rust
use pkix_path::{validate_path, DefaultVerifier, TrustAnchor, ValidationPolicy};
use der::Decode as _;
use x509_cert::Certificate;

let chain = vec![
    Certificate::from_der(leaf_der)?,
    Certificate::from_der(intermediate_der)?,
];

let anchors = vec![
    TrustAnchor {
        subject: root_cert.tbs_certificate.subject.clone(),
        subject_public_key_info: root_cert.tbs_certificate.subject_public_key_info.clone(),
    }
];

let policy = ValidationPolicy {
    current_time_unix: 1_780_272_000,
    ..Default::default()
};

let validated = validate_path(&chain, &anchors, &policy, &DefaultVerifier)?;
println!("trust anchor subject: {:?}", validated.trust_anchor.subject);
```

## Pluggable crypto

The [`SignatureVerifier`] trait is the seam between path validation logic and
cryptographic operations. Implement it to use any backend:

```rust
use pkix_path::SignatureVerifier;
use spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};

struct MyFipsVerifier;

impl SignatureVerifier for MyFipsVerifier {
    fn verify_signature(
        &self,
        algorithm: AlgorithmIdentifierRef<'_>,
        issuer_spki: SubjectPublicKeyInfoRef<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), signature::Error> {
        // dispatch to your FIPS-validated backend
        todo!()
    }
}
```

The [`DefaultVerifier`] provides RSA-PKCS1v15-SHA-256 and ECDSA-P-256-SHA-256
via RustCrypto. Enable the `rsa` and `p256` features (both on by default).

## `no_std`

`pkix-path` is `no_std` by default. The `std` feature enables
`std::error::Error` impls on error types. Algorithm backends (`rsa`, `p256`)
are `no_std`-compatible via `default-features = false`.

## What is validated

Per RFC 5280 §6.1, for each certificate in the chain:

- **Signatures** — each cert's signature is verified against the issuer's SPKI
- **Validity period** — `notBefore ≤ now ≤ notAfter`
- **Name linkage** — `cert.issuer == issuer.subject` for each adjacent pair
- **Trust anchor** — final issuer matches a provided trust anchor
- **BasicConstraints** — intermediates must have `cA = TRUE`
- **pathLenConstraint** — enforced if present on intermediate CA certs
- **KeyUsage** — `keyCertSign` bit enforced on CAs (configurable via policy)
- **Critical extensions** — any unrecognised critical extension causes failure

## What is not validated (v0.1)

- Name constraints (RFC 5280 §4.2.1.10)
- Policy constraints and policy validation (§4.2.1.9, §6.1.5)
- CRL/OCSP revocation — use [`pkix-revocation`]
- Path building — chain must be caller-ordered, leaf first
- RFC 4518 DN normalization — name comparison is byte-exact

## Standards

- [RFC 5280] §6 — Path Validation Algorithm
- [RFC 5280] §4.2 — Certificate Extensions
- [FIPS 186-5] — Digital Signature Standard (ECDSA)

## License

Apache-2.0 OR MIT
