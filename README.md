# PKIX — X.509 Certificate Path Validation

Pure Rust, `no_std`-capable implementation of RFC 5280 X.509 certificate path
validation with pluggable cryptography and revocation checking.

## Why this exists

The Rust ecosystem has good X.509 *parsing* (`x509-cert`, `der`) and good
*TLS-specific* certificate validation (`rustls-webpki`), but no general-purpose
RFC 5280 path validator that is:

- **`no_std`** — usable in firmware, TPMs, HSMs, and embedded attestation
- **Crypto-agnostic** — swappable backends (RustCrypto, wolfCrypt/FIPS, hardware)
- **Not Web-PKI-opinionated** — works for code signing, S/MIME, device attestation, not just TLS
- **Dependency-light** — built entirely on the RustCrypto `formats` crates

`rustls-webpki` is excellent for its use case but hard-couples to `ring`, enforces
CA/Browser Forum TLS rules, and is not `no_std`. This project fills the gap.

## Crate map

| Crate | What it does | `no_std` | Status |
|-------|-------------|----------|--------|
| [`pkix-path`] | RFC 5280 §6 path validation, pluggable crypto | ✓ | v0.1 |
| [`pkix-revocation`] | CRL and OCSP revocation checking (offline) | core only | v0.1 |
| [`pkix-chain`] | Umbrella: combines path + revocation | — | v0.1 |
| [`pkix-chain-simple`] | Opinionated single-call validator | — | v0.1 |
| [`pkix-path-builder`] | RFC 4158 path building from unordered certs | ✓ | v0.1 |
| [`pkix-revocation-http`] | Online CRL/OCSP fetching from CDP/AIA | — | planned |
| [`pkix-profiles`] | CA/B Forum policy pre-configurations | — | planned |
| [`pkix-ct`] | Certificate Transparency SCT verification | — | planned |
| [`pkix-composite`] | Composite classical+PQC signature verifier | ✓ | planned |
| [`pkix-ac`] | RFC 5755 attribute certificate validation | ✓ | planned |

## Quick start

Add to `Cargo.toml`:

```toml
[dependencies]
pkix-chain = "0.1"
```

Verify a certificate chain:

```rust
use pkix_chain::{verify_chain_default, NoRevocation, TrustAnchor, ValidationPolicy};
use der::Decode as _;
use x509_cert::Certificate;

// Parse your certificates (leaf first)
let chain: Vec<Certificate> = vec![
    Certificate::from_der(leaf_der)?,
    Certificate::from_der(intermediate_der)?,
];

// Configure trust anchors
let anchors = vec![TrustAnchor::from_der(root_der)?];

let policy = ValidationPolicy {
    current_time_unix: 1_780_272_000, // seconds since Unix epoch
    ..Default::default()
};

// Validate — no revocation checking
let validated = verify_chain_default(&chain, &anchors, &policy, &NoRevocation)?;
println!("chain depth: {}", validated.chain.len());
```

With CRL revocation checking:

```rust
use pkix_chain::{verify_chain_default, CrlChecker};

let crl_checker = CrlChecker::new(crl_der_bytes, now_unix, DefaultVerifier);
let validated = verify_chain_default(&chain, &anchors, &policy, &crl_checker)?;
```

With a custom (e.g. FIPS-validated) signature backend:

```rust
use pkix_chain::verify_chain;

// Implement pkix_path::SignatureVerifier for your backend
let validated = verify_chain(&chain, &anchors, &policy, &my_fips_verifier, &NoRevocation)?;
```

## Architecture

```
pkix-chain-simple          (opinionated single-call API)
pkix-chain                 (umbrella: combines path + revocation)
       │                        │
       ▼                        ▼
  pkix-path              pkix-revocation
  (RFC 5280 §6           (CRL, OCSP —
   path validation,       offline)
   no_std)
       │
       ▼
  SignatureVerifier trait
  (pluggable crypto seam)
       │
  ┌────┴────────────────────────┐
  │                             │
  DefaultVerifier          (your backend)
  (RustCrypto: RSA,         wolfCrypt, FIPS,
   ECDSA P-256)             hardware HSM
```

The `SignatureVerifier` trait is the crypto seam. Swap it to change the
entire cryptographic foundation without touching validation logic.

## v0.1 scope

Implemented:
- Signature chain verification (RSA-PKCS1v15-SHA-256, ECDSA-P-256-SHA-256)
- Validity period checks
- Issuer/subject name linkage
- `BasicConstraints` cA=true on intermediates
- `pathLenConstraint` enforcement
- `KeyUsage` keyCertSign enforcement
- Unknown critical extension rejection
- CRL revocation checking (offline, issuer-signed)
- OCSP revocation checking (offline, direct responder)

Not yet implemented (v0.2+):
- RFC 4518 DN string normalization — PKIX-pyc

In progress for v0.1:
- Policy validation (RFC 5280 §6.1 state machine) — PKIX-mi3
- Path building from unordered certs (RFC 4158) — PKIX-y2j
- Delta CRLs and CRL Distribution Points — PKIX-58m

## Standards

| Document | Title |
|----------|-------|
| [RFC 5280] | Internet X.509 PKI Certificate and CRL Profile |
| [RFC 6960] | X.509 Internet PKI Online Certificate Status Protocol (OCSP) |
| [RFC 4158] | Internet X.509 PKI: Certification Path Building |
| [RFC 4518] | LDAP: Internationalized String Preparation (DN normalization) |
| [RFC 5755] | An Internet Attribute Certificate Profile for Authorization |
| [FIPS 186-5] | Digital Signature Standard (ECDSA, EdDSA) |
| [FIPS 204] | Module-Lattice-Based Digital Signature Standard (ML-DSA) |
| [CA/B Forum BR] | Baseline Requirements for TLS Server Certificates |
| [draft-ietf-lamps-dilithium-certificates] | X.509 Certificate Profile for ML-DSA |

Local copies of all referenced specifications are in [`specs/`](specs/).

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
