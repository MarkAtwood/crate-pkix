# pkix-chain

High-level X.509 certificate chain verification.

Combines [`pkix-path`] (RFC 5280 §6 path validation) with
[`pkix-revocation`] (CRL/OCSP checking) into a single ergonomic API.
The starting point for most applications.

## Usage

### Simplest case — no revocation

```rust
use pkix_chain::{verify_chain_default, NoRevocation, TrustAnchor, ValidationPolicy};
use der::Decode as _;
use x509_cert::Certificate;

let chain = vec![
    Certificate::from_der(leaf_der)?,
    Certificate::from_der(intermediate_der)?,
];
let anchors = vec![TrustAnchor::from_der(root_der)?];

let policy = ValidationPolicy {
    current_time_unix: unix_now(),
    ..Default::default()
};

let result = verify_chain_default(&chain, &anchors, &policy, &NoRevocation)?;
```

### With CRL revocation

```rust
use pkix_chain::{verify_chain_default, CrlChecker};

let checker = CrlChecker::new(crl_der, unix_now(), DefaultVerifier);
let result = verify_chain_default(&chain, &anchors, &policy, &checker)?;
```

### With OCSP revocation

```rust
use pkix_chain::{verify_chain_default, OcspChecker};

let checker = OcspChecker::new(ocsp_response_der, unix_now(), DefaultVerifier);
let result = verify_chain_default(&chain, &anchors, &policy, &checker)?;
```

### With a custom signature backend

```rust
use pkix_chain::verify_chain;

// Any type implementing pkix_path::SignatureVerifier
let result = verify_chain(&chain, &anchors, &policy, &my_verifier, &NoRevocation)?;
```

## What this crate does

`verify_chain` runs two sequential checks:

1. **Path validation** — calls `pkix_path::validate_path`, which verifies
   signatures, validity periods, name linkage, BasicConstraints, pathLen,
   KeyUsage, and critical extensions per RFC 5280 §6.1.

2. **Revocation checking** — calls `RevocationChecker::check_revocation` for
   each certificate in the validated chain (leaf through issuer, excluding
   the trust anchor itself).

If either step fails, an `Error` is returned wrapping the underlying error.

## Re-exports

For convenience this crate re-exports the full public API of both component
crates. You do not need to add `pkix-path` or `pkix-revocation` directly to
your `Cargo.toml`:

```rust
use pkix_chain::{
    // from pkix-path:
    DefaultVerifier, SignatureVerifier, TrustAnchor, ValidatedPath, ValidationPolicy,
    // from pkix-revocation:
    NoRevocation, RevocationChecker,
    CrlChecker,   // requires feature = "crl"
    OcspChecker,  // requires feature = "ocsp"
};
```

## Features

| Feature | Enables |
|---------|---------|
| `crl` | `CrlChecker` (offline CRL validation) |
| `ocsp` | `OcspChecker` (offline OCSP validation) |
| `rsa` | RSA-PKCS1v15 backend in `DefaultVerifier` (default on) |
| `p256` | ECDSA P-256 backend in `DefaultVerifier` (default on) |

## `std` only

This crate requires `std`. For `no_std` environments, use `pkix-path` and
`pkix-revocation` directly.

## Standards

- [RFC 5280] — Internet X.509 PKI Certificate and CRL Profile
- [RFC 6960] — Online Certificate Status Protocol (OCSP)

## License

Apache-2.0 OR MIT
