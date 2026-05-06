# pkix-profiles

CA/Browser Forum and RFC certificate profile policies for `pkix-chain`.

**Status: planned (not yet implemented). Stub functions return
`ValidationPolicy::default()` pending v0.2 work.**

## What this will do

Provide pre-configured [`ValidationPolicy`] values for common certificate
use cases, encoding the additional constraints imposed by the CA/Browser
Forum Baseline Requirements on top of RFC 5280.

## Planned API

```rust
use pkix_profiles::{web_pki_policy, smime_policy, code_signing_policy};
use pkix_chain::{verify_chain_default, NoRevocation};

// TLS server certificate — enforces CA/B Forum TLS BR constraints
let policy = web_pki_policy(unix_now());
verify_chain_default(&chain, &anchors, &policy, &NoRevocation)?;

// S/MIME certificate
let policy = smime_policy(unix_now());

// Code signing certificate
let policy = code_signing_policy(unix_now());
```

## Planned constraints per profile

### `web_pki_policy` (CA/B Forum TLS Baseline Requirements)

- Maximum validity: 398 days
- Subject Alternative Name extension required
- SHA-1 signatures prohibited
- RSA keys ≥ 2048 bits
- `serverAuth` EKU required on leaf

### `smime_policy` (CA/B Forum S/MIME Baseline Requirements)

- `emailProtection` EKU required
- Subject email address must be in SAN `rfc822Name`
- S/MIME-specific key usage requirements

### `code_signing_policy` (CA/B Forum Code Signing Baseline Requirements)

- `codeSigning` EKU required
- Timestamp authority constraints

## Standards

- CA/Browser Forum Baseline Requirements for TLS Server Certificates (see `specs/cabforum-BR.md`)
- CA/Browser Forum S/MIME Baseline Requirements (see `specs/cabforum-smime-BR.md`)
- CA/Browser Forum Code Signing Baseline Requirements (see `specs/cabforum-code-signing-BR.md`)
- [RFC 5280] — Internet X.509 PKI Certificate and CRL Profile

## License

Apache-2.0 OR MIT
