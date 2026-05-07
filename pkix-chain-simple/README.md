# pkix-chain-simple

Strict, opinionated X.509 certificate chain verification.

A thin validation layer that imposes a strict simplicity contract: short
chains, a fixed algorithm set, and an extension allowlist. Any deviation is
an immediate error. Suitable for closed PKI environments where you control
certificate issuance and want to reject anything unexpected.

## When to use this vs `pkix-chain`

| | `pkix-chain` | `pkix-chain-simple` |
|---|---|---|
| Signature algorithms | any (pluggable) | RSA-PKCS1v15-SHA-256, ECDSA-P-256-SHA-256 |
| Unknown non-critical extensions | allowed | rejected |
| Unknown critical extensions | rejected | rejected |
| Maximum chain depth | configurable | leaf + 2 intermediates |
| Name constraints, policy | ✓ | ✓ (via pkix-path) |
| Custom crypto backend | ✓ | no (DefaultVerifier only) |
| Intended for | general use | controlled/closed PKIs |

Use `pkix-chain-simple` when certificates are issued by your own CA and you
want strict, auditable enforcement that fails loudly on anything out of the
ordinary. Use `pkix-chain` for general-purpose validation where certificates
may carry extensions or algorithms you haven't explicitly listed.

## Usage

```rust
use pkix_chain_simple::{verify_simple, NoRevocation, TrustAnchor, ValidationPolicy};
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

verify_simple(&chain, &anchors, &policy, &NoRevocation)?;
```

## Simplicity contract

A chain passes if and only if all of the following hold:

**Chain shape**
- At least 1 certificate (the leaf)
- At most 3 certificates: leaf + up to 2 intermediates (trust anchor is separate)

**Signature algorithms**
- `sha256WithRSAEncryption` (OID 1.2.840.113549.1.1.11)
- `ecdsa-with-SHA256` (OID 1.2.840.10045.4.3.2)

**Extension allowlist — leaf** (`chain[0]`):
- `BasicConstraints` (2.5.29.19) — cA MUST be FALSE or absent
- `KeyUsage` (2.5.29.15)
- `ExtendedKeyUsage` (2.5.29.37)
- `SubjectAltName` (2.5.29.17)
- `SubjectKeyIdentifier` (2.5.29.14)
- `AuthorityKeyIdentifier` (2.5.29.35)
- `CRLDistributionPoints` (2.5.29.31) — presence allowed; content not inspected
- `AuthorityInfoAccess` (1.3.6.1.5.5.7.1.1) — presence allowed; content not inspected

**Extension allowlist — intermediates** (`chain[1..]`):
- `BasicConstraints` (2.5.29.19) — required, cA MUST be TRUE
- `KeyUsage` (2.5.29.15) — keyCertSign required
- `SubjectKeyIdentifier` (2.5.29.14)
- `AuthorityKeyIdentifier` (2.5.29.35)
- `CRLDistributionPoints` (2.5.29.31) — presence allowed; content not inspected
- `AuthorityInfoAccess` (1.3.6.1.5.5.7.1.1) — presence allowed; content not inspected

Any extension outside these lists causes:
- `Err(UnhandledCriticalExtension { oid, index })` if critical
- `Err(UnexpectedExtension { oid, index })` if non-critical

## Standards

- [RFC 5280] §4.2 — Standard certificate extensions
- [RFC 5280] §6.1 — Path validation algorithm

## License

Apache-2.0 OR MIT
