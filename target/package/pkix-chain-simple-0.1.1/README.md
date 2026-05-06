# pkix-chain-simple

Opinionated, strict X.509 certificate chain verification.

A thin wrapper around [`pkix-chain`] that adds an **extension whitelist**:
certificates must contain only the extensions this crate recognises, and
any unrecognised critical extension is an immediate failure. Suitable for
closed PKI environments where you control certificate issuance and want
to reject anything unexpected.

## When to use this vs `pkix-chain`

| | `pkix-chain` | `pkix-chain-simple` |
|---|---|---|
| Unknown non-critical extensions | allowed | rejected |
| Unknown critical extensions | rejected | rejected |
| Intended for | general use | controlled/closed PKIs |
| Extension whitelist | none | yes (see below) |

Use `pkix-chain-simple` when certificates are issued by your own CA and
you want strict enforcement. Use `pkix-chain` for general-purpose validation
where certificates may contain extensions you haven't seen before.

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

## Extension whitelist

`verify_simple` checks every extension in every certificate. The whitelist
differs between leaf and intermediate certificates:

**Intermediates** — must only contain:
- `BasicConstraints` (2.5.29.19) — required, cA=true
- `KeyUsage` (2.5.29.15) — keyCertSign required

**Leaves** — may also contain:
- `SubjectAltName` (2.5.29.17)
- `ExtendedKeyUsage` (2.5.29.37)
- `SubjectKeyIdentifier` (2.5.29.14)
- `AuthorityKeyIdentifier` (2.5.29.35)
- `CRLDistributionPoints` (2.5.29.31)
- `AuthorityInfoAccess` (1.3.6.1.5.5.7.1.1)

Any extension outside this list causes:
- `Err(UnhandledCriticalExtension)` if the extension is marked critical
- `Err(UnexpectedExtension)` if it is non-critical

## Standards

- [RFC 5280] §4.2 — Standard certificate extensions
- [RFC 5280] §6.1 — Path validation algorithm

## License

Apache-2.0 OR MIT
