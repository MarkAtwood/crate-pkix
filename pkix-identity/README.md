# pkix-identity

Cert-side identity matching: does this leaf certificate authorize this name?

- **DNS hostname** binding per RFC 6125 §6.4 (TLS server identity).
- **IP literal** binding (IPv4/IPv6 byte-equal SAN entry).
- **Mailbox** binding per RFC 5280 §4.2.1.6 and RFC 8398
  (S/MIME signer/recipient identity).

Pure: no chain context, no trust anchors, no revocation, no I/O. `no_std`.

**Status: scaffold (PKIX-fmtv.21). 0.1.0 ships the public API surface;
all entry points return `IdentityError::NotYetImplemented`. Bodies fill
in via PKIX-fmtv.11 (`verify_dns_name`) and PKIX-fmtv.12 (`verify_mailbox`).**

## Why a separate crate

Identity matching is reused by several callers and split out so each
gets a focused dep, mirroring how `rustls-pki-types::ServerName` and
`webpki::SubjectNameRef` are split from chain validation:

- [`pkix-chain`] composes path validation + identity matching in its
  `verify_tls_server` / `verify_smime_signer` wrappers.
- Future trust-store adapters ([`pkix-truststore-system`],
  [`pkix-truststore-pkcs11`]) use it to answer "what identities does
  this anchored cert claim?".
- ACME / TLS-ALPN-01 implementations use it for leaf-cert identity
  checks without paying for a full chain validator.

The `Profile` trait was not a fit: identity matching is a stateless
data transform `(cert, identity-string) -> Result<(), IdentityError>`,
not a policy hook over a chain. Inlining in `pkix-chain` would force
duplication elsewhere.

## Planned API

```rust
use pkix_identity::{ServerName, MailboxName, verify_dns_name, verify_mailbox};
use x509_cert::Certificate;

let cert: Certificate = parse_leaf_der(der_bytes)?;

// TLS server identity
let name = ServerName::dns_name("example.com")?;
verify_dns_name(&cert, &name)?;

// IP literal
let ip = ServerName::ip_address("203.0.113.1")?;
verify_dns_name(&cert, &ip)?;

// S/MIME signer
let mailbox = MailboxName::parse("alice@example.com")?;
verify_mailbox(&cert, &mailbox)?;
```

## Scope discipline

This crate has high risk of "what doesn't go in here?" scope creep.
The line is drawn deliberately.

### In scope

- `ServerName` parsing — DNS hostname (LDH + IDN A-label/U-label) and
  IP literal (IPv4 / IPv6).
- `MailboxName` parsing — RFC 5322 ASCII mailbox and RFC 8398
  SmtpUTF8Mailbox (otherName-wrapped UTF-8).
- `verify_dns_name` — RFC 6125 §6.4 SAN-only matching (exact,
  wildcard with single-leftmost-label rule, IDN normalization, IP byte
  compare).
- `verify_mailbox` — RFC 5280 §4.2.1.6 rfc822Name and RFC 8398
  SmtpUTF8Mailbox SAN matching.
- IDN A-label / U-label normalization via the `idna` crate (added in
  PKIX-fmtv.11).
- Internal helpers: wildcard matching, case folding, IP byte compare.

### Out of scope

- **Name constraints matching.** Different semantics — constraint
  subset check, not target match. Lives in `pkix-path` as
  `dns_name_matches_constraint` and stays there.
- **DN canonicalization (RFC 4518 string prep).** Already in
  `pkix-path`; not duplicated here.
- **CSR parsing.** Not a verifier concern.
- **Public Suffix List enforcement (eTLD blocking).** Deliberately not
  included. Callers who need it pull in their own PSL crate. `webpki`
  makes the same choice; this crate follows.
- **CN fallback.** Deprecated by RFC 6125 §6.4.4; `verify_dns_name`
  intentionally does not look at Subject DN CN.
- Anything that requires chain context, trust-anchor knowledge, or
  network I/O.

## Standards

- [RFC 6125] §6.4 — Server identity matching
- [RFC 5280] §4.2.1.6 — Subject Alternative Name extension
- [RFC 8398] — Internationalized Email Addresses in X.509 Certificates
- [RFC 5890]–[RFC 5894] — IDNA 2008

## License

Apache-2.0 OR MIT

[`pkix-chain`]: https://docs.rs/pkix-chain
[`pkix-truststore-system`]: https://docs.rs/pkix-truststore-system
[`pkix-truststore-pkcs11`]: https://docs.rs/pkix-truststore-pkcs11
[RFC 6125]: https://www.rfc-editor.org/rfc/rfc6125
[RFC 5280]: https://www.rfc-editor.org/rfc/rfc5280
[RFC 8398]: https://www.rfc-editor.org/rfc/rfc8398
[RFC 5890]: https://www.rfc-editor.org/rfc/rfc5890
[RFC 5894]: https://www.rfc-editor.org/rfc/rfc5894
