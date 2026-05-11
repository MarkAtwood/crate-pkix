# pkix-truststore

PEM/DER trust anchor loading for [`pkix-path`](https://docs.rs/pkix-path).

## Project stance: no baked-in trust data, no baked-in trust source

`pkix-truststore` ships **no compiled-in CA certificates** and **no built-in
knowledge of any platform trust store**. Trust data is deployment
configuration, not library content. The set of trust anchors a validator uses
is the most security-critical decision a deployment makes; bundling a snapshot
of the Mozilla CA list (or any other vendor's list) into a library version
pins that decision to the library's release cadence. That is the wrong
coupling.

This crate provides only the bytes-in, anchors-out plumbing.

## What this does

- Parse one or more PEM-encoded certificates into `Vec<TrustAnchor>`.
- Parse a single DER-encoded certificate into a `TrustAnchor`.
- Parse an iterator of DER blobs into `Vec<TrustAnchor>` — the canonical
  adapter entry point (see below).
- Convenience file-reading wrappers for the above.

It tolerates the real-world quirks of distro CA bundles:

- Multiple concatenated `-----BEGIN CERTIFICATE-----` blocks.
- OpenSSL `Subject:` / `Issuer:` / `Serial Number:` header lines between
  certs (Debian `ca-certificates.crt` format).
- Leading UTF-8 BOM.
- Mixed CRLF / LF line endings.
- Trailing whitespace after the last cert.

It rejects, deliberately:

- Unknown PEM labels (`PRIVATE KEY`, `X509 CRL`, …). PEM decoding is strict
  per RFC 7468.
- Trailing non-whitespace content after the last `-----END CERTIFICATE-----`.
  This matches the underlying `x509-cert::load_pem_chain` behaviour. Real
  distro bundles do not include such trailing content; if your producer does,
  strip it before calling.
- Empty input / input with zero `-----BEGIN CERTIFICATE-----` boundaries —
  `Error::NoCertificates`. An empty trust store is almost always a
  configuration mistake.

## API

```rust
use pkix_truststore::{from_pem, from_pem_file, from_der, from_der_iter, TrustAnchor};

// From bytes already in memory.
let anchors: Vec<TrustAnchor> = from_pem(pem_bytes)?;
let one: TrustAnchor          = from_der(der_bytes)?;

// From files.
let anchors = from_pem_file("/etc/ssl/certs/ca-certificates.crt")?;
let one     = from_der_file("/path/to/cert.der")?;

// From an iterator of DER blobs — the canonical adapter entry point.
let anchors = from_der_iter([der_blob_1.as_slice(), der_blob_2.as_slice()])?;
# Ok::<(), pkix_truststore::Error>(())
```

`TrustAnchor` is re-exported from `pkix-path` for ergonomics: consumers do not
need to import `pkix-path` separately just to name the type.

## Source coverage

Tier 1 (this crate) covers raw PEM/DER from memory or files.

Other sources are provided by opt-in adapter crates that produce DER bytes
and feed them to `from_der_iter`. The unifying currency is DER bytes; the
adapter handles whatever source-specific API (OS keychain, HSM, cloud KMS) is
needed to obtain them.

**Placeholder adapter beads filed:**

- `pkix-truststore-system` (PKIX-8h87) — OS-native trust stores: macOS
  Security framework, Windows CryptoAPI, iOS Keychain, Android KeyStore,
  Linux/BSD distro CA bundle paths. The `rustls-native-certs` analog.
- `pkix-truststore-pkcs11` (PKIX-p8vz) — PKCS#11 tokens: HSMs (YubiHSM,
  Thales, AWS CloudHSM, Azure Dedicated HSM, SafeNet), YubiKey PIV, smart
  cards, TPM 2.0 via `tpm2-pkcs11`, SoftHSM for testing.

**Adapter crates plausible — file when there is concrete demand:**
cloud KMS (AWS / Azure / GCP), Vault PKI, NSS, EST, SCEP, CMP.

## Explicit non-goals

- **Compiled-in Mozilla CA bundle.** The `webpki-roots` model is rejected
  for this project. If a Mozilla snapshot is needed, it lives in a separate
  crate or as build-time data the consumer supplies.
- **Per-anchor trust policy.** NSS-style trust flags ("trusted for serverAuth
  only," "distrust after date X," constraint patterns) are a substantial
  data-model extension that affects `pkix-path::TrustAnchor` itself. Out of
  scope; revisit when a concrete consumer asks for it.

## License

Licensed under either of

- Apache License, Version 2.0
- MIT license

at your option.
