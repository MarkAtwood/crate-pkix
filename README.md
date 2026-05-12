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

Per-crate versions live on crates.io and in each crate's `Cargo.toml`.

### Core workspace crates

| Crate | What it does | `no_std` | Status |
|-------|-------------|----------|--------|
| [`pkix-path`] | RFC 5280 §6 path validation, pluggable crypto | ✓ | released |
| [`pkix-revocation`] | CRL and OCSP revocation checking (offline) | core only[^revocation-no-std] | released |
| [`pkix-chain`] | Umbrella: combines path + revocation | — | released |
| [`pkix-chain-simple`] | Opinionated validator with extension whitelist | — | released |
| [`pkix-path-builder`] | RFC 4158 path building from unordered certs | ✓ | released |
| [`pkix-profiles`] | `Profile` trait + RFC-baseline profile pre-configurations | — | released |
| [`pkix-lint`] | Advisory lint engine + RFC-conformance lint bundle | — | released |
| [`pkix-revocation-http`] | Online CRL/OCSP fetching from CDP/AIA | — | planned |
| [`pkix-ct`] | Certificate Transparency SCT verification | — | planned |
| [`pkix-composite`] | Composite classical+PQC signature verifier | ✓ | planned |
| [`pkix-ac`] | RFC 5755 attribute certificate validation | ✓ | planned |

### Industry-forum reference crates (not authoritative)

These crates encode specific industry-forum requirements (e.g., CA/B Forum
Baseline Requirements) on top of the core framework. They are explicit
reference implementations — snapshot-style, not maintained as canonical
encodings — and ship with a "fork and adapt to your deployment's current
interpretation" caveat in their crate-level rustdoc. See the
[framework / policy split](#framework--policy-split) section below for the
rationale.

| Crate | What it does | `no_std` | Status |
|-------|-------------|----------|--------|
| [`pkix-profiles-cabf`] | CA/B Forum TLS BR / S/MIME BR / Code Signing BR profile pre-configurations (reference) | — | released |
| [`pkix-lint-cabf`] | CA/B Forum TLS BR lint bundle (`cabf_tls_br`) (reference) | — | released |

[^revocation-no-std]: `pkix-revocation`'s core (`NoRevocation`, the
    `RevocationChecker` trait, `Error` enum) is `no_std`. The `crl` and
    `ocsp` features both require `std` (CRL/OCSP parsing pulls in
    `x509-cert`/`x509-ocsp` types that need allocation).

## Quick start

Add to `Cargo.toml`:

```toml
[dependencies]
pkix-chain = "0.4"
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
let root = Certificate::from_der(root_der)?;
let anchors = vec![TrustAnchor::try_from(root)?];

let policy = ValidationPolicy::new(1_780_272_000); // seconds since Unix epoch

// Validate — no revocation checking
let validated = verify_chain_default(&chain, &anchors, &policy, &NoRevocation)?;
println!("chain depth: {}", validated.depth);
```

With CRL revocation checking (requires the `crl` Cargo feature, e.g.
`pkix-chain = { version = "0.4", features = ["crl"] }`):

```rust
use pkix_chain::{verify_chain_default, CrlChecker, DefaultVerifier};

let crl_checker = CrlChecker::new(crl_der_bytes, now_unix, DefaultVerifier)?;
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
pkix-chain-simple          (strict single-call API, extension whitelist)
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

Path building (turning an unordered bag of certificates into an ordered chain)
is handled by `pkix-path-builder`. Profile-specific policy pre-configuration
lives in `pkix-profiles`. Advisory linting lives in `pkix-lint`.

## Framework / policy split

The workspace ships standards-based **mechanisms** (the `Profile` trait,
`ValidationPolicy`, the `Lint` trait, `LintRunner`, OSCAL Catalog / Profile
machinery, …) and **RFC-baseline implementations** in the core crates. It
does **not** ship canonical encodings of any single organization's policy —
CA/B Forum, DoD, Mozilla / Apple / Microsoft root programs, individual CA
CPSs — in the core crates.

Industry-forum content (CA/B Forum TLS BR, S/MIME BR, Code Signing BR) lives
in sibling **`-cabf` reference crates** carrying a "reference / not
authoritative" header in their rustdoc. They are a starting point that you
are expected to fork and adapt to your deployment's current interpretation
of the BR text.

| Concern | Core crate | Reference crate |
|---------|-----------|-----------------|
| `Profile` trait + RFC-baseline (`BasicTlsProfile`, `BasicSmimeProfile`) | [`pkix-profiles`] | — |
| CA/B Forum profiles (`WebPkiProfile`, `SmimeProfile`, `CodeSigningProfile`) | — | [`pkix-profiles-cabf`] |
| `Lint` trait, `LintRunner`, `EvaluationReport`, RFC-conformance lints | [`pkix-lint`] | — |
| CA/B Forum TLS BR lints (`cabf_tls_br`) | — | [`pkix-lint-cabf`] |

Encoded as workspace stance in [`AGENTS.md`] non-negotiable #6 (PKIX-amgn).

[`AGENTS.md`]: ./AGENTS.md

## What is validated

`pkix-path::validate_path` implements RFC 5280 §6.1:

- **Signatures** — each certificate's signature is verified against the issuer's SPKI
- **Validity period** — `notBefore ≤ now ≤ notAfter` for every certificate
- **Name linkage** — `cert.issuer == issuer.subject` for each adjacent pair
- **Trust anchor** — final issuer matches a provided trust anchor
- **BasicConstraints** — intermediates must have `cA = TRUE`
- **pathLenConstraint** — enforced if present on intermediate CA certificates
- **KeyUsage** — `keyCertSign` bit enforced on CAs (configurable via policy)
- **Critical extensions** — any unrecognised critical extension causes failure
- **Certificate policies** — RFC 5280 §6.1 policy state machine
- **Policy mappings** — RFC 5280 §6.1.3–6.1.5 mapping and constraint enforcement
- **Name constraints** — RFC 5280 §4.2.1.10 (DNS, RFC 822, URI, DirectoryName, IP address)
- **Duplicate certificate detection** — issuer+serial uniqueness in the chain

`pkix-revocation` adds:
- **CRL checking** — RFC 5280 §5 offline CRL with delta CRL support
- **OCSP checking** — RFC 6960 offline OCSP response with CertID hash verification

## Not yet implemented

- RFC 4518 full Unicode NFKC DN normalization (BMPString/TeletexString transcoding)
- CRL Distribution Points — caller supplies the CRL DER directly
- Online CRL/OCSP fetching (`pkix-revocation-http`, planned)
- Delegated OCSP responders

## Interoperability

`pkix-path`'s verdict behaviour is differential-tested against
[OpenSSL](https://www.openssl.org/) and
[pyca/cryptography](https://cryptography.io/) on the
[NIST PKITS](https://csrc.nist.gov/projects/pki-testing) corpus via
the [`pkix-difftest`](pkix-difftest/) harness. The PKITS baseline
is committed at
[`pkix-difftest/baseline-pkits.json`](pkix-difftest/baseline-pkits.json)
(machine-readable source of truth) and
[`pkix-difftest/baseline-pkits-analysis.md`](pkix-difftest/baseline-pkits-analysis.md)
(human-readable bucket analysis).

Concrete real-world divergences from the major implementations,
along with our reasoning for each, are documented in
[**INTEROP.md**](INTEROP.md). If `pkix-path`'s verdict on your chain
disagrees with another validator, that document is the first place to
look.

## Standards

| Document | Title |
|----------|-------|
| [RFC 5280] | Internet X.509 PKI Certificate and CRL Profile |
| [RFC 6960] | X.509 Internet PKI Online Certificate Status Protocol (OCSP) |
| [RFC 4158] | Internet X.509 PKI: Certification Path Building |
| [RFC 4518] | LDAP: Internationalized String Preparation (DN normalization) |
| [RFC 5755] | An Internet Attribute Certificate Profile for Authorization |
| [RFC 6962] | Certificate Transparency |
| [RFC 9162] | Certificate Transparency Version 2.0 |
| [FIPS 186-5] | Digital Signature Standard (ECDSA) |
| [FIPS 204] | Module-Lattice-Based Digital Signature Standard (ML-DSA) |
| [CA/B Forum TLS BR] | Baseline Requirements for TLS Server Certificates |
| [CA/B Forum S/MIME BR] | Baseline Requirements for S/MIME Certificates |
| [CA/B Forum CS BR] | Baseline Requirements for Code Signing |
| [draft-ietf-lamps-pq-composite-sigs] | Composite Post-Quantum Signatures |

Local copies of all referenced specifications are in [`specs/`](specs/).

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
