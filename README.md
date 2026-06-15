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
   ECDSA P-256/P-384)       hardware HSM
```

The `SignatureVerifier` trait is the crypto seam. Swap it to change the
entire cryptographic foundation without touching validation logic.

Path building (turning an unordered bag of certificates into an ordered chain)
is handled by `pkix-path-builder`. Profile-specific policy pre-configuration
lives in `pkix-profiles`. Advisory linting lives in `pkix-lint`.

## Framework / policy split

The workspace ships standards-based **mechanisms** (the `Profile` trait,
`ValidationPolicy`, the `Lint` trait, `LintRunner`, …) and
**RFC-baseline implementations** in the core crates. It does **not**
ship canonical encodings of any single organization's policy —
CA/B Forum, DoD, Mozilla / Apple / Microsoft root programs, individual
CA CPSs — in the core crates. The serialization format for externalized
policy data is an open design question: `pkix-lint` ships an optional
OSCAL Catalog / Profile / Assessment Results bridge (`oscal` feature)
as one supported wire format, but it is not the workspace-mandated
encoding — callers may equally use the Rust APIs directly or wrap
them in any other format.

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

## Gaps

### Must harden before 1.0

**pkix-ct API shape.** The Certificate Transparency crate has correctness issues
that will fossilize if shipped: `verify_sct_for_cert` silently treats every SCT
as an `x509_entry` (wrong for precerts, surfaces as `InvalidSignature`);
`SignedCertificateTimestamp`, `CtLog`, `SignedTreeHead`, and `MerkleAuditPath`
all lack `#[non_exhaustive]` with every field public; `SctList`'s inner `Vec`
is public, letting callers bypass parser invariants; and
`verify_embedded_scts` coalesces all SCT failures into `count=0` with no
diagnostic. Tracked as epic **PKIX-d4h** (8 items).

**pkix-revocation-http cache and async.** The HTTP fetcher crate's cache uses
`SystemTime::now()` for freshness checks while the validator uses
caller-supplied `now_unix` — the two can disagree on whether a CRL/OCSP
response is fresh. The cache has no expired-entry eviction (unbounded memory
growth), the async path replicates the `RevocationChecker` default-skip
footgun, and `InMemoryCache` silently swallows lock poisoning. Tracked as
epic **PKIX-cr8** (10 items).

**pkix-identity edge cases.** `ServerName` and `MailboxName` have no
`into_owned()` escape hatch (the `'a` lifetime forces callers to hold the
borrow forever); an ASCII `MailboxName` incorrectly matches
`SmtpUTF8Mailbox` SAN entries contradicting the rustdoc; and `find_san`
returns the first SAN extension only, silently ignoring duplicates. Tracked
as epic **PKIX-bue** (3 items).

### Algorithm coverage

`DefaultVerifier` handles RSA-PKCS1v15-SHA-{256,384,512} and
ECDSA-P-{256,384}. Missing: **RSA-PSS** (increasingly common — Let's
Encrypt ISRG Root X2, government PKIs), **Ed25519**, **P-521**, and
**legacy SHA-1** (feature-gated, off by default, for validating old chains).
This is the single feature addition that most expands the set of real-world
certificate chains the library can validate. Tracked as epic **PKIX-qws**
(4 items).

### Not yet implemented

- RFC 4518 full Unicode NFKC DN normalization (BMPString/TeletexString transcoding)
- CRL Distribution Points fetching — caller supplies the CRL DER directly today
- DANE / TLSA (RFC 6698 + 7671) — `pkix-dane` and `pkix-dane-resolver` planned but not yet shipped
- Composite post-quantum + classical signature verification (`pkix-composite`, stub only)
- RFC 5755 attribute certificate validation (`pkix-ac`, stub only)
- OS-native trust store loading (`pkix-truststore-system`, stub only)
- PKCS#11 / HSM trust store adapter (`pkix-truststore-pkcs11`, stub only)

Stub crates are tracked as epic **PKIX-ljt** (4 items).

### Review debt

The workspace has been through 30+ review passes. The current review
(**PKIX-rm8**, June 2025) closed 59 findings and flagged 16 design
decisions requiring human judgment — mostly breaking API changes
(error type wrapping, `Cow<str>` → typed enums, inverted dependencies)
and security design choices (CertPool size cap, AIA byte cap, SSRF URI
filtering). These are deferred, not forgotten.

## Roadmap

Our goal is to become the standard PKIX library for Rust — the way
`rustls` is the standard TLS library but for the certificate validation
layer underneath. Here is what is shipping and what is next.

### Shipping today

- **RFC 5280 §6 path validation** with full policy tree, name constraints,
  and policy mappings (`pkix-path`, `no_std`)
- **CRL + OCSP revocation checking** with delta CRL and indirect CRL
  support (`pkix-revocation`, offline)
- **Path building** from unordered certificate bundles (`pkix-path-builder`)
- **High-level chain verification** with use-case wrappers for TLS server,
  TLS client, S/MIME, code signing, timestamping, and OCSP responder
  delegation (`pkix-chain`)
- **Pluggable crypto** — swap `DefaultVerifier` (RustCrypto) for wolfCrypt
  FIPS, a hardware HSM, or any custom backend
- **RFC 6125 hostname + RFC 8398 mailbox identity binding** (`pkix-identity`)
- **Trust anchor loading** from PEM/DER files and bytes (`pkix-truststore`)
- **Advisory lint engine** with RFC-conformance lints and CA/B Forum
  reference bundles (`pkix-lint`, `pkix-lint-cabf`)
- **Profile framework** with RFC-baseline and CA/B Forum reference
  profiles (`pkix-profiles`, `pkix-profiles-cabf`)
- **Certificate Transparency** SCT parsing and verification (`pkix-ct`)
- **AIA chain reassembly** — automatic intermediate fetching via
  `id-ad-caIssuers` (`pkix-aia`, `pkix-aia-http`)
- **External lint adapters** — zlint and pkilint integration via
  subprocess bridges (`pkix-zlint-bridge`, `pkix-policy-zlint`)
- **Differential testing** against OpenSSL and pyca/cryptography on the
  NIST PKITS corpus (`pkix-difftest`)

### Critical path to standard-library status

| Priority | Workstream | What it unblocks |
|----------|-----------|-----------------|
| **P1** | **Algorithm coverage** — RSA-PSS, Ed25519, P-521, legacy SHA-1 | Real-world chain validation (Let's Encrypt ISRG Root X2, government PKIs, modern CAs) |
| **P1** | **OS trust store integration** — `pkix-truststore-system` for Linux, macOS, Windows | The #1 adopter question: "how do I use the system trust store?" |
| **P1** | **Online revocation hardening** — cache eviction, stale-response fixes, async footguns | Production deployment with CRL/OCSP fetching that actually works |
| **P1** | **Rust TLS ecosystem integration** — `pkix-rustls-provider`, ring backend, reqwest/hyper examples | Lets the existing Rust TLS stack use PKIX as the certificate verifier |
| **P1** | **CT correctness** — precert entry type, re-encoder bit-exactness, diagnostic errors | CT-mandatory deployments (browsers, monitors) |
| **P2** | **Documentation** — getting started guide, cookbook, migration guides from rustls-webpki and openssl | 30-minutes-to-working adoption experience |

### Future work

| Crate | What | Status |
|-------|------|--------|
| `pkix-dane` | DANE / TLSA (RFC 6698 + 7671) | name reserved |
| `pkix-dane-resolver` | DNSSEC-validating TLSA resolver | name reserved |
| `pkix-composite` | Post-quantum + classical composite signatures | stub |
| `pkix-ac` | RFC 5755 attribute certificate validation | stub |
| `pkix-pkilint-bridge` | pkilint subprocess integration | name reserved |
| `pkix-policy-pkilint` | pkilint → pkix-lint adapter | name reserved |
| `pkix-truststore-pkcs11` | HSM / smart card trust store adapter | stub |

### Contributing

Contributions are welcome. The critical-path items above are tracked as
beads epic `PKIX-77k9` in the repository's issue tracker. The ecosystem
integration work (`pkix-rustls-provider`) may involve upstream PRs to
other projects — we are happy to collaborate.

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

## Commercial support

PKIX is developed by [wolfSSL](https://www.wolfssl.com/).

- **FIPS 140-3 validation** — The `SignatureVerifier` trait accepts
  [wolfCrypt](https://www.wolfssl.com/products/wolfcrypt/) as a backend,
  giving your path validator access to
  [FIPS 140-3 validated cryptography](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4718)
  (CMVP certificate #4718).
- **Commercial support contracts** — wolfSSL offers support for PKIX
  and the broader wolfSSL product family.
- **NRE / custom engineering** — Need a custom `SignatureVerifier`
  backend, HSM integration, or help meeting a compliance requirement?
  wolfSSL's engineering team can help.

Contact [facts@wolfssl.com](mailto:facts@wolfssl.com) or call
+1 425 245 8247. See also:
[wolfProvider FIPS for 35+ open-source packages](https://www.wolfssl.com/wolfprovider-expansion-35-new-fips-open-source-integrations/).

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
