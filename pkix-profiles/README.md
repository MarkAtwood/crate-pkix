# pkix-profiles

CA/Browser Forum and RFC certificate profile policies for `pkix-path`.

Provides pre-configured [`Profile`] implementations and [`ValidationPolicy`]
convenience constructors for common certificate use cases — TLS server
certificates, S/MIME, code signing, and plain RFC 5280.

## Profiles

| Struct | Function alias | Normative basis | Key constraints |
|--------|----------------|-----------------|-----------------|
| [`WebPkiProfile`] | [`web_pki_policy`] | CA/B Forum TLS BR (SC-081) | SHA-1 prohibited, RSA ≥ 2048 bits, SAN required, `serverAuth` EKU, path len ≤ 2 |
| [`SmimeProfile`] | [`smime_policy`] | CA/B Forum S/MIME BR v1.0 | SHA-1 prohibited, RSA ≥ 2048 bits, `rfc822Name` SAN required, `emailProtection` EKU, max validity 1185 days, path len ≤ 1 |
| [`CodeSigningProfile`] | [`code_signing_policy`] | CA/B Forum CS BR v3.0 | SHA-1 prohibited, RSA ≥ 3072 bits, `codeSigning` EKU |
| [`Rfc5280Profile`] | [`rfc5280_policy`] | RFC 5280 only | No CA/B Forum additions; strict RFC 5280 defaults |

## Usage

```rust
use pkix_profiles::{web_pki_policy, WebPkiProfile, Profile};
use pkix_path::validate_path;

// Function alias — returns a ValidationPolicy for the current time
let policy = web_pki_policy(now_unix);
validate_path(&chain, &anchors, &policy, &DefaultVerifier)?;

// Struct form — useful when implementing LintProfile from pkix-lint
let profile = WebPkiProfile;
let policy = profile.policy(now_unix);
```

### S/MIME

```rust
use pkix_profiles::smime_policy;

let policy = smime_policy(now_unix);
validate_path(&chain, &anchors, &policy, &DefaultVerifier)?;
```

### Code signing

```rust
use pkix_profiles::code_signing_policy;

let policy = code_signing_policy(now_unix);
validate_path(&chain, &anchors, &policy, &DefaultVerifier)?;
```

### Bare RFC 5280

```rust
use pkix_profiles::rfc5280_policy;

let policy = rfc5280_policy(now_unix);
validate_path(&chain, &anchors, &policy, &DefaultVerifier)?;
```

## SC-081 validity cap

CA/B Forum Ballot SC-081 introduced a phased reduction in TLS certificate
maximum validity:

| Issuance date | Maximum validity |
|---------------|-----------------|
| Before 2026-03-15 | 398 days |
| 2026-03-15 – 2027-03-15 | 200 days |
| 2027-03-15 – 2029-03-15 | 100 days |
| From 2029-03-15 | 47 days |

Because the applicable cap depends on the certificate's `notBefore` date rather
than the current clock, SC-081 enforcement is not set in `ValidationPolicy`
directly. It is handled by `ValidityMaxLint` in `pkix-lint`, which evaluates
each certificate at issuance time. Use `sc081_validity_cap(not_before_unix)` to
look up the correct cap for a given issuance date.

## Limitations (v0.2)

- `SmimeProfile` covers the Mailbox-validated / strict generation only.
  Organization-validated, Sponsor-validated, and Individual-validated S/MIME
  profiles are planned for v0.3.
- Timestamp authority verification (CS BR requirement) is out of scope for
  `pkix-path`; it requires RFC 3161 timestamp token parsing.

## Standards

- CA/B Forum Baseline Requirements for TLS Server Certificates (TLS BR, SC-081)
- CA/B Forum S/MIME Baseline Requirements v1.0
- CA/B Forum Code Signing Baseline Requirements v3.0
- [RFC 5280] — Internet X.509 PKI Certificate and CRL Profile
- [RFC 5753] — Use of Elliptic Curve Cryptography (ECC) Algorithms in CMS

## License

Apache-2.0 OR MIT
