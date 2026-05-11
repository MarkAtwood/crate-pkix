# pkix-profiles

RFC-baseline certificate profile policies for `pkix-path`.

Provides standards-body [`Profile`] implementations: the structural
constraints that any conforming PKI deployment can rely on, derived
directly from IETF RFCs without overlaying any individual industry-forum
interpretation.

## Profiles

| Struct | Free-function alias | Normative basis | Key constraints |
|--------|---------------------|-----------------|-----------------|
| [`Rfc5280Profile`] | [`rfc5280_policy`] | RFC 5280 | No overlay; strict RFC 5280 defaults |
| [`BasicTlsProfile`] | [`basic_tls_policy`] | RFC 5280 + RFC 6125 | Non-empty SAN required, `id-kp-serverAuth` EKU |
| [`BasicSmimeProfile`] | [`basic_smime_policy`] | RFC 8551 §3 | `rfc822Name` SAN required, `id-kp-emailProtection` EKU |

For CA/Browser Forum profile content (TLS BR, S/MIME BR, Code Signing BR,
SC-081 phased validity caps), use the sibling [`pkix-profiles-cabf`] crate.

## Usage

```rust
use pkix_profiles::{basic_tls_policy, BasicTlsProfile, Profile};
use pkix_path::validate_path;

// Function alias — returns a ValidationPolicy for the current time
let policy = basic_tls_policy(now_unix);
validate_path(&chain, &anchors, &policy, &DefaultVerifier)?;

// Struct form — useful when implementing LintProfile from pkix-lint
let profile = BasicTlsProfile;
let policy = profile.policy(now_unix);
```

### S/MIME

```rust
use pkix_profiles::basic_smime_policy;

let policy = basic_smime_policy(now_unix);
validate_path(&chain, &anchors, &policy, &DefaultVerifier)?;
```

### Bare RFC 5280

```rust
use pkix_profiles::rfc5280_policy;

let policy = rfc5280_policy(now_unix);
validate_path(&chain, &anchors, &policy, &DefaultVerifier)?;
```

## Migration from 0.2.x

The CA/Browser Forum-specific profiles (`WebPkiProfile`, `SmimeProfile`,
`CodeSigningProfile`), the SC-081 phased validity helper
(`sc081_validity_cap`), and the CA/B Forum allowed-algorithm tables moved
to the sibling [`pkix-profiles-cabf`] crate in `pkix-profiles 0.3.0`.

Deprecated re-exports remain in `pkix-profiles 0.3.x` so existing imports
continue to compile (with a deprecation warning). The re-exports drop in
`pkix-profiles 0.4.0`.

Migration path: add `pkix-profiles-cabf` to your `Cargo.toml` and update
imports:

```rust
// Before (pkix-profiles 0.2.x):
use pkix_profiles::{WebPkiProfile, web_pki_policy, sc081_validity_cap};

// After (pkix-profiles-cabf 0.2.x):
use pkix_profiles_cabf::{WebPkiProfile, web_pki_policy, sc081_validity_cap};
```

The rationale is the framework-not-policy stance: this crate ships
standards-body profile mechanisms; CA/B Forum reference encodings live
in `pkix-profiles-cabf` clearly marked "reference / not authoritative —
fork and adapt to your deployment's current CA/B Forum interpretation."

## Limitations

- `BasicSmimeProfile` covers only the RFC 8551 §3 baseline. CA/Browser
  Forum S/MIME BR identity-tier sub-profiles (Mailbox-validated,
  Organization-validated, Sponsor-validated, Individual-validated) are
  out-of-scope here and live in [`pkix-profiles-cabf`].

## Standards

- [RFC 5280] — Internet X.509 PKI Certificate and CRL Profile
- [RFC 5753] — Use of ECC Algorithms in CMS
- [RFC 6125] — Representation and Verification of Domain-Based
  Application Service Identity within Internet PKIX Using X.509
  Certificates
- [RFC 8551] — S/MIME 4.0 Message Specification

## License

Apache-2.0 OR MIT

[`pkix-profiles-cabf`]: https://docs.rs/pkix-profiles-cabf
[RFC 5280]: https://datatracker.ietf.org/doc/html/rfc5280
[RFC 5753]: https://datatracker.ietf.org/doc/html/rfc5753
[RFC 6125]: https://datatracker.ietf.org/doc/html/rfc6125
[RFC 8551]: https://datatracker.ietf.org/doc/html/rfc8551
