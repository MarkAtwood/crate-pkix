# pkix-revocation

Certificate revocation checking for `pkix-path` and `pkix-chain`.

Provides the [`RevocationChecker`] trait and three implementations:

| Type | Feature | Description |
|------|---------|-------------|
| `NoRevocation` | always | Zero-cost; always reports not-revoked |
| `CrlChecker` | `crl` | Offline CRL validation (you supply DER bytes) |
| `OcspChecker` | `ocsp` | Offline OCSP response validation (you supply DER bytes) |

## Design: offline by default

All checkers are **offline** — the caller supplies pre-fetched DER bytes.
There is no network I/O in this crate. This keeps the core `no_std`-compatible
and lets you control fetching (cache, rate-limit, pre-fetch at startup).

For online fetching from CRL Distribution Points and OCSP URLs found in
certificates, see [`pkix-revocation-http`].

## Usage

### No revocation (offline/embedded)

```rust
use pkix_revocation::NoRevocation;
// Pass to pkix_chain::verify_chain as the revocation argument.
// Always returns Ok(()); suitable for closed networks, short-lived certs,
// hardware attestation where issuance is the control.
```

### CRL checking

```rust
use pkix_revocation::{CrlChecker, RevocationChecker};
use pkix_path::DefaultVerifier;

let crl_der = std::fs::read("issuing-ca.crl")?;
let checker = CrlChecker::new(crl_der, now_unix, DefaultVerifier);

// Called once per certificate by pkix_chain::verify_chain,
// or directly:
checker.check_revocation(&leaf_cert, &issuer_cert)?;
```

### CRL with delta CRL

Delta CRLs (RFC 5280 §5.2.4) contain only the incremental changes since a
base CRL was issued, reducing download size. Supply both:

```rust
use pkix_revocation::CrlChecker;
use pkix_path::DefaultVerifier;

let checker = CrlChecker::with_delta(base_crl_der, delta_crl_der, now_unix, DefaultVerifier)?;
checker.check_revocation(&leaf_cert, &issuer_cert)?;
```

### OCSP checking

```rust
use pkix_revocation::{OcspChecker, RevocationChecker};
use pkix_path::DefaultVerifier;

let ocsp_response_der = fetch_ocsp_response(/* ... */);
let checker = OcspChecker::new(ocsp_response_der, now_unix, DefaultVerifier);
checker.check_revocation(&leaf_cert, &issuer_cert)?;
```

### Custom revocation

```rust
use pkix_revocation::RevocationChecker;
use x509_cert::Certificate;

struct MyRevocationChecker;

impl RevocationChecker for MyRevocationChecker {
    fn check_revocation(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
    ) -> pkix_revocation::Result<()> {
        // consult your own database, HSM, or policy
        Ok(())
    }
}
```

## How CRL checking works

`CrlChecker::check_revocation`:

1. Verifies that `issuer` is the actual issuer of `cert` (subject/issuer DN match).
2. Parses the DER-encoded `CertificateList` (RFC 5280 §5).
3. Checks the CRL's `issuer` field matches the certificate's `issuer`.
4. Verifies the CRL signature against the issuer's SPKI.
5. Checks `thisUpdate ≤ now ≤ nextUpdate` (absent `nextUpdate` → fail).
6. When a delta CRL is present (`with_delta`), verifies and merges the delta's
   revoked entries with the base CRL's entries (RFC 5280 §5.2.4).
7. Checks the `IssuingDistributionPoint` scope flags if present (onlyContainsUserCerts,
   onlyContainsCACerts, onlyContainsAttributeCerts).
8. Searches `revokedCertificates` for the certificate's serial number.
9. Returns `Err(Revoked { serial, reason_code })` if found, `Ok(())` if not.

## How OCSP checking works

`OcspChecker::check_revocation`:

1. Verifies that `issuer` is the actual issuer of `cert` (subject/issuer DN match).
2. Parses the DER-encoded `OCSPResponse` (RFC 6960 §4.2).
3. Requires `responseStatus == successful`.
4. Verifies the signature on `BasicOCSPResponse` against the issuer's SPKI.
5. Verifies the `ResponderId` matches the issuer by DN (`byName`) or SHA-1 of
   the issuer's SPKI public key bytes (`byKey`).
6. Finds the `SingleResponse` matching the certificate's serial number.
7. Verifies `issuerNameHash` and `issuerKeyHash` in the `CertID` against the
   issuer's subject DN and SPKI key bytes.
8. Checks `producedAt ≤ now`, `thisUpdate ≤ now ≤ nextUpdate`.
9. Returns based on `certStatus`: `good → Ok(())`, `revoked → Err(Revoked)`,
   `unknown → Err(OcspStatusUnknown)`.

## Limitations

- CRL checking does not follow CRL Distribution Points — caller supplies the CRL.
- Indirect CRLs (RFC 5280 §5.2.6) are not yet supported (tracked).
- OCSP checking supports both issuer-signed (direct) responses and CA
  Designated Responder (delegated) responses (RFC 6960 §4.2.2.2). The
  third RFC 6960 case — a Trusted Responder whose key the requester
  trusts out-of-band — is not separately modeled (callers can pass that
  responder cert as the `issuer` argument).
- The `id-pkix-ocsp-nocheck` extension on delegate certs (RFC 6960
  §4.2.2.2.1) is documented but not enforced — this crate is a
  single-shot offline checker and never recurses into delegate
  revocation regardless of the extension.

## Standards

- [RFC 5280] §5 — CRL Profile
- [RFC 5280] §5.2.4 — Delta CRLs
- [RFC 5280] §5.2.5 — IssuingDistributionPoint
- [RFC 5280] §4.2.1.13 — CRL Distribution Points
- [RFC 6960] — Online Certificate Status Protocol (OCSP)

## License

Apache-2.0 OR MIT
