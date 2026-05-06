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

### OCSP checking

```rust
use pkix_revocation::{OcspChecker, RevocationChecker};
use pkix_path::DefaultVerifier;

let ocsp_response_der = fetch_ocsp_response(...);
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

1. Parses the DER-encoded `CertificateList` (RFC 5280 §5).
2. Verifies the CRL signature against the issuer's SPKI.
3. Checks the CRL's `issuer` field matches the certificate's `issuer`.
4. Checks `thisUpdate ≤ now ≤ nextUpdate` (absent `nextUpdate` → fail).
5. Searches `revokedCertificates` for the certificate's serial number.
6. Returns `Err(Revoked { serial, reason_code })` if found, `Ok(())` if not.

## How OCSP checking works

`OcspChecker::check_revocation`:

1. Parses the DER-encoded `OCSPResponse` (RFC 6960 §4.2).
2. Requires `responseStatus == successful`.
3. Verifies the signature on `BasicOCSPResponse` against the issuer's SPKI.
4. Finds the `SingleResponse` matching the certificate's serial number.
5. Checks `producedAt ≤ now`, `thisUpdate ≤ now`, `now ≤ nextUpdate`.
6. Returns based on `certStatus`: `good → Ok(())`, `revoked → Err(Revoked)`,
   `unknown → Err(OcspStatusUnknown)`.

## v0.1 limitations

- CRL checking does not follow CRL Distribution Points — caller supplies the CRL.
- Delta CRLs are not supported.
- OCSP checking only supports issuer-signed (direct) responses; delegated
  responder certificates are not supported.
- `SingleResponse` matching is by serial number only; `issuerNameHash` and
  `issuerKeyHash` are not verified.

## Standards

- [RFC 5280] §5 — CRL Profile
- [RFC 5280] §4.2.1.13 — CRL Distribution Points
- [RFC 6960] — Online Certificate Status Protocol (OCSP)

## License

Apache-2.0 OR MIT
