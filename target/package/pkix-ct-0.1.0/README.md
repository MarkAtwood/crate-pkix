# pkix-ct

Certificate Transparency SCT verification for `pkix-chain`.

**Status: planned (not yet implemented).**

## What this will do

Verify Signed Certificate Timestamps (SCTs) embedded in X.509 certificates
against a set of trusted CT log public keys. The CA/Browser Forum TLS
Baseline Requirements mandate that publicly-trusted TLS certificates include
at least two SCTs from distinct logs.

SCTs can be embedded in three places:
- The certificate itself — `SignedCertificateTimestampList` extension
  (OID 1.3.6.1.4.1.11129.2.4.2)
- OCSP responses — `SignedCertificateTimestampList` extension in stapled OCSP
- TLS handshake — delivered as a TLS extension (outside this crate's scope)

## Planned API

```rust
use pkix_ct::{verify_scts, CtLogList};
use x509_cert::Certificate;

// Build your log list from the current CT log list JSON
// (e.g. https://www.gstatic.com/ct/log_list/v3/log_list.json)
let mut logs = CtLogList::new();
logs.add_log(log_id_bytes, log_public_key_spki_der);

// Verify that the certificate has at least one valid SCT from a trusted log
verify_scts(&leaf_cert, &logs)?;
```

## How it will work

1. Extract the `SignedCertificateTimestampList` extension from the certificate.
2. For each SCT in the list, look up the log by `log_id` (SHA-256 of the log's
   public key) in the provided `CtLogList`.
3. Verify the SCT signature: the signed data is a `TreeHeadSignature` over the
   pre-certificate's `TBSCertificate` and the SCT's timestamp.
4. Return `Ok(())` if at least one SCT verifies against a trusted log.

## Standards

- [RFC 6962] — Certificate Transparency
- [RFC 9162] — Certificate Transparency Version 2.0
- CA/Browser Forum TLS Baseline Requirements §3.2.2.9 — SCT requirements

## License

Apache-2.0 OR MIT
