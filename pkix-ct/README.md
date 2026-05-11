# pkix-ct

Certificate Transparency SCT verification for `pkix-chain`.

## What this does

Parses and verifies Signed Certificate Timestamps (SCTs) embedded in X.509
certificates and OCSP responses against a set of trusted CT log public keys.
The CA/Browser Forum TLS Baseline Requirements mandate that publicly-trusted
TLS certificates include at least two SCTs from distinct logs.

SCTs can be embedded in three places:

- The certificate itself — `SignedCertificateTimestampList` extension
  (OID 1.3.6.1.4.1.11129.2.4.2). Parser implemented; SCTs are typically
  `precert_entry` here and full signature verification of the precert
  variant is not yet implemented (tracked as PKIX-baac.4).
- OCSP responses — `SignedCertificateTimestampList` extension under
  OID 1.3.6.1.4.1.11129.2.4.5. Parser implemented behind the `ocsp` feature.
  Typically `x509_entry`, which `SctVerifier` fully verifies.
- TLS handshake — delivered as a TLS extension (raw `SerializedSCTList`).
  Parser implemented (see [`sct_list_from_tls_extension`][delivery]).

## Status

Implemented:

- Binary-format parsing of `SignedCertificateTimestamp` and `SctList`
  (RFC 6962 §3.2 / §3.3).
- CT log list management (`CtLog`, `CtLogList`) with the Google/Chrome
  `log_list.json` schema parser behind `log-list-json`.
- Delivery-channel extractors for the TLS handshake extension and (behind
  the `ocsp` feature) OCSP responses.
- SCT signature verification for the `x509_entry` log entry type via
  [`SctVerifier`][verifier], dispatching algorithm-specific verification
  through `pkix-path`'s [`SignatureVerifier`] trait.

Not yet implemented (tracked under PKIX-baac):

- `precert_entry` signature verification — the pre-cert branch of
  RFC 6962 §3.2.
- Merkle inclusion proof verification (RFC 6962 §2.1.1).

## Example

```rust,no_run
# #[cfg(all(feature = "log-list", feature = "log-list-json"))]
# fn example() -> Result<(), pkix_ct::Error> {
use pkix_ct::{CtLogList, SctList, SctVerifier};
use pkix_path::DefaultVerifier;

// Caller-supplied log list. pkix-ct ships no built-in trust data.
let log_list_json: &str = ""; // load from a trusted source
let logs = CtLogList::from_google_log_list_json(log_list_json)?;

let cert_der: &[u8] = &[]; // final certificate, DER-encoded
let sct_list_bytes: &[u8] = &[]; // extracted from cert/OCSP/TLS
let scts = SctList::from_extension_value(sct_list_bytes)?;

let v = SctVerifier::new(logs, DefaultVerifier);
for sct in &scts.0 {
    v.verify_sct_for_cert(sct, cert_der)?;
}
# Ok(())
# }
```

## Standards

- [RFC 6962] — Certificate Transparency
- [RFC 9162] — Certificate Transparency Version 2.0
- CA/Browser Forum TLS Baseline Requirements §3.2.2.9 — SCT requirements

[RFC 6962]: https://www.rfc-editor.org/rfc/rfc6962
[RFC 9162]: https://www.rfc-editor.org/rfc/rfc9162
[delivery]: https://docs.rs/pkix-ct/latest/pkix_ct/fn.sct_list_from_tls_extension.html
[verifier]: https://docs.rs/pkix-ct/latest/pkix_ct/struct.SctVerifier.html
[`SignatureVerifier`]: https://docs.rs/pkix-path/latest/pkix_path/trait.SignatureVerifier.html

## License

Apache-2.0 OR MIT
