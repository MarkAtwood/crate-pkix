# pkix-ct

Certificate Transparency SCT verification for `pkix-chain`.

## What this does

Parses and verifies Signed Certificate Timestamps (SCTs) embedded in X.509
certificates and OCSP responses against a set of trusted CT log public keys.
The CA/Browser Forum TLS Baseline Requirements mandate that publicly-trusted
TLS certificates include at least two SCTs from distinct logs.

SCTs can be embedded in three places:

- The certificate itself — `SignedCertificateTimestampList` extension
  (OID 1.3.6.1.4.1.11129.2.4.2). Always `precert_entry`; verified via
  [`SctVerifier::verify_sct_for_precert`][verifier-precert] or the
  loop helper [`SctVerifier::verify_embedded_scts`][verifier-embedded].
- OCSP responses — `SignedCertificateTimestampList` extension under
  OID 1.3.6.1.4.1.11129.2.4.5. Parser implemented behind the `ocsp` feature.
  Always `x509_entry`; verified via
  [`SctVerifier::verify_sct_for_cert`][verifier-cert].
- TLS handshake — delivered as a TLS extension (raw `SerializedSCTList`).
  Parser implemented (see [`sct_list_from_tls_extension`][delivery]).
  Also `x509_entry`.

## Status

Implemented:

- Binary-format parsing of `SignedCertificateTimestamp` and `SctList`
  (RFC 6962 §3.2 / §3.3).
- CT log list management (`CtLog`, `CtLogList`) with the Google/Chrome
  `log_list.json` schema parser behind `log-list-json`.
- Delivery-channel extractors for the TLS handshake extension and (behind
  the `ocsp` feature) OCSP responses.
- SCT signature verification for both the `x509_entry` and
  `precert_entry` log entry types via [`SctVerifier`][verifier],
  dispatching algorithm-specific verification through `pkix-path`'s
  [`SignatureVerifier`] trait.

Implemented (continued):

- Merkle inclusion proof verification and Signed Tree Head signature
  verification (RFC 6962 §2.1.1 / §3.5). See
  [`SctVerifier::verify_inclusion`][verifier-inclusion] and
  [`SctVerifier::verify_sth`][verifier-sth].

## Example

Verify the SCTs embedded in a cert against a trusted log list:

```rust,no_run
# #[cfg(all(feature = "log-list", feature = "log-list-json"))]
# fn example() -> Result<(), pkix_ct::Error> {
use pkix_ct::{CtLogList, SctVerifier};
use pkix_path::DefaultVerifier;
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

// Caller-supplied log list. pkix-ct ships no built-in trust data.
let log_list_json: &str = ""; // load from a trusted source
let logs = CtLogList::from_google_log_list_json(log_list_json)?;

let leaf_der: &[u8] = &[]; // final cert, DER-encoded
let issuer_der: &[u8] = &[]; // its immediate issuer, DER-encoded
let leaf = Certificate::from_der(leaf_der).map_err(|_| pkix_ct::Error::ParseError)?;
let issuer = Certificate::from_der(issuer_der).map_err(|_| pkix_ct::Error::ParseError)?;

let v = SctVerifier::new(logs, DefaultVerifier);
let valid = v.verify_embedded_scts(&leaf, &issuer)?;
// CA/Browser Forum TLS BR §3.2.2.9 requires at least two SCTs.
assert!(valid >= 2, "cert has too few valid SCTs (got {valid})");
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
[verifier-cert]: https://docs.rs/pkix-ct/latest/pkix_ct/struct.SctVerifier.html#method.verify_sct_for_cert
[verifier-precert]: https://docs.rs/pkix-ct/latest/pkix_ct/struct.SctVerifier.html#method.verify_sct_for_precert
[verifier-embedded]: https://docs.rs/pkix-ct/latest/pkix_ct/struct.SctVerifier.html#method.verify_embedded_scts
[verifier-inclusion]: https://docs.rs/pkix-ct/latest/pkix_ct/struct.SctVerifier.html#method.verify_inclusion
[verifier-sth]: https://docs.rs/pkix-ct/latest/pkix_ct/struct.SctVerifier.html#method.verify_sth
[`SignatureVerifier`]: https://docs.rs/pkix-path/latest/pkix_path/trait.SignatureVerifier.html

## License

Apache-2.0 OR MIT
