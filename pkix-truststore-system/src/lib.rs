//! # pkix-truststore-system
//!
//! **OS-native trust store adapter for [`pkix-truststore`]. Stub crate.**
//!
//! Loads trust anchors from platform-native trust stores and feeds them
//! through [`pkix_truststore::from_der_iter`] to produce
//! `Vec<TrustAnchor>`. The `rustls-native-certs` analog for the
//! `pkix-truststore` ecosystem.
//!
//! Planned platform support:
//! - macOS — via `security-framework` (Security.framework / Keychain)
//! - Windows — via `wincert-store` or direct CryptoAPI bindings
//! - iOS — via `security-framework` (Keychain Services)
//! - Android — via JNI to `KeyStore`
//!
//! Linux trust stores are deliberately out of scope here: most distributions
//! expose the system bundle as a PEM file at a well-known path
//! (`/etc/ssl/certs/ca-certificates.crt` or similar), which the consumer
//! reads directly via `pkix_truststore::from_pem`. Adding a separate Linux
//! adapter doesn't pay rent.
//!
//! ## Project stance
//!
//! No baked-in trust data, no baked-in trust source. Per the workspace
//! `pkix-truststore` stance, platform / HSM / cloud KMS sources are adapter
//! crates that fetch DER bytes from a source-specific API and feed them into
//! [`pkix_truststore::from_der_iter`]. This crate is one such adapter.
//!
//! ## Status
//!
//! Stub crate. The substantive content (per-platform trust store readers,
//! feature flags, error types) is scheduled to land via [PKIX-8h87].
//!
//! [`pkix-truststore`]: https://docs.rs/pkix-truststore
//! [`pkix_truststore::from_der_iter`]: https://docs.rs/pkix-truststore
//! [`pkix_truststore::from_pem`]: https://docs.rs/pkix-truststore
//! [PKIX-8h87]: https://github.com/MarkAtwood/crate-pkix

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
