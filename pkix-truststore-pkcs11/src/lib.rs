//! # pkix-truststore-pkcs11
//!
//! **PKCS#11 / HSM / smart card trust store adapter for [`pkix-truststore`]. Stub crate.**
//!
//! Opens a PKCS#11 session, enumerates `CKO_CERTIFICATE` objects with
//! `CKA_TRUSTED=true` (or filtered by other criteria), extracts `CKA_VALUE`
//! (DER bytes), and feeds them through [`pkix_truststore::from_der_iter`] to
//! produce `Vec<TrustAnchor>`.
//!
//! Planned support:
//! - General PKCS#11 tokens (Yubico HSM, Thales, AWS CloudHSM, Azure
//!   Dedicated HSM, SafeNet, OpenSC-backed tokens)
//! - PIV / CAC smart cards via PKCS#11
//! - FIPS-mode deployments where trust roots live on a token rather than
//!   in a filesystem PEM bundle
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
//! Stub crate. The substantive content (PKCS#11 session management, object
//! enumeration, `CKA_TRUSTED` filtering, error mapping) is scheduled to land
//! via [PKIX-p8vz].
//!
//! [`pkix-truststore`]: https://docs.rs/pkix-truststore
//! [`pkix_truststore::from_der_iter`]: https://docs.rs/pkix-truststore
//! [PKIX-p8vz]: https://github.com/MarkAtwood/crate-pkix

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, unreachable_pub)]
#![warn(missing_docs)]
