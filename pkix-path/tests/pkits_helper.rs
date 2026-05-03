//! Shared helpers for PKITS (NIST SP 800-89) integration tests.
//!
//! Include in a test file with:
//!
//! ```rust,ignore
//! #[path = "pkits_helper.rs"]
//! mod pkits_helper;
//! use pkits_helper::{pkits_validate, PKITS_NOW};
//! ```
//!
//! # Cert naming
//!
//! Pass cert base names without the `.crt` extension, leaf-first:
//!
//! ```rust,ignore
//! pkits_validate(&["ValidCertificatePathTest1EE", "GoodCACert"], PKITS_NOW)
//! ```
//!
//! The trust anchor (`TrustAnchorRootCertificate.crt`) is always loaded automatically.

use der::Decode as _;
use pkix_path::{DefaultVerifier, TrustAnchor, ValidatedPath, ValidationPolicy};
use x509_cert::Certificate;

/// Unix timestamp in the PKITS cert validity window (notBefore=2010-01-01, notAfter=2030-12-31).
///
/// Using 2020-01-01 00:00:00 UTC = 1 577 836 800.
///
/// **Keep in sync**: `pkix-chain/tests/e2e.rs` defines the same constant.
/// If you update this value, update that file too.
pub const PKITS_NOW: u64 = 1_577_836_800;

/// PKITS cert base path relative to `CARGO_MANIFEST_DIR`.
const PKITS_CERT_DIR: &str = "tests/pkits/certs";

/// Load a PKITS DER certificate by its base name (without `.crt` extension).
///
/// Panics with a descriptive message if the file is missing or fails to parse.
pub fn pkits_cert(name: &str) -> Certificate {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(PKITS_CERT_DIR)
        .join(format!("{name}.crt"));
    let der = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("failed to read PKITS cert '{name}': {e} (path: {path:?})"));
    Certificate::from_der(&der)
        .unwrap_or_else(|e| panic!("failed to parse PKITS cert '{name}': {e}"))
}

/// Load the PKITS trust anchor.
///
/// Wraps `TrustAnchorRootCertificate.crt` as a [`TrustAnchor`].
pub fn pkits_trust_anchor() -> TrustAnchor {
    TrustAnchor::from_cert(pkits_cert("TrustAnchorRootCertificate"))
}

/// Validate a PKITS certificate path.
///
/// - `cert_names` — leaf-first, without the trust anchor
/// - `now_unix`   — seconds since Unix epoch; use [`PKITS_NOW`] for the standard test time
///
/// Uses [`DefaultVerifier`] (RSA-PKCS1v15-SHA256 and ECDSA-P256-SHA256) and the
/// standard PKITS trust anchor.
pub fn pkits_validate(cert_names: &[&str], now_unix: u64) -> pkix_path::Result<ValidatedPath> {
    let chain: Vec<Certificate> = cert_names.iter().map(|n| pkits_cert(n)).collect();
    let anchors = [pkits_trust_anchor()];
    let policy = ValidationPolicy::new(now_unix);
    pkix_path::validate_path(&chain, &anchors, &policy, &DefaultVerifier)
}
