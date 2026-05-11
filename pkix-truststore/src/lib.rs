#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! PEM/DER trust anchor loading for [`pkix-path`](https://docs.rs/pkix-path).
//!
//! This crate is the canonical place to turn bytes-on-disk (or bytes from any
//! adapter) into [`TrustAnchor`] values that [`pkix_path::validate_path`] will
//! accept. It is intentionally a small Tier 1 building block: bytes-in,
//! anchors-out.
//!
//! # Project stance: no baked-in trust data, no baked-in trust source
//!
//! `pkix-truststore` deliberately ships **no compiled-in CA certificates** and
//! **no built-in knowledge of any platform trust store**. Trust data is
//! deployment configuration, not library content. The set of trust anchors a
//! validator uses is the most security-critical decision a deployment makes,
//! and bundling a snapshot of the Mozilla CA list (or any other vendor's list)
//! into a library version pins that decision to the library's release cadence.
//! That is the wrong coupling.
//!
//! Instead, this crate exposes loaders that accept caller-supplied bytes or
//! paths, plus a generic [`from_der_iter`] entry point that adapter crates
//! (system stores, HSMs, cloud KMS) can feed.
//!
//! # API
//!
//! ```no_run
//! use pkix_truststore::{from_pem_file, TrustAnchor};
//!
//! let anchors: Vec<TrustAnchor> =
//!     from_pem_file("/etc/ssl/certs/ca-certificates.crt")?;
//! # Ok::<(), pkix_truststore::Error>(())
//! ```
//!
//! All loaders return `Result<_, Error>`. PEM bundles are expected to contain
//! one or more concatenated `-----BEGIN CERTIFICATE-----` blocks; comments
//! between blocks (the OpenSSL "Subject / Issuer / Serial" form used by Debian
//! `ca-certificates.crt`) are tolerated. A leading UTF-8 BOM is stripped.
//!
//! # Source coverage
//!
//! Tier 1 (this crate) covers raw PEM/DER from memory or files. Other sources
//! are provided by opt-in adapter crates that produce DER bytes and feed them
//! to [`from_der_iter`]:
//!
//! - `pkix-truststore-system` — OS-native trust stores (macOS Security,
//!   Windows CryptoAPI, Linux/BSD distro bundles). See bead `PKIX-8h87`.
//! - `pkix-truststore-pkcs11` — HSMs, smart cards, TPM 2.0 via PKCS#11.
//!   See bead `PKIX-p8vz`.
//!
//! Plausible future adapters (file when concrete demand): cloud KMS
//! (AWS / Azure / GCP), Vault PKI, NSS, EST, SCEP, CMP.
//!
//! # Stability
//!
//! [`Error`] is `#[non_exhaustive]`. New error variants may be added in minor
//! releases; do not match it exhaustively.

use std::path::Path;
use std::{fs, io, vec::Vec};

use der::Decode;
use x509_cert::Certificate;

pub use pkix_path::TrustAnchor;

/// Errors returned by trust anchor loading.
///
/// `#[non_exhaustive]`: new variants may be added in minor releases.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Filesystem I/O failed while reading a trust anchor file.
    Io(io::Error),
    /// PEM decoding failed. The wrapped [`der::Error`] surfaces the underlying
    /// `der::pem` failure (missing end boundary, bad base64, unknown label).
    Pem(der::Error),
    /// DER decoding failed for a certificate body.
    Der(der::Error),
    /// The input parsed cleanly but contained no certificates.
    ///
    /// Returned by [`from_pem`] and the file/iter variants when zero
    /// `-----BEGIN CERTIFICATE-----` blocks (or zero DER inputs) were
    /// observed. An empty trust store is almost always a configuration
    /// mistake, so this is a hard error rather than `Ok(vec![])`.
    NoCertificates,
    /// One certificate in a multi-cert input was malformed. The wrapped
    /// `usize` is the 0-based position of the offending entry in the input
    /// stream (PEM block index for [`from_pem`], iterator index for
    /// [`from_der_iter`]).
    MalformedAnchor(usize),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "i/o error: {e}"),
            Self::Pem(e) => write!(f, "PEM decoding failed: {e}"),
            Self::Der(e) => write!(f, "DER decoding failed: {e}"),
            Self::NoCertificates => f.write_str("input contained no certificates"),
            Self::MalformedAnchor(i) => write!(f, "malformed certificate at position {i}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Pem(e) | Self::Der(e) => Some(e),
            Self::NoCertificates | Self::MalformedAnchor(_) => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// UTF-8 byte order mark.
const UTF8_BOM: &[u8] = b"\xef\xbb\xbf";

/// Strip a leading UTF-8 BOM from `bytes`, if present.
fn strip_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(UTF8_BOM).unwrap_or(bytes)
}

/// Parse one or more PEM-encoded certificates into trust anchors.
///
/// Accepts the common real-world bundle shapes:
///
/// * Multiple concatenated `-----BEGIN CERTIFICATE----- ... -----END
///   CERTIFICATE-----` blocks.
/// * Header text or `Subject/Issuer/Serial` comment lines between blocks
///   (Debian `ca-certificates.crt` format).
/// * A leading UTF-8 BOM.
/// * Mixed CRLF / LF line endings.
/// * Trailing whitespace (spaces, tabs, blank lines) after the last
///   `-----END CERTIFICATE-----`.
///
/// Returns [`Error::NoCertificates`] if the input parsed cleanly but contained
/// zero PEM blocks; returns [`Error::Pem`] or [`Error::Der`] on the first
/// malformed block.
///
/// # Limitations
///
/// * Trailing **non-whitespace** content after the last
///   `-----END CERTIFICATE-----` (for example, a closing comment line) is
///   rejected with [`Error::Pem`]. This matches the underlying x509-cert
///   `load_pem_chain` behaviour. Real-world distro bundles do not include
///   such trailing content; if your producer does, strip it before calling.
///
/// # Strictness
///
/// PEM decoding is strict per RFC 7468 (RustCrypto's `pem-rfc7468`). Unknown
/// PEM labels (`PRIVATE KEY`, `RSA PRIVATE KEY`, `X509 CRL`, etc.) are an
/// error, not silently skipped. If you need a lenient loader that extracts
/// only `CERTIFICATE` blocks from a mixed PEM file, decode it yourself and
/// feed the DER bytes to [`from_der_iter`].
///
/// # Errors
///
/// * [`Error::Pem`] — PEM boundary or base64 was malformed.
/// * [`Error::Der`] — a PEM block decoded but its DER body was not a valid
///   `Certificate`.
/// * [`Error::NoCertificates`] — input contained zero PEM blocks.
pub fn from_pem(bytes: &[u8]) -> Result<Vec<TrustAnchor>, Error> {
    let bytes = strip_bom(bytes);
    // x509-cert 0.2.5's `load_pem_chain` panics on input that is empty after
    // its internal trailing-whitespace strip (subtract-with-overflow at
    // `certificate.rs:256`). Defend against that here so consumers see
    // `Error::NoCertificates` instead of a panic. The check is also correct
    // for input with no `-----BEGIN CERTIFICATE-----` markers at all.
    if !bytes
        .windows(BEGIN_BOUNDARY.len())
        .any(|w| w == BEGIN_BOUNDARY)
    {
        return Err(Error::NoCertificates);
    }
    let certs = Certificate::load_pem_chain(bytes).map_err(map_pem_chain_error)?;
    if certs.is_empty() {
        return Err(Error::NoCertificates);
    }
    Ok(certs.into_iter().map(TrustAnchor::from_cert).collect())
}

const BEGIN_BOUNDARY: &[u8] = b"-----BEGIN CERTIFICATE-----";

/// Parse a single DER-encoded certificate into a trust anchor.
///
/// DER is a binary, length-prefixed encoding: unlike PEM, multiple
/// certificates do not concatenate cleanly into a single buffer. Use
/// [`from_der_iter`] when you have multiple DER blobs.
///
/// # Errors
///
/// Returns [`Error::Der`] if the bytes do not decode as a single
/// `Certificate`.
pub fn from_der(bytes: &[u8]) -> Result<TrustAnchor, Error> {
    let cert = Certificate::from_der(bytes).map_err(Error::Der)?;
    Ok(TrustAnchor::from_cert(cert))
}

/// Parse an iterator of DER-encoded certificates into trust anchors.
///
/// This is the canonical adapter entry point. Adapter crates that obtain DER
/// bytes from a source (file read, HSM API, OS keychain API, cloud KMS,
/// network protocol) feed those bytes through this function. Centralising the
/// parsing here means every adapter inherits the same validation behaviour and
/// the same error reporting.
///
/// The iterator is consumed eagerly; all anchors are decoded before returning.
///
/// # Errors
///
/// * [`Error::MalformedAnchor`] — the wrapped index identifies which entry
///   in the iterator failed to decode. The underlying [`der::Error`] is not
///   currently surfaced; if you need it, decode entries one at a time with
///   [`from_der`].
/// * [`Error::NoCertificates`] — the iterator yielded zero items.
pub fn from_der_iter<I, B>(iter: I) -> Result<Vec<TrustAnchor>, Error>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
{
    let mut anchors = Vec::new();
    for (i, bytes) in iter.into_iter().enumerate() {
        let cert = Certificate::from_der(bytes.as_ref()).map_err(|_| Error::MalformedAnchor(i))?;
        anchors.push(TrustAnchor::from_cert(cert));
    }
    if anchors.is_empty() {
        return Err(Error::NoCertificates);
    }
    Ok(anchors)
}

/// Load PEM-encoded trust anchors from a file.
///
/// Convenience wrapper around [`from_pem`]. The whole file is read into
/// memory; for very large bundles (tens of MB), call [`from_pem`] on a
/// caller-managed buffer.
///
/// # Errors
///
/// * [`Error::Io`] — the file could not be opened or read.
/// * Any error returned by [`from_pem`].
pub fn from_pem_file(path: impl AsRef<Path>) -> Result<Vec<TrustAnchor>, Error> {
    let bytes = fs::read(path)?;
    from_pem(&bytes)
}

/// Load a single DER-encoded trust anchor from a file.
///
/// Convenience wrapper around [`from_der`].
///
/// # Errors
///
/// * [`Error::Io`] — the file could not be opened or read.
/// * Any error returned by [`from_der`].
pub fn from_der_file(path: impl AsRef<Path>) -> Result<TrustAnchor, Error> {
    let bytes = fs::read(path)?;
    from_der(&bytes)
}

/// Best-effort split of a `der::Error` returned by PEM chain decoding into
/// [`Error::Pem`] vs [`Error::Der`].
///
/// `x509_cert::Certificate::load_pem_chain` returns `der::Error` directly. We
/// distinguish PEM-framing failures from DER-body failures by inspecting the
/// inner `der::ErrorKind`: anything in the `Pem` family maps to
/// [`Error::Pem`], everything else to [`Error::Der`].
fn map_pem_chain_error(e: der::Error) -> Error {
    use der::ErrorKind;
    match e.kind() {
        ErrorKind::Pem(_) => Error::Pem(e),
        _ => Error::Der(e),
    }
}

#[cfg(test)]
mod tests {
    //! Internal smoke tests.
    //!
    //! The bulk of testing — real-world distro bundles, BOM/CRLF quirks, and
    //! the negative cases catalogued in PKIX-lhm4 — lives in `tests/`, where
    //! the fixtures are full files rather than `include_bytes!` blobs. These
    //! in-source tests cover only the unit-level behaviours that do not
    //! benefit from on-disk fixtures.
    use super::*;

    #[test]
    fn strip_bom_present() {
        let mut v = UTF8_BOM.to_vec();
        v.extend_from_slice(b"hello");
        assert_eq!(strip_bom(&v), b"hello");
    }

    #[test]
    fn strip_bom_absent() {
        assert_eq!(strip_bom(b"hello"), b"hello");
    }

    #[test]
    fn empty_pem_input_is_no_certificates() {
        assert!(matches!(from_pem(b""), Err(Error::NoCertificates)));
    }

    #[test]
    fn empty_der_iter_is_no_certificates() {
        let empty: [&[u8]; 0] = [];
        assert!(matches!(from_der_iter(empty), Err(Error::NoCertificates)));
    }

    #[test]
    fn from_der_rejects_garbage() {
        let bad = [0xff_u8; 64];
        assert!(matches!(from_der(&bad), Err(Error::Der(_))));
    }

    #[test]
    fn from_der_iter_reports_index_of_bad_entry() {
        // First entry will be a syntactically-invalid DER blob.
        let bad: &[&[u8]] = &[&[0xff_u8; 16]];
        match from_der_iter(bad.iter().copied()) {
            Err(Error::MalformedAnchor(i)) => assert_eq!(i, 0),
            other => panic!("expected MalformedAnchor(0), got {other:?}"),
        }
    }
}
