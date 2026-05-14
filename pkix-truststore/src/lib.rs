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
//!
//! # Contract guarantees
//!
//! - **Iteration order is preserved.** The `Vec<TrustAnchor>` returned by
//!   [`from_pem`], [`from_pem_file`], [`from_pem_file_with_cap`],
//!   [`from_der_iter`], and any future bulk loader is in the same order as
//!   the input (PEM block order for `from_pem`, iterator order for
//!   `from_der_iter`).
//! - **Duplicates are preserved, not deduplicated.** If the input contains
//!   the same certificate N times, the output contains N [`TrustAnchor`]
//!   values. Bundles in the wild sometimes ship a root multiple times
//!   (e.g., distros that pull the same CA from two upstream packages);
//!   callers wanting dedup must do it themselves (deriving a key from
//!   `(subject, subject_public_key_info)` is the canonical approach).
//!   `TrustAnchor` derives `PartialEq + Eq` so this is straightforward.
//! - **No signature verification.** These loaders extract
//!   `(subject, subject_public_key_info, NameConstraints)` from each
//!   certificate and do **not** verify any signature on the certificate
//!   itself — not the self-signature on a root, not the signature from
//!   an offline parent. Trust in the loaded anchors derives entirely from
//!   trust in the input bytes. This is RFC-conformant (RFC 5280 §6.1
//!   models trust anchors as `(name, key, optional constraints)` tuples)
//!   but means deployment authors must ensure trust-anchor files are
//!   sourced from a trusted channel (signed distro packages, internal
//!   CMDB, etc.).
//! - **Send + Sync.** [`Error`], [`IoFailure`], and the re-exported
//!   [`TrustAnchor`] / [`DerError`] all implement `Send + Sync`. Compile-
//!   time assertions in this crate and in `pkix-path` pin the guarantee
//!   across future refactors. The natural use pattern (load anchors at
//!   startup, share `&[TrustAnchor]` across worker threads, surface
//!   `Error` from any thread) is supported.
//! - **No panics on valid Rust input.** All loader entry points return
//!   [`Result`] for every error category; the only known panic mode in
//!   the dependency stack is an upstream x509-cert 0.2.x edge case
//!   (RustCrypto/formats#1965, empty/whitespace-only PEM input causing a
//!   subtract-with-overflow) which is defended against by an explicit
//!   guard in [`from_pem`]. The workaround is documented inline and is
//!   removed once the workspace bumps to x509-cert 0.3.x. Allocation
//!   failure can panic in `alloc::vec::Vec` and is not specially handled
//!   (consistent with std behaviour).
//!
//! # Features
//!
//! - **`serde`** (off by default) — adds `serde::Serialize` and
//!   `serde::Deserialize` derives to [`Error`] and [`IoFailure`], and
//!   propagates `pkix-path/serde` so the re-exported [`DerError`] gains
//!   the matching wire form. Useful for caching load failures across
//!   processes or persisting them for later replay (AGENTS.md
//!   non-negotiable #6, PKIX-2l0v.1). Round-trip notes: the [`DerError`]
//!   inner `der::Error` is dropped on deserialize (its `Display` message
//!   survives); [`IoFailure::kind`] round-trips via the `Debug` form of
//!   `io::ErrorKind` and falls back to `io::ErrorKind::Other` on
//!   variants the consumer does not know.
//!
//! # Limitations
//!
//! - **No compiled-in CA bundle.** This crate ships zero trust data by
//!   design. See "Project stance" above. Callers needing the Mozilla CA
//!   list must download it (e.g., from curl.se/docs/caextract.html) and
//!   load it with [`from_pem`] / [`from_pem_file`]; this is a
//!   deployment-configuration decision, not a library decision.
//! - **No platform integration in this crate.** Loading from the OS-native
//!   trust store (macOS Security framework, Windows CryptoAPI, iOS, Android)
//!   is the job of `pkix-truststore-system` (skeleton; substantive content
//!   tracked under `PKIX-8h87`). Loading from PKCS#11 / HSM / smart card
//!   tokens is the job of `pkix-truststore-pkcs11` (skeleton; tracked
//!   under `PKIX-p8vz`). Both adapter crates feed [`from_der_iter`] and
//!   stay outside the 1.0 release; they ship at their own 0.x cadence.
//! - **No constraint metadata beyond DER.** This crate loads certificates
//!   as [`TrustAnchor`] values and does not surface per-anchor policy
//!   constraints (Mozilla's "websites trust bit", root-program-specific
//!   EKU restrictions, etc.). Callers needing that machinery layer it on
//!   top via `pkix-path::ValidationPolicy` and per-anchor filtering.

use std::io::Read as _;
use std::path::Path;
use std::{fs, io};

use der::Decode;
use x509_cert::Certificate;

/// Default upper bound for [`from_pem_file`] and [`from_der_file`].
///
/// Real-world trust bundles top out at a few hundred KB (Debian
/// `ca-certificates.crt` is ~200 KB; the full Mozilla CA list is
/// ~250 KB; minimal Alpine and Fedora bundles are smaller still).
/// 64 MiB is a forgiving cap: it admits any plausible trust store
/// while bounding the memory and time the loader will spend on a
/// pathological input (`/dev/zero`, an accidentally-symlinked log
/// file, an attacker-influenced env-var path).
///
/// Use [`from_pem_file_with_cap`] or [`from_der_file_with_cap`] to
/// pass a different limit explicitly.
pub const DEFAULT_FILE_SIZE_CAP: u64 = 64 * 1024 * 1024;

/// Open `path`, refuse files larger than `cap`, and read up to `cap`
/// bytes into a `Vec`.
///
/// Two-stage check: (1) `metadata().len()` short-circuits when the file
/// system already knows the size (fast rejection of multi-GB bundles);
/// (2) `Read::take(cap).read_to_end(...)` defends against TOCTOU on the
/// metadata (the file grows between metadata and read) and against
/// special files like `/dev/zero` (which report 0 bytes in metadata
/// but stream forever).
///
/// `cap + 1` is requested from `take` so the read fills exactly when
/// the file is at the limit and overshoots by one byte when it is
/// over — distinguishing "exactly cap bytes" (accepted) from "more
/// than cap bytes" (rejected).
fn read_file_capped(path: &Path, cap: u64) -> Result<Vec<u8>, Error> {
    // `io::ErrorKind::FileTooLarge` exists upstream (stabilised 1.83) but
    // the workspace MSRV is 1.73, so use `InvalidData` with an explicit
    // "exceeds N-byte cap" message. Callers that branch on `kind` get a
    // meaningful but non-confusing signal; callers that read `message`
    // get the precise cause.
    let file = fs::File::open(path)?;
    // Fast-path rejection on metadata. `metadata().len()` is 0 for
    // unsized streams (FIFOs, /dev/zero) so do not treat 0 as a
    // pre-passing signal — fall through to the take-bounded read.
    if let Ok(meta) = file.metadata() {
        if meta.len() > cap {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "trust-anchor file is {} bytes; exceeds {cap}-byte cap",
                    meta.len(),
                ),
            )
            .into());
        }
    }
    let mut bytes = Vec::new();
    let mut limited = file.take(cap.saturating_add(1));
    limited.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("trust-anchor file exceeds {cap}-byte cap during read"),
        )
        .into());
    }
    Ok(bytes)
}

pub use pkix_path::{DerError, TrustAnchor};

/// Boundary representation of a [`std::io::Error`] suitable for
/// inclusion in cache-friendly result types.
///
/// `std::io::Error` is intentionally not `Clone + PartialEq + Eq +
/// Serialize + Deserialize`, which prevents it from appearing in
/// [`Error`] under AGENTS.md non-negotiable #6 (cache-friendly result
/// types). `IoFailure` is the principled boundary: it captures the
/// [`io::ErrorKind`] and a rendered message string, dropping the
/// `os_error` integer code (low-value for callers) but gaining
/// `Clone`, `Eq`, and `Serialize`.
///
/// # Stability
///
/// `IoFailure` is `#[non_exhaustive]`; future minor releases may
/// surface additional context (`std::io::ErrorKind` grows
/// non-breakingly in the standard library).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct IoFailure {
    /// Kind of I/O error.
    ///
    /// `io::ErrorKind` is `Copy + Eq + Hash` but does not implement
    /// `serde::Serialize` / `Deserialize` (it is `#[non_exhaustive]`
    /// upstream and the standard library deliberately does not pick
    /// a wire form). We serialize it via its `Debug` output
    /// (`"NotFound"`, `"PermissionDenied"`, …) and parse the same
    /// set on the way back. Two known costs of this approach:
    ///
    /// 1. The `Debug` derive on `io::ErrorKind` is not a contractually
    ///    stable identifier. The current output happens to be the
    ///    variant name and has been since the type was added, but the
    ///    standard library makes no such guarantee. A future Rust
    ///    release could in principle change the format.
    /// 2. New `ErrorKind` variants (added non-breakingly by the
    ///    standard library) round-trip through an older consumer as
    ///    [`io::ErrorKind::Other`]. The message string is preserved;
    ///    only the typed `kind` is lossy across version skew.
    ///
    /// Use this field for human display and best-effort programmatic
    /// branching, not as a security-critical input.
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "io_error_kind_serde::serialize",
            deserialize_with = "io_error_kind_serde::deserialize"
        )
    )]
    pub kind: io::ErrorKind,
    /// Rendered message string from the original [`io::Error`].
    pub message: String,
}

impl IoFailure {
    /// Construct an `IoFailure` from a real [`io::Error`]. The
    /// message is captured via `Display`; the OS error code (if any)
    /// is dropped.
    #[must_use]
    pub fn from_io(e: &io::Error) -> Self {
        Self {
            kind: e.kind(),
            message: e.to_string(),
        }
    }
}

impl core::fmt::Display for IoFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for IoFailure {}

#[cfg(feature = "serde")]
mod io_error_kind_serde {
    //! `io::ErrorKind` does not implement `Serialize`/`Deserialize`
    //! (it is `#[non_exhaustive]` upstream and the standard library
    //! does not pick a wire form). We serialize via its `Debug`
    //! output (`"NotFound"`, `"PermissionDenied"`, …) and parse the
    //! same set on the way back. See [`crate::IoFailure::kind`] for
    //! the two known costs of this approach (Debug-derive is not a
    //! contractually stable identifier; unknown variants degrade to
    //! `ErrorKind::Other` on the consumer side).

    use serde::{Deserialize as _, Deserializer, Serializer};
    use std::io;

    pub fn serialize<S: Serializer>(
        kind: &io::ErrorKind,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        // `Debug` on `ErrorKind` produces the variant name verbatim
        // ("NotFound", "PermissionDenied", …) on every stdlib version
        // shipped to date; the format is not contractually stable but
        // is the only textual representation that round-trips through
        // the deserialize match below.
        s.serialize_str(&format!("{kind:?}"))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<io::ErrorKind, D::Error> {
        let s = String::deserialize(d)?;
        // Map a finite list of known variants. Anything else lands
        // in `ErrorKind::Other` — this is lossy: a producer on a
        // newer Rust that emitted (say) "FilesystemQuotaExceeded"
        // will reach a consumer on an older Rust as `Other`. The
        // accompanying `message` field is preserved, so the
        // diagnostic is not lost, only its typed form.
        Ok(match s.as_str() {
            "NotFound" => io::ErrorKind::NotFound,
            "PermissionDenied" => io::ErrorKind::PermissionDenied,
            "ConnectionRefused" => io::ErrorKind::ConnectionRefused,
            "ConnectionReset" => io::ErrorKind::ConnectionReset,
            "ConnectionAborted" => io::ErrorKind::ConnectionAborted,
            "NotConnected" => io::ErrorKind::NotConnected,
            "AddrInUse" => io::ErrorKind::AddrInUse,
            "AddrNotAvailable" => io::ErrorKind::AddrNotAvailable,
            "BrokenPipe" => io::ErrorKind::BrokenPipe,
            "AlreadyExists" => io::ErrorKind::AlreadyExists,
            "WouldBlock" => io::ErrorKind::WouldBlock,
            "InvalidInput" => io::ErrorKind::InvalidInput,
            "InvalidData" => io::ErrorKind::InvalidData,
            "TimedOut" => io::ErrorKind::TimedOut,
            "WriteZero" => io::ErrorKind::WriteZero,
            "Interrupted" => io::ErrorKind::Interrupted,
            "Unsupported" => io::ErrorKind::Unsupported,
            "UnexpectedEof" => io::ErrorKind::UnexpectedEof,
            "OutOfMemory" => io::ErrorKind::OutOfMemory,
            _ => io::ErrorKind::Other,
        })
    }
}

/// Errors returned by trust anchor loading.
///
/// `#[non_exhaustive]`: new variants may be added in minor releases.
///
/// # Cache-friendliness (AGENTS.md non-negotiable #6)
///
/// All variants are `Clone + PartialEq + Eq + Send + Sync`. The
/// `Pem`/`Der` variants carry an opaque [`DerError`] newtype (rather
/// than the upstream `der::Error`) so a future major-version bump in
/// the `der` crate cannot cascade into a semver break here. The `Io`
/// variant carries an [`IoFailure`] (rather than [`io::Error`]) so the
/// type can derive `Clone + Eq`; this drops the OS error code but
/// preserves [`io::ErrorKind`] and the rendered message.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Error {
    /// Filesystem I/O failed while reading a trust anchor file.
    Io(IoFailure),
    /// PEM decoding failed. The wrapped [`DerError`] preserves the
    /// underlying `der::pem` failure (missing end boundary, bad base64,
    /// unknown label) as a Display-renderable string.
    Pem(DerError),
    /// DER decoding failed for a certificate body.
    Der(DerError),
    /// The input contained no certificates.
    ///
    /// Returned by [`from_pem`] when no `-----BEGIN CERTIFICATE-----`
    /// marker is found at all (truly empty input, whitespace-only
    /// input, or non-PEM bytes — the loader cannot distinguish), and
    /// by [`from_der_iter`] when the supplied iterator yields zero
    /// items. An empty trust store is almost always a configuration
    /// mistake, so this is a hard error rather than `Ok(vec![])`.
    ///
    /// **Diagnostic limitation:** `from_pem` cannot distinguish "valid
    /// non-cert PEM" (e.g., a `PRIVATE KEY`-only file) from "non-PEM
    /// bytes" (a JPEG, a JSON config) from "empty input" — all three
    /// surface as `NoCertificates`. Callers needing that distinction
    /// must inspect the input themselves before calling.
    NoCertificates,
    /// One certificate in a multi-cert input was malformed.
    ///
    /// * `index` — 0-based position of the offending entry in the iterator
    ///   passed to [`from_der_iter`].
    /// * `source` — the underlying [`DerError`] from `x509-cert` or from
    ///   `NameConstraints` extension decoding. Returned both for entries
    ///   that failed to decode as `Certificate` and for entries that
    ///   decoded but whose `NameConstraints` extension had malformed DER.
    MalformedAnchor {
        /// 0-based position of the offending entry in the iterator.
        index: usize,
        /// Underlying DER-decode failure.
        source: DerError,
    },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "i/o error: {e}"),
            Self::Pem(e) => write!(f, "PEM decoding failed: {e}"),
            Self::Der(e) => write!(f, "DER decoding failed: {e}"),
            Self::NoCertificates => f.write_str(
                "input contained no certificates (no `-----BEGIN CERTIFICATE-----` marker; \
                 if the input is non-PEM the loader cannot tell)",
            ),
            Self::MalformedAnchor { index, source } => {
                write!(f, "malformed certificate at position {index}: {source}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Pem(e) | Self::Der(e) => Some(e),
            Self::MalformedAnchor { source, .. } => Some(source),
            Self::NoCertificates => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(IoFailure::from_io(&e))
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
///   `Certificate`, or one of its critical extensions (notably
///   `NameConstraints`) had malformed DER. See "`NameConstraints` strictness"
///   below.
/// * [`Error::NoCertificates`] — input contained zero PEM blocks.
///
/// # `NameConstraints` strictness
///
/// Trust anchors are decoded via [`TrustAnchor::try_from`], which fails closed
/// on a malformed `NameConstraints` extension (RFC 5280 §4.2: a critical
/// extension a relying party cannot process must cause rejection — and the
/// strongest form of "cannot process" is "cannot parse"). For a trust anchor
/// in particular, accepting an anchor whose `NameConstraints` could not be
/// parsed would be a fail-open: the deployment asserted "this root may only
/// sign for these names" via that extension, and silently dropping it would
/// remove the constraint at validation time.
pub fn from_pem(bytes: &[u8]) -> Result<Vec<TrustAnchor>, Error> {
    let bytes = strip_bom(bytes);
    // x509-cert 0.2.x's `load_pem_chain` panics on input that is empty after
    // its internal trailing-whitespace strip (subtract-with-overflow at
    // `certificate.rs:256`). Fixed upstream in RustCrypto/formats#1965 and
    // shipped in x509-cert 0.3.0-rc.2+; this guard can be removed once the
    // workspace bumps to x509-cert 0.3.x stable. Until then, defend against
    // the panic here so consumers see `Error::NoCertificates` instead. The
    // check is also correct for input with no `-----BEGIN CERTIFICATE-----`
    // markers at all.
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
    certs
        .into_iter()
        .map(|c| TrustAnchor::try_from(c).map_err(Error::Der))
        .collect()
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
/// `Certificate`, or if the certificate has a malformed `NameConstraints`
/// extension (see [`from_pem`] for rationale).
pub fn from_der(bytes: &[u8]) -> Result<TrustAnchor, Error> {
    let cert = Certificate::from_der(bytes).map_err(|e| Error::Der(DerError::new(e)))?;
    TrustAnchor::try_from(cert).map_err(Error::Der)
}

/// Parse an iterator of DER-encoded certificates into trust anchors.
///
/// This is the canonical adapter entry point. Adapter crates that obtain DER
/// bytes from a source (file read, HSM API, OS keychain API, cloud KMS,
/// network protocol) feed those bytes through this function. Centralising the
/// parsing here means every adapter inherits the same validation behaviour and
/// the same error reporting.
///
/// The iterator is consumed eagerly (not lazy) and decoded **fail-fast**:
/// on the first malformed entry the function returns
/// `Err(Error::MalformedAnchor { index, source })` where `index` is the
/// 0-based position of the failing item, and the rest of the iterator
/// is not polled. Callers wrapping a stream-backed iterator that needs
/// full draining for resource cleanup must drain it themselves.
///
/// # Errors
///
/// * [`Error::MalformedAnchor`] — carries the 0-based `index` of the entry
///   that failed plus a [`DerError`] `source` describing the underlying
///   `x509-cert` or `NameConstraints` decode failure. Returned for entries
///   that failed to decode as `Certificate` and for entries that decoded
///   but whose `NameConstraints` extension had malformed DER.
/// * [`Error::NoCertificates`] — the iterator yielded zero items.
///
/// See [`from_pem`] for the rationale behind fail-closed `NameConstraints`
/// handling.
pub fn from_der_iter<I, B>(iter: I) -> Result<Vec<TrustAnchor>, Error>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
{
    let anchors: Vec<TrustAnchor> = iter
        .into_iter()
        .enumerate()
        .map(|(index, bytes)| {
            let cert = Certificate::from_der(bytes.as_ref()).map_err(|e| {
                Error::MalformedAnchor {
                    index,
                    source: DerError::new(e),
                }
            })?;
            TrustAnchor::try_from(cert).map_err(|source| Error::MalformedAnchor { index, source })
        })
        .collect::<Result<_, _>>()?;
    if anchors.is_empty() {
        return Err(Error::NoCertificates);
    }
    Ok(anchors)
}

/// Load PEM-encoded trust anchors from a file.
///
/// Convenience wrapper around [`from_pem`]. The whole file is read
/// into memory; the read is bounded by [`DEFAULT_FILE_SIZE_CAP`]
/// (64 MiB) so a pathological path (`/dev/zero`, an
/// accidentally-symlinked log file, an oversized junk file) cannot
/// hang or OOM the process. Callers needing a different limit should
/// call [`from_pem_file_with_cap`].
///
/// # Errors
///
/// * [`Error::Io`] — the file could not be opened or read, or its
///   contents exceed [`DEFAULT_FILE_SIZE_CAP`] bytes (the wrapped
///   [`IoFailure::kind`] is [`io::ErrorKind::InvalidData`] in the
///   cap-exceeded case, and the message starts with "trust-anchor
///   file ... exceeds ...-byte cap"; MSRV 1.73 predates
///   `ErrorKind::FileTooLarge`).
/// * Any error returned by [`from_pem`].
pub fn from_pem_file(path: impl AsRef<Path>) -> Result<Vec<TrustAnchor>, Error> {
    from_pem_file_with_cap(path, DEFAULT_FILE_SIZE_CAP)
}

/// Load PEM-encoded trust anchors from a file with an explicit size cap.
///
/// Same shape as [`from_pem_file`] but accepts an explicit byte cap.
/// Pass [`u64::MAX`] to disable the cap entirely; doing so is the
/// caller's responsibility — see [`DEFAULT_FILE_SIZE_CAP`] for the
/// rationale behind the default.
///
/// # Errors
///
/// Same as [`from_pem_file`], substituting `cap` for the default.
pub fn from_pem_file_with_cap(
    path: impl AsRef<Path>,
    cap: u64,
) -> Result<Vec<TrustAnchor>, Error> {
    let bytes = read_file_capped(path.as_ref(), cap)?;
    from_pem(&bytes)
}

/// Load a single DER-encoded trust anchor from a file.
///
/// Convenience wrapper around [`from_der`]. The read is bounded by
/// [`DEFAULT_FILE_SIZE_CAP`]; pass an explicit cap via
/// [`from_der_file_with_cap`] for unusual deployments.
///
/// # Errors
///
/// * [`Error::Io`] — the file could not be opened or read, or its
///   contents exceed [`DEFAULT_FILE_SIZE_CAP`] bytes (the wrapped
///   [`IoFailure::kind`] is [`io::ErrorKind::InvalidData`] in the
///   cap-exceeded case; see [`from_pem_file`] for the MSRV
///   rationale).
/// * Any error returned by [`from_der`].
pub fn from_der_file(path: impl AsRef<Path>) -> Result<TrustAnchor, Error> {
    from_der_file_with_cap(path, DEFAULT_FILE_SIZE_CAP)
}

/// Load a single DER-encoded trust anchor from a file with an
/// explicit size cap.
///
/// Same shape as [`from_der_file`] but accepts an explicit byte cap.
/// Pass [`u64::MAX`] to disable the cap entirely.
///
/// # Errors
///
/// Same as [`from_der_file`], substituting `cap` for the default.
pub fn from_der_file_with_cap(
    path: impl AsRef<Path>,
    cap: u64,
) -> Result<TrustAnchor, Error> {
    let bytes = read_file_capped(path.as_ref(), cap)?;
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
        ErrorKind::Pem(_) => Error::Pem(DerError::new(e)),
        _ => Error::Der(DerError::new(e)),
    }
}

// ---------------------------------------------------------------------------
// Send + Sync compile-time assertions (AGENTS.md non-negotiable #6, PKIX-2l0v.2)
// ---------------------------------------------------------------------------
//
// `TrustAnchor` is re-exported from `pkix-path`; the assertion in `pkix-path`
// covers it. Here we only need to pin `pkix_truststore::Error` itself.

const _: fn() = || {
    fn _assert_send_sync<T: Send + Sync>() {}
    _assert_send_sync::<Error>();
};

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
            Err(Error::MalformedAnchor { index, source: _ }) => assert_eq!(index, 0),
            other => panic!("expected MalformedAnchor {{ index: 0, .. }}, got {other:?}"),
        }
    }
}
