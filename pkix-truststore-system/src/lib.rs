//! Loads trust anchors from where the operating system keeps them, and
//! hands them to [`pkix-truststore`](pkix_truststore) to become
//! [`TrustAnchor`] values. The `rustls-native-certs` analogue for the
//! `pkix-truststore` ecosystem.
//!
//! ```no_run
//! let anchors = pkix_truststore_system::from_system()?;
//! // hand `&anchors` to pkix_path::validate_path / pkix_chain::verify_chain
//! # Ok::<(), pkix_truststore_system::Error>(())
//! ```
//!
//! # Design: portable first, per-OS second
//!
//! Nothing in this workspace is nailed to an operating system, and this
//! crate is the one place allowed to look at one. It is arranged so that
//! the portable path carries the weight and the OS-specific paths are
//! additive:
//!
//! - **The default backend reads PEM bundles and certificate
//!   directories.** That is not a Linux feature. It is how trust is
//!   exposed on Linux, Android, the BSDs, illumos, inside every
//!   container image, and on macOS whenever a bundle has been installed
//!   by Homebrew, MacPorts or Nix. It needs no FFI and no platform
//!   crate, so it compiles and is testable everywhere.
//! - **`SSL_CERT_FILE` and `SSL_CERT_DIR` are consulted first.** These
//!   are the OpenSSL convention and the only thing that works reliably
//!   in containers, in Nix and Guix builds, and in any sandbox that
//!   relocates the store. A caller who sets them has made a decision,
//!   and it is honoured over anything found on disk.
//! - **Keychain and CryptoAPI are per-target backends** layered on top,
//!   for the platforms whose canonical store is not a file. They are
//!   selected by target rather than behind a feature, so a macOS build
//!   gets the Keychain reader without opting in and a Linux build
//!   compiles neither.
//!
//! Linux is the primary target, which is why the portable reader is the
//! default rather than a fallback.
//!
//! # Why this is not just `from_pem_file`
//!
//! [`pkix_truststore::from_pem_file`] is one call, and a consumer who
//! knows their deployment can use it directly. Two things make a system
//! adapter worth having anyway.
//!
//! **"The well-known path" is not one path.** It is
//! `/etc/ssl/certs/ca-certificates.crt` on Debian, Ubuntu, Alpine and
//! Gentoo; `/etc/pki/tls/certs/ca-bundle.crt` on RHEL and Fedora;
//! `/etc/ssl/ca-bundle.pem` on SUSE; `/etc/ssl/cert.pem` on Alpine and
//! OpenBSD; `/usr/local/share/certs/ca-root-nss.crt` on FreeBSD; a
//! directory on Android. A consumer who hard-codes one of them has
//! written a program that works on their distribution and fails on the
//! next. [`candidate_bundle_files`] and [`candidate_cert_dirs`] are the
//! list, and they are public so it can be inspected rather than guessed
//! at.
//!
//! **A system bundle is not all-or-nothing.** `from_pem_file` fails the
//! whole load if any certificate in the file fails to convert, which is
//! the right behaviour for a file a consumer curated and the wrong
//! behaviour for 150 certificates shipped by a distribution. One odd
//! encoding would leave a program with no trust anchors rather than 149,
//! which fails every connection instead of a few. This crate converts
//! entries individually and keeps the ones that work, and
//! [`from_system_with_report`] says how many it had to drop so the
//! degradation is visible rather than silent.
//!
//! # Errors
//!
//! [`Error::NoTrustStore`] carries every location that was searched, so
//! a deployment that has no store says which paths were tried rather
//! than reporting a bare not-found.
//!
//! # Platform backend status
//!
//! The macOS and Windows backends are compiled and run on every change
//! to this crate, on `macos-latest` and `windows-latest` runners. What
//! that establishes:
//!
//! - **They compile and type-check**, with warnings denied, including
//!   their test targets.
//! - **They answer.** [`from_system`] reports
//!   [`Source::Native`] and returns a non-empty anchor set on both, read
//!   through Keychain trust settings and through CryptoAPI's `ROOT`
//!   store respectively. A skipped assertion is not mistaken for a
//!   passing one: the suite prints why it skipped and the runner log is
//!   read for those lines.
//!
//! What is still not established:
//!
//! - **iOS and Android are unverified.** iOS shares this crate's Apple
//!   path but not its entitlements, and no runner exists for either, so
//!   neither has been compiled or run.
//! - **The Windows backend does not consult the `DISALLOWED` store**, so
//!   an administrator's explicit distrust is not subtracted. That is
//!   documented in its module. The Apple backend does honour `Deny`.
//! - **Anchor sets are unmeasured.** A runner's trust store is not a
//!   user's, so no claim is made about how many anchors either backend
//!   returns, in what order, or which it rejects — only that the call
//!   works and returns some.
//!
//! The portable reader runs on those targets too, so a consumer who
//! wants to decide for themselves rather than rely on the platform can
//! set [`SSL_CERT_FILE`] and get the file-based path on any OS.
//!
//! # Features
//!
//! - `serde` — propagates to [`pkix-truststore`](pkix_truststore) so
//!   [`Error`] and the re-exported [`IoFailure`] gain the derives.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

// Platform backends. Selected by target rather than by feature, so a
// consumer gets their OS's store without opting in and never compiles
// another OS's. That also puts them out of reach of every Linux build,
// which is why they have a CI workflow of their own; see "Platform
// backend status" above for what it does and does not establish.
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod apple;
#[cfg(target_os = "windows")]
mod windows;

use std::path::{Path, PathBuf};

// Re-exported rather than reinvented. An adapter crate needs an
// io-error shape in its own error type, and `pkix-truststore` already
// defines one that satisfies the workspace's cache-friendly
// requirements (Clone + Eq + Send + Sync, serde under the feature).
// Declaring a second, incompatible `IoFailure` here would force any
// consumer handling both crates' errors to convert between two types
// that mean the same thing.
pub use pkix_truststore::{DerError, IoFailure, TrustAnchor};

/// PEM bundle files to try, in order.
///
/// Ordered so that the most specific and most widely deployed paths come
/// first. The list is public because a consumer debugging a deployment
/// should be able to print what was searched rather than read this
/// crate's source.
const BUNDLE_FILES: &[&str] = &[
    // Debian, Ubuntu, Alpine, Gentoo, Arch, and most container images.
    "/etc/ssl/certs/ca-certificates.crt",
    // RHEL, CentOS, Fedora, Amazon Linux.
    "/etc/pki/tls/certs/ca-bundle.crt",
    // Fedora/RHEL p11-kit extracted bundle; present when the above is a
    // symlink into it, and sometimes when it is not.
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    // openSUSE, SLES.
    "/etc/ssl/ca-bundle.pem",
    // Alpine, OpenBSD, NetBSD, and Homebrew/MacPorts on macOS.
    "/etc/ssl/cert.pem",
    // FreeBSD (ca_root_nss port).
    "/usr/local/share/certs/ca-root-nss.crt",
    // Older RHEL layouts.
    "/etc/ssl/certs/ca-bundle.crt",
    // illumos / Solaris.
    "/etc/certs/ca-certificates.crt",
];

/// Certificate directories to try, in order, when no bundle file is
/// found.
///
/// A directory holds one certificate per file. Android's store is only
/// ever a directory, which is why this path exists rather than being an
/// afterthought.
const CERT_DIRS: &[&str] = &[
    // Android (AOSP, pre-Conscrypt-only devices).
    "/system/etc/security/cacerts",
    // Debian/Ubuntu also populate this as individual files alongside the
    // bundle; RHEL uses the pki path.
    "/etc/ssl/certs",
    "/etc/pki/tls/certs",
];

/// Environment variable naming a single PEM bundle, per the OpenSSL
/// convention.
pub const SSL_CERT_FILE: &str = "SSL_CERT_FILE";

/// Environment variable naming a directory of certificates, per the
/// OpenSSL convention.
pub const SSL_CERT_DIR: &str = "SSL_CERT_DIR";

/// Largest bundle this crate will read, in bytes.
///
/// A system bundle is a few hundred kilobytes; 8 MiB is far above any
/// real one while still refusing to read an arbitrarily large file that
/// happens to sit at one of these paths.
pub const MAX_BUNDLE_BYTES: u64 = 8 * 1024 * 1024;

/// Where the anchors came from.
///
/// Returned by [`from_system_with_report`] so a deployment can log which
/// store it actually used, which is the first thing worth knowing when
/// trust behaves unexpectedly between two machines.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Source {
    /// A bundle named by [`SSL_CERT_FILE`].
    EnvBundle(PathBuf),
    /// A directory named by [`SSL_CERT_DIR`].
    EnvDir(PathBuf),
    /// One of [`candidate_bundle_files`].
    Bundle(PathBuf),
    /// One of [`candidate_cert_dirs`].
    Dir(PathBuf),
    /// The operating system's own trust store, read through its API
    /// rather than from a file.
    ///
    /// Carries no path because there is no file to name.
    Native(NativeStore),
}

/// Which platform store [`Source::Native`] refers to.
///
/// A typed discriminant rather than a string: it costs nothing, it
/// cannot be misspelled by a caller matching on it, and it keeps
/// [`Source`] `Copy`-friendly and serde-clean, which a `&'static str`
/// does not — a borrowed string cannot satisfy `Deserialize`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum NativeStore {
    /// Keychain trust settings, across the System, Admin and User
    /// domains (macOS, iOS).
    MacosKeychain,
    /// The CryptoAPI `ROOT` stores, local-machine and current-user
    /// (Windows).
    WindowsRootStore,
}

impl core::fmt::Display for NativeStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::MacosKeychain => "macOS Keychain trust settings",
            Self::WindowsRootStore => "Windows ROOT certificate stores",
        })
    }
}

impl core::fmt::Display for Source {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EnvBundle(p) => write!(f, "{SSL_CERT_FILE}={}", p.display()),
            Self::EnvDir(p) => write!(f, "{SSL_CERT_DIR}={}", p.display()),
            Self::Bundle(p) => write!(f, "bundle {}", p.display()),
            Self::Dir(p) => write!(f, "directory {}", p.display()),
            Self::Native(store) => write!(f, "native store: {store}"),
        }
    }
}

/// What a load found, beyond the anchors themselves.
///
/// The `skipped` count is the point of this type. A system store is not
/// curated by the consumer, so an entry that will not convert is an
/// ordinary event rather than a reason to fail; reporting it is what
/// keeps that from being a silent loss.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct LoadReport {
    /// Which store the anchors came from.
    pub source: Source,
    /// How many certificates converted into anchors.
    pub loaded: usize,
    /// How many entries were present but could not be converted.
    ///
    /// Non-zero is not an error. It usually means a distribution shipped
    /// something this parser does not accept — an unusual name encoding,
    /// a certificate that is not a CA. Worth logging once at startup;
    /// worth investigating if it is most of the store.
    pub skipped: usize,
}

/// Errors from loading a platform trust store.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// No trust store was found at any searched location.
    ///
    /// Carries every path tried, in order, so the message names them.
    NoTrustStore {
        /// Locations searched, in the order they were tried.
        searched: Vec<PathBuf>,
    },
    /// A store named by an environment variable could not be used.
    ///
    /// Distinct from [`Error::NoTrustStore`] on purpose: a caller who
    /// set [`SSL_CERT_FILE`] expressed an intent, and quietly falling
    /// back to a different store would hand them a trust set they did
    /// not choose.
    EnvStoreUnusable {
        /// The variable that named it.
        variable: &'static str,
        /// What it named.
        path: PathBuf,
        /// Why it could not be used.
        source: IoFailure,
    },
    /// A store was found but yielded no usable anchor.
    ///
    /// Carries where it was and how many entries were rejected, because
    /// "the file exists and is entirely unusable" is a different
    /// operational problem from "there is no file".
    StoreEmpty {
        /// Where the store was.
        source: Source,
        /// How many entries were present but unconvertible.
        skipped: usize,
    },
    /// Reading a store failed.
    Io(IoFailure),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoTrustStore { searched } => {
                write!(
                    f,
                    "no system trust store found; searched {} location(s)",
                    searched.len()
                )?;
                for p in searched {
                    write!(f, "\n  {}", p.display())?;
                }
                Ok(())
            }
            Self::EnvStoreUnusable { variable, path, .. } => {
                write!(
                    f,
                    "{variable} names {}, which could not be read",
                    path.display()
                )
            }
            Self::StoreEmpty { source, skipped } => write!(
                f,
                "{source} held no usable trust anchor ({skipped} entr(y|ies) rejected)"
            ),
            Self::Io(_) => f.write_str("reading the system trust store failed"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::EnvStoreUnusable { source, .. } | Self::Io(source) => Some(source),
            Self::NoTrustStore { .. } | Self::StoreEmpty { .. } => None,
        }
    }
}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// The PEM bundle paths [`from_system`] will try, in order.
pub fn candidate_bundle_files() -> impl Iterator<Item = &'static Path> {
    BUNDLE_FILES.iter().map(Path::new)
}

/// The certificate directories [`from_system`] will try, in order.
pub fn candidate_cert_dirs() -> impl Iterator<Item = &'static Path> {
    CERT_DIRS.iter().map(Path::new)
}

/// Load trust anchors from the platform trust store.
///
/// Discovery order is [`SSL_CERT_FILE`], [`SSL_CERT_DIR`],
/// [`candidate_bundle_files`], then [`candidate_cert_dirs`]; the first
/// location that yields at least one anchor wins.
///
/// Entries that cannot be converted are skipped rather than failing the
/// load; use [`from_system_with_report`] to find out how many. See the
/// crate documentation for why.
///
/// # Errors
///
/// - [`Error::EnvStoreUnusable`] if [`SSL_CERT_FILE`] or
///   [`SSL_CERT_DIR`] is set but unreadable. This does not fall through
///   to the search: an explicitly configured store that is broken is an
///   error, not a reason to use a different one.
/// - [`Error::StoreEmpty`] if a store was found and every entry in it
///   was rejected.
/// - [`Error::NoTrustStore`] if nothing was found, listing what was
///   searched.
pub fn from_system() -> Result<Vec<TrustAnchor>> {
    from_system_with_report().map(|(anchors, _)| anchors)
}

/// As [`from_system`], and also report which store was used and how many
/// entries were skipped.
///
/// # Errors
///
/// As [`from_system`].
pub fn from_system_with_report() -> Result<(Vec<TrustAnchor>, LoadReport)> {
    let mut searched: Vec<PathBuf> = Vec::new();

    // 1. An explicitly configured store wins, and a broken one is an
    //    error rather than a reason to look elsewhere.
    if let Some(path) = env_path(SSL_CERT_FILE) {
        searched.push(path.clone());
        let bytes = std::fs::read(&path).map_err(|e| Error::EnvStoreUnusable {
            variable: SSL_CERT_FILE,
            path: path.clone(),
            source: IoFailure::from_io(&e),
        })?;
        return finish(Source::EnvBundle(path), anchors_from_pem(&bytes));
    }
    if let Some(path) = env_path(SSL_CERT_DIR) {
        searched.push(path.clone());
        let found = read_cert_dir(&path).map_err(|e| Error::EnvStoreUnusable {
            variable: SSL_CERT_DIR,
            path: path.clone(),
            source: IoFailure::from_io(&e),
        })?;
        return finish(Source::EnvDir(path), found);
    }

    // 2. The platform's own store, where it has one that is not a file.
    //    After the environment variables, because an operator who set
    //    them has overridden the platform deliberately; before the file
    //    search, because on these platforms a bundle on disk is a
    //    third-party addition rather than the system's answer.
    if let Some((found, store)) = native_store() {
        if !found.anchors.is_empty() {
            return finish(Source::Native(store), found);
        }
    }

    // 3. Well-known bundles.
    for path in candidate_bundle_files() {
        searched.push(path.to_path_buf());
        let Ok(bytes) = read_capped(path) else {
            continue;
        };
        let found = anchors_from_pem(&bytes);
        if !found.anchors.is_empty() {
            return finish(Source::Bundle(path.to_path_buf()), found);
        }
    }

    // 4. Well-known directories.
    for dir in candidate_cert_dirs() {
        searched.push(dir.to_path_buf());
        let Ok(found) = read_cert_dir(dir) else {
            continue;
        };
        if !found.anchors.is_empty() {
            return finish(Source::Dir(dir.to_path_buf()), found);
        }
    }

    Err(Error::NoTrustStore { searched })
}

/// Load trust anchors from one PEM bundle, skipping entries that cannot
/// be converted.
///
/// The lenient counterpart to [`pkix_truststore::from_pem_file`], for a
/// bundle the caller did not curate. Useful when a deployment knows its
/// store's location and wants the skip-and-report behaviour anyway.
///
/// # Errors
///
/// [`Error::Io`] if the file cannot be read, or [`Error::StoreEmpty`] if
/// no entry in it converted.
pub fn from_bundle_file(path: impl AsRef<Path>) -> Result<(Vec<TrustAnchor>, LoadReport)> {
    let path = path.as_ref();
    let bytes = read_capped(path).map_err(|e| Error::Io(IoFailure::from_io(&e)))?;
    finish(Source::Bundle(path.to_path_buf()), anchors_from_pem(&bytes))
}

/// Load trust anchors from a directory holding one certificate per file.
///
/// # Errors
///
/// [`Error::Io`] if the directory cannot be listed, or
/// [`Error::StoreEmpty`] if nothing in it converted.
pub fn from_cert_dir(path: impl AsRef<Path>) -> Result<(Vec<TrustAnchor>, LoadReport)> {
    let path = path.as_ref();
    let found = read_cert_dir(path).map_err(|e| Error::Io(IoFailure::from_io(&e)))?;
    finish(Source::Dir(path.to_path_buf()), found)
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// Read the platform's native trust store, if this target has one.
///
/// `None` on every target without a native store, and also when the
/// store exists but could not be opened — a sandboxed macOS process
/// without Keychain entitlements, say — so that the file search still
/// gets its turn rather than the load failing outright.
fn native_store() -> Option<(Found, NativeStore)> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        return apple::load().map(|f| (f, NativeStore::MacosKeychain));
    }
    #[cfg(target_os = "windows")]
    {
        return windows::load().map(|f| (f, NativeStore::WindowsRootStore));
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "windows")))]
    None
}

/// Anchors plus the count of entries that would not convert.
pub(crate) struct Found {
    pub(crate) anchors: Vec<TrustAnchor>,
    pub(crate) skipped: usize,
}

fn finish(source: Source, found: Found) -> Result<(Vec<TrustAnchor>, LoadReport)> {
    if found.anchors.is_empty() {
        return Err(Error::StoreEmpty {
            source,
            skipped: found.skipped,
        });
    }
    let report = LoadReport {
        source,
        loaded: found.anchors.len(),
        skipped: found.skipped,
    };
    Ok((found.anchors, report))
}

/// A set environment variable, ignoring an empty value.
///
/// An empty `SSL_CERT_FILE=` is how a shell unsets a variable it cannot
/// remove, and treating it as a path would turn that into an error.
fn env_path(var: &str) -> Option<PathBuf> {
    let v = std::env::var_os(var)?;
    if v.is_empty() {
        return None;
    }
    Some(PathBuf::from(v))
}

fn read_capped(path: &Path) -> std::io::Result<Vec<u8>> {
    let meta = std::fs::metadata(path)?;
    if !meta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    if meta.len() > MAX_BUNDLE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "trust store larger than MAX_BUNDLE_BYTES",
        ));
    }
    std::fs::read(path)
}

/// Convert a PEM bundle one entry at a time.
///
/// `pkix_truststore::from_pem` is all-or-nothing by design, which is
/// right for a curated file. Splitting first and converting each entry
/// through that same vetted path keeps one bad certificate from
/// discarding the rest of a distribution's store, without
/// reimplementing any PEM or DER handling here.
fn anchors_from_pem(bytes: &[u8]) -> Found {
    const END: &[u8] = b"-----END CERTIFICATE-----";
    let mut anchors = Vec::new();
    let mut skipped = 0usize;

    let mut rest = bytes;
    while let Some(pos) = find(rest, END) {
        let (entry, tail) = rest.split_at(pos + END.len());
        rest = tail;
        if find(entry, b"-----BEGIN CERTIFICATE-----").is_none() {
            continue;
        }
        let mut pem = entry.to_vec();
        pem.push(b'\n');
        match pkix_truststore::from_pem(&pem) {
            Ok(mut a) if !a.is_empty() => anchors.append(&mut a),
            _ => skipped += 1,
        }
    }
    Found { anchors, skipped }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Read every file in a directory as a certificate.
///
/// Both PEM and DER are accepted, because a certificate directory holds
/// whichever the platform's tooling wrote. Subdirectories are not
/// walked: no platform nests its store, and walking would turn a
/// misconfigured `SSL_CERT_DIR` into an unbounded traversal.
fn read_cert_dir(dir: &Path) -> std::io::Result<Found> {
    let mut anchors = Vec::new();
    let mut skipped = 0usize;

    for entry in std::fs::read_dir(dir)? {
        let Ok(entry) = entry else {
            skipped += 1;
            continue;
        };
        let path = entry.path();
        // `read_capped` rejects anything that is not a regular file,
        // which also covers the dangling symlinks these directories
        // accumulate.
        let Ok(bytes) = read_capped(&path) else {
            continue;
        };
        if find(&bytes, b"-----BEGIN CERTIFICATE-----").is_some() {
            let mut found = anchors_from_pem(&bytes);
            if found.anchors.is_empty() {
                skipped += 1;
            } else {
                anchors.append(&mut found.anchors);
                skipped += found.skipped;
            }
        } else {
            match pkix_truststore::from_der(&bytes) {
                Ok(a) => anchors.push(a),
                Err(_) => skipped += 1,
            }
        }
    }
    Ok(Found { anchors, skipped })
}

const _: fn() = || {
    fn _assert_send_sync<T: Send + Sync>() {}
    _assert_send_sync::<Error>();
    _assert_send_sync::<LoadReport>();
    _assert_send_sync::<Source>();
    _assert_send_sync::<NativeStore>();
};
