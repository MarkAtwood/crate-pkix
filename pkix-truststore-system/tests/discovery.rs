//! Platform trust store discovery.
//!
//! The tests that matter here are the ones about *degradation*: a system
//! store is not curated by the consumer, so the interesting behaviour is
//! what happens when part of it is unusable, when an operator has
//! redirected it, and when it is absent. A test that only loads a good
//! bundle would pass on any implementation, including one that fails the
//! whole load over a single bad certificate.
//!
//! Run: cargo test -p pkix-truststore-system

use std::path::{Path, PathBuf};

use pkix_truststore_system::{
    candidate_bundle_files, candidate_cert_dirs, from_bundle_file, from_cert_dir, Error, Source,
    SSL_CERT_DIR, SSL_CERT_FILE,
};

/// A real CA certificate, taken from the workspace's own fixtures so the
/// test does not depend on the host having a trust store.
fn good_pem() -> Vec<u8> {
    let der = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../pkix-path/tests/pkits/certs/TrustAnchorRootCertificate.crt"
    ))
    .expect("PKITS anchor fixture");
    pem_wrap(&der)
}

fn pem_wrap(der: &[u8]) -> Vec<u8> {
    // Minimal PEM encoder: the crate under test parses PEM, so building
    // the input with it would be circular.
    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    let mut line = 0;
    for chunk in der.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        let idx = [(n >> 18) & 63, (n >> 12) & 63, (n >> 6) & 63, n & 63];
        for (i, ix) in idx.iter().enumerate() {
            if i <= chunk.len() {
                out.push(B64[*ix as usize] as char);
            } else {
                out.push('=');
            }
        }
        line += 4;
        if line >= 64 {
            out.push('\n');
            line = 0;
        }
    }
    if line != 0 {
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out.into_bytes()
}

fn tmpdir(name: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!(
        "pkix-truststore-system-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("create temp dir");
    base
}

fn write(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("write fixture");
}

// ---------------------------------------------------------------------------
// Degradation: the reason this crate exists rather than from_pem_file
// ---------------------------------------------------------------------------

/// One unusable entry must not discard the rest of the store.
///
/// `pkix_truststore::from_pem` is all-or-nothing, which is correct for a
/// file the consumer curated and wrong for a bundle shipped by a
/// distribution: a single odd encoding would leave a program with no
/// trust anchors instead of all-but-one, failing every connection rather
/// than none. The skipped entry still has to be reported, or the loss is
/// silent.
#[test]
fn a_bad_entry_is_skipped_and_counted_not_fatal() {
    let dir = tmpdir("mixed");
    let path = dir.join("bundle.pem");

    let mut bundle = good_pem();
    // A well-formed PEM envelope whose contents are not a certificate.
    bundle.extend_from_slice(b"-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n");
    bundle.extend_from_slice(&good_pem());
    write(&path, &bundle);

    let (anchors, report) = from_bundle_file(&path).expect("the good entries must survive");
    assert_eq!(anchors.len(), 2, "both good certificates should load");
    assert_eq!(report.loaded, 2);
    assert_eq!(
        report.skipped, 1,
        "the bad entry must be counted, not hidden"
    );
    assert_eq!(report.source, Source::Bundle(path));
}

/// A store that exists but is entirely unusable is an error, and says so
/// distinctly from "there is no store".
///
/// Those are different operational problems: the first is a corrupt or
/// unexpected file at a path that should hold trust, the second is a
/// deployment that never had one.
#[test]
fn a_wholly_unusable_store_is_distinct_from_a_missing_one() {
    let dir = tmpdir("empty");
    let path = dir.join("bundle.pem");
    write(
        &path,
        b"-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n",
    );

    match from_bundle_file(&path) {
        Err(Error::StoreEmpty { source, skipped }) => {
            assert_eq!(source, Source::Bundle(path));
            assert_eq!(skipped, 1);
        }
        other => panic!("expected StoreEmpty, got {other:?}"),
    }
}

/// A PEM file with no certificate envelope at all yields StoreEmpty with
/// nothing skipped — there was nothing to skip.
#[test]
fn a_file_with_no_certificates_reports_nothing_skipped() {
    let dir = tmpdir("nocerts");
    let path = dir.join("bundle.pem");
    write(&path, b"# just a comment, no PEM here\n");

    match from_bundle_file(&path) {
        Err(Error::StoreEmpty { skipped, .. }) => assert_eq!(skipped, 0),
        other => panic!("expected StoreEmpty, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Certificate directories
// ---------------------------------------------------------------------------

/// A directory store accepts both PEM and DER files, because a
/// certificate directory holds whichever the platform's tooling wrote.
#[test]
fn a_cert_dir_accepts_both_pem_and_der() {
    let dir = tmpdir("certdir");
    let der = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../pkix-path/tests/pkits/certs/TrustAnchorRootCertificate.crt"
    ))
    .expect("fixture");

    write(&dir.join("anchor.pem"), &good_pem());
    write(&dir.join("anchor.der"), &der);
    // Junk that must be skipped rather than fatal.
    write(&dir.join("README"), b"not a certificate\n");

    let (anchors, report) = from_cert_dir(&dir).expect("the directory holds usable anchors");
    assert_eq!(anchors.len(), 2, "one PEM and one DER should both load");
    assert_eq!(report.skipped, 1, "the README must be counted as skipped");
    assert_eq!(report.source, Source::Dir(dir));
}

/// A subdirectory is not walked. No platform nests its store, and
/// walking would turn a misconfigured `SSL_CERT_DIR` into an unbounded
/// traversal of whatever it points at.
#[test]
fn a_cert_dir_does_not_recurse() {
    let dir = tmpdir("norecurse");
    let nested = dir.join("nested");
    std::fs::create_dir_all(&nested).expect("mkdir");
    write(&nested.join("anchor.pem"), &good_pem());
    write(&dir.join("anchor.pem"), &good_pem());

    let (anchors, _) = from_cert_dir(&dir).expect("the top level has one anchor");
    assert_eq!(
        anchors.len(),
        1,
        "only the top-level certificate should load, not the nested one"
    );
}

#[test]
fn a_missing_directory_is_an_io_error_not_a_panic() {
    let missing = std::env::temp_dir().join("pkix-truststore-system-definitely-absent");
    let _ = std::fs::remove_dir_all(&missing);
    assert!(matches!(from_cert_dir(&missing), Err(Error::Io(_))));
}

// ---------------------------------------------------------------------------
// The candidate lists
// ---------------------------------------------------------------------------

/// The searched locations are public and rooted, so a deployment can
/// print what was tried instead of reading this crate's source.
#[test]
fn the_candidate_lists_are_inspectable_and_absolute() {
    let bundles: Vec<&Path> = candidate_bundle_files().collect();
    let dirs: Vec<&Path> = candidate_cert_dirs().collect();

    assert!(
        bundles.len() >= 5,
        "the point of the list is covering distributions; got {bundles:?}"
    );
    assert!(!dirs.is_empty());
    for p in bundles.iter().chain(dirs.iter()) {
        // Rooted at `/`, checked literally rather than with
        // `Path::is_absolute`. That predicate is platform-dependent: on
        // Windows it wants a prefix like `C:\` and calls every one of
        // these paths relative, which failed this test there. These are
        // Unix filesystem locations by construction — the Windows store
        // is reached through CryptoAPI, not through this list — so the
        // property to assert is the one that does not change with the
        // host.
        assert!(
            p.starts_with("/"),
            "{p:?} must be rooted, so NoTrustStore names a location \
             that cannot be read two ways"
        );
    }

    // The two most widely deployed layouts, named explicitly so a
    // reordering that drops one is caught.
    assert!(bundles.contains(&Path::new("/etc/ssl/certs/ca-certificates.crt")));
    assert!(bundles.contains(&Path::new("/etc/pki/tls/certs/ca-bundle.crt")));
    // Android's store is a directory and only a directory.
    assert!(dirs.contains(&Path::new("/system/etc/security/cacerts")));
}

/// No duplicate candidates: a repeated path would be searched twice and
/// reported twice in `NoTrustStore`.
#[test]
fn the_candidate_lists_have_no_duplicates() {
    for list in [
        candidate_bundle_files().collect::<Vec<_>>(),
        candidate_cert_dirs().collect::<Vec<_>>(),
    ] {
        let mut seen = list.clone();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), list.len(), "duplicate entry in {list:?}");
    }
}

// ---------------------------------------------------------------------------
// This host
// ---------------------------------------------------------------------------

/// Whatever this machine has, `from_system` must agree with reading its
/// bundle directly — same anchor count, nothing silently dropped.
///
/// Skipped rather than failed where there is no store, so the suite still
/// passes in a scratch container. The assertion only runs where there is
/// something to assert about.
#[test]
fn from_system_agrees_with_reading_the_host_bundle_directly() {
    // Env overrides would make this compare two different stores.
    if std::env::var_os(SSL_CERT_FILE).is_some() || std::env::var_os(SSL_CERT_DIR).is_some() {
        eprintln!("skipped: {SSL_CERT_FILE}/{SSL_CERT_DIR} set in this environment");
        return;
    }
    let Some(bundle) = candidate_bundle_files().find(|p| p.is_file()) else {
        eprintln!("skipped: this host has no bundle at any candidate path");
        return;
    };

    let (ours, report) =
        pkix_truststore_system::from_system_with_report().expect("the host has a store");

    // A file on disk is only the system's answer where the platform has
    // no store of its own. On macOS the Keychain is consulted first and
    // wins — deliberately, see the precedence in `from_system_with_report`
    // — and a macOS runner does have a bundle at a candidate path, which
    // is how this test failed there. Reading the Keychain and a Homebrew
    // bundle are two different stores, so there is nothing to compare;
    // the native backend has its own coverage.
    let Source::Bundle(used) = &report.source else {
        eprintln!(
            "skipped: this platform answered from {:?} rather than a candidate file",
            report.source
        );
        return;
    };
    assert_eq!(
        used, bundle,
        "the first existing candidate should be the one used"
    );

    // The strict loader is the oracle: where it succeeds, the lenient one
    // must produce exactly the same number of anchors. A mismatch would
    // mean the per-entry split is losing or inventing certificates.
    if let Ok(strict) = pkix_truststore::from_pem_file(bundle) {
        assert_eq!(
            ours.len(),
            strict.len(),
            "lenient and strict loaders disagree on {}",
            bundle.display()
        );
        assert_eq!(
            report.skipped, 0,
            "nothing should be skipped in a clean bundle"
        );
    }
    assert!(!ours.is_empty());
}

/// On a platform whose canonical store is not a file, the native backend
/// must be the one that answers, and it must come back with anchors.
///
/// This is the only test that exercises the Keychain and CryptoAPI
/// readers, and it exists because the test above stops being able to:
/// where a native store wins there is no candidate file to compare it
/// against, so that test skips and would leave the FFI unasserted.
///
/// Compiled only where there is a native backend. On Linux there is
/// none, so there is nothing here to assert and `from_system` is covered
/// by the file-based tests instead.
#[test]
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "windows"))]
fn the_native_store_answers_and_returns_anchors() {
    // Set deliberately, these override the platform, and then the
    // native backend is correctly not consulted at all.
    if std::env::var_os(SSL_CERT_FILE).is_some() || std::env::var_os(SSL_CERT_DIR).is_some() {
        eprintln!("skipped: {SSL_CERT_FILE}/{SSL_CERT_DIR} override the platform store");
        return;
    }

    let (anchors, report) = pkix_truststore_system::from_system_with_report()
        .expect("a platform with a native trust store has a trust store");

    assert!(
        matches!(report.source, Source::Native(_)),
        "the platform store should answer before any file is searched, \
         got {:?}",
        report.source
    );
    assert!(
        !anchors.is_empty(),
        "the platform store answered with nothing, which from_system \
         treats as no answer at all"
    );
}
