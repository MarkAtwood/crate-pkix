//! Integration tests for [`from_pem_file`] / [`from_der_file`] size caps
//! (PKIX-tit4.24).
//!
//! The cap defends against pathological paths (oversized files,
//! `/dev/zero`-style infinite streams, accidental symlinks to log files).
//! Tests verify:
//!
//! 1. The default cap admits real-world bundles (covered by `fixtures.rs`).
//! 2. A file larger than an explicit cap is rejected with
//!    `Error::Io { kind: InvalidData, message: ".. exceeds ..-byte cap" }`.
//! 3. The same file loads cleanly when the cap is raised above its size.
//!
//! Oracle: file size on disk (`std::fs::metadata().len()`) compared against
//! the explicit cap. pkix-truststore is not used as its own oracle: the
//! input file is generated in /tmp (or the OS tempdir) outside the crate
//! and its size is asserted independently before the loader runs.

use pkix_truststore::{
    from_der_file_with_cap, from_pem_file, from_pem_file_with_cap, Error, DEFAULT_FILE_SIZE_CAP,
};
use std::io::{ErrorKind, Write as _};

const CERT1_PEM_PATH: &str = "tests/fixtures/cert1.pem";

fn make_tempfile(prefix: &str, bytes: &[u8]) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    path.push(format!("pkix-truststore-{prefix}-{pid}-{nanos}.bin"));
    let mut f = std::fs::File::create(&path).expect("create tempfile");
    f.write_all(bytes).expect("write tempfile");
    path
}

#[test]
fn default_cap_admits_typical_bundles() {
    // Sanity: the smallest committed fixture loads under the default cap.
    let anchors = from_pem_file(CERT1_PEM_PATH).expect("cert1.pem must load under default cap");
    assert_eq!(anchors.len(), 1);
}

#[test]
fn from_pem_file_with_cap_rejects_oversized() {
    // Build a 2 KiB junk PEM file and reject it with a 1 KiB cap.
    let junk = vec![b'A'; 2048];
    let path = make_tempfile("pem-over", &junk);
    let actual_size = std::fs::metadata(&path).expect("stat tempfile").len();
    assert!(actual_size > 1024, "tempfile must exceed the 1 KiB cap");

    match from_pem_file_with_cap(&path, 1024) {
        Err(Error::Io(failure)) => {
            assert_eq!(failure.kind, ErrorKind::InvalidData);
            assert!(
                failure.message.contains("exceeds") && failure.message.contains("cap"),
                "message must mention the cap; got: {}",
                failure.message,
            );
        }
        other => panic!("expected Error::Io(.. exceeds ..-byte cap); got {other:?}"),
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn from_pem_file_with_cap_accepts_under_cap() {
    // Same file loads when the cap is well above its size. The bytes are
    // not a valid PEM bundle, so loading must fail at the PEM step
    // (Error::NoCertificates), NOT at the cap step.
    let junk = vec![b'A'; 2048];
    let path = make_tempfile("pem-under", &junk);

    let err = from_pem_file_with_cap(&path, 64 * 1024).expect_err("junk PEM must fail to parse");
    assert!(
        matches!(err, Error::NoCertificates | Error::Pem(_)),
        "must fail at PEM step, not cap step; got {err:?}",
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn from_der_file_with_cap_rejects_oversized() {
    let junk = vec![0xffu8; 2048];
    let path = make_tempfile("der-over", &junk);

    match from_der_file_with_cap(&path, 1024) {
        Err(Error::Io(failure)) => {
            assert_eq!(failure.kind, ErrorKind::InvalidData);
            assert!(
                failure.message.contains("exceeds") && failure.message.contains("cap"),
                "message must mention the cap; got: {}",
                failure.message,
            );
        }
        other => panic!("expected Error::Io(.. exceeds ..-byte cap); got {other:?}"),
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn cap_default_is_64_mib() {
    // Pin the public constant against an independent oracle (the literal
    // 64 * 1024 * 1024) so a future maintainer changing the cap is
    // forced to update this test deliberately rather than accidentally.
    assert_eq!(DEFAULT_FILE_SIZE_CAP, 64 * 1024 * 1024);
}
