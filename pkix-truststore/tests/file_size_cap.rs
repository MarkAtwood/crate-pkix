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

/// A file of exactly `cap` bytes is within the cap.
///
/// `read_file_capped`'s own rustdoc states the contract: `cap + 1` is
/// requested from `take` "so the read fills exactly when the file is at
/// the limit and overshoots by one byte when it is over --
/// distinguishing 'exactly cap bytes' (accepted) from 'more than cap
/// bytes' (rejected)". Two comparisons implement that, one on the
/// metadata fast path and one on the bytes actually read, and both sat
/// untested: every other case here is a 2 KiB file against a 1 KiB cap
/// or a 64 KiB one, a thousand bytes from either boundary.
///
/// Read as `>=` or `==`, a file exactly at the limit is refused -- and
/// the cap is a documented public number, so that is a bundle a
/// deployment sized to the limit on purpose and cannot load.
///
/// The bytes are junk, so the load must fail at the PEM step; reaching
/// that step at all is the assertion. Oracle: the size on disk, checked
/// against the cap before the loader runs.
#[test]
fn a_file_exactly_at_the_cap_is_read() {
    const CAP: u64 = 1024;
    let path = make_tempfile("pem-exact", &vec![b'A'; CAP as usize]);
    let size = std::fs::metadata(&path).expect("stat tempfile").len();
    assert_eq!(size, CAP, "the fixture must sit exactly on the cap");

    let err = from_pem_file_with_cap(&path, CAP)
        .expect_err("junk is not a PEM bundle, whatever its size");
    assert!(
        matches!(err, Error::NoCertificates | Error::Pem(_)),
        "a file at the cap must reach the PEM step, not be refused by the cap; got {err:?}"
    );

    let _ = std::fs::remove_file(&path);
}

/// And one byte more is over it.
///
/// The other side of the same two comparisons. Paired with the case
/// above because one byte is the whole difference between them: a test
/// that only rejected an oversized file would pass for a cap that
/// refused everything at or above the limit.
#[test]
fn a_file_one_byte_over_the_cap_is_refused() {
    const CAP: u64 = 1024;
    let path = make_tempfile("pem-over-by-one", &vec![b'A'; CAP as usize + 1]);
    let size = std::fs::metadata(&path).expect("stat tempfile").len();
    assert_eq!(size, CAP + 1, "exactly one byte over");

    match from_pem_file_with_cap(&path, CAP) {
        Err(Error::Io(failure)) => {
            assert_eq!(failure.kind, ErrorKind::InvalidData);
            assert!(
                failure.message.contains("exceeds") && failure.message.contains("cap"),
                "message must name the cap; got: {}",
                failure.message
            );
        }
        other => panic!("one byte over the cap must be refused by the cap; got {other:?}"),
    }

    let _ = std::fs::remove_file(&path);
}
