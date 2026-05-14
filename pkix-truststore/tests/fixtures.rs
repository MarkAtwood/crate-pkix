//! Integration tests against on-disk fixtures.
//!
//! Real-world distro CA bundles committed under `tests/fixtures/`:
//!
//! * `debian-ca-certificates.crt` — the Debian `/etc/ssl/certs/
//!   ca-certificates.crt` bundle, copied at fixture-creation time from a
//!   Debian system.
//! * `alpine-ca-certificates.crt` — the Alpine `/etc/ssl/certs/
//!   ca-certificates.crt` bundle, extracted on 2026-05-10 from the
//!   `docker.io/library/alpine:latest` OCI image with linux/amd64 manifest
//!   digest `sha256:4d889c14e7d5a73929ab00be2ef8ff22437e7cbc545931e52554a7b00e123d8b`
//!   (Alpine 3.23.4). The bundle is supplied by the
//!   `ca-certificates-bundle-20260413-r0` apk package.
//! * `fedora-ca-bundle.crt` — the Fedora `/etc/pki/tls/certs/ca-bundle.crt`
//!   bundle, extracted on 2026-05-10 from the
//!   `docker.io/library/fedora:latest` OCI image with linux/amd64 manifest
//!   digest `sha256:f717d3f59ea0dc45d3c024c9477e786bab7d418d26636920d17b48016f1e69ca`
//!   (Fedora 44 Container Image). The bundle is supplied by the
//!   `ca-certificates-2025.2.80_v9.0.304-6.fc44` rpm package. The minimal
//!   container image strips the `/etc/pki/tls/certs/ca-bundle.crt` symlink
//!   but keeps its target `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`;
//!   the file copied here is that target byte-for-byte.
//!
//! These three bundles are used to exercise multi-cert PEM parsing against
//! the real encodings each distro ships, and to compare the loaded-anchor
//! count against an independent oracle (`grep -c "BEGIN CERTIFICATE"`) at
//! fixture-creation time.
//!
//! Single-cert and DER smoke-test fixtures (all derived from the Debian
//! bundle to keep dependencies minimal):
//!
//! * `cert1.pem`, `cert2.pem` — the first two certificates extracted from
//!   the Debian bundle. Single-cert PEM smoke tests use these.
//! * `cert1.der` — `cert1.pem` converted to DER with
//!   `openssl x509 -in cert1.pem -outform DER -out cert1.der`. The external
//!   oracle is OpenSSL's encoder: the DER must round-trip equal to the PEM's
//!   base64 body.
//!
//! Per the project test-discipline rule, no test uses `pkix-truststore`
//! itself as its oracle. Counts come from `grep` (or a constant verified by
//! `grep` at fixture-creation time); DER bytes come from OpenSSL; the
//! synthetic-quirk PEMs are byte-built in this test file from independently
//! known-good PEM strings.

use pkix_truststore::{from_der, from_der_file, from_der_iter, from_pem, from_pem_file, Error};

const DEBIAN_BUNDLE_PATH: &str = "tests/fixtures/debian-ca-certificates.crt";
const ALPINE_BUNDLE_PATH: &str = "tests/fixtures/alpine-ca-certificates.crt";
const FEDORA_BUNDLE_PATH: &str = "tests/fixtures/fedora-ca-bundle.crt";
const CERT1_PEM_PATH: &str = "tests/fixtures/cert1.pem";
const CERT2_PEM_PATH: &str = "tests/fixtures/cert2.pem";
const CERT1_DER_PATH: &str = "tests/fixtures/cert1.der";

/// Independent oracle: `grep -c "-----BEGIN CERTIFICATE-----"
/// debian-ca-certificates.crt` on the fixture at the time it was committed
/// reported this count. CI re-verifies the count at the start of the
/// integration tests so a fixture refresh that changes the count fails
/// loudly here, not in a misleading "anchor parse failed" assertion.
const DEBIAN_BUNDLE_CERT_COUNT: usize = 147;

/// Independent oracle: `grep -c "-----BEGIN CERTIFICATE-----"
/// alpine-ca-certificates.crt` on the fixture at the time it was committed
/// (Alpine 3.23.4, `ca-certificates-bundle-20260413-r0`) reported this count.
const ALPINE_BUNDLE_CERT_COUNT: usize = 145;

/// Independent oracle: `grep -c "-----BEGIN CERTIFICATE-----"
/// fedora-ca-bundle.crt` on the fixture at the time it was committed
/// (Fedora 44, `ca-certificates-2025.2.80_v9.0.304-6.fc44`) reported this
/// count.
const FEDORA_BUNDLE_CERT_COUNT: usize = 146;

/// Re-derive the cert count from the bundle bytes by counting BEGIN
/// boundaries. This is the in-process replay of the external `grep`
/// oracle; it intentionally does not use `from_pem`.
fn count_begin_boundaries(bytes: &[u8]) -> usize {
    bytes
        .windows(b"-----BEGIN CERTIFICATE-----".len())
        .filter(|w| *w == b"-----BEGIN CERTIFICATE-----")
        .count()
}

#[test]
fn debian_bundle_loads() {
    let bytes = std::fs::read(DEBIAN_BUNDLE_PATH).expect("fixture missing");
    // Sanity-check the oracle constant against the bytes on disk.
    assert_eq!(
        count_begin_boundaries(&bytes),
        DEBIAN_BUNDLE_CERT_COUNT,
        "fixture refresh changed cert count; update DEBIAN_BUNDLE_CERT_COUNT",
    );
    let anchors = from_pem(&bytes).expect("Debian bundle should parse");
    assert_eq!(anchors.len(), DEBIAN_BUNDLE_CERT_COUNT);
}

#[test]
fn debian_bundle_loads_via_file_helper() {
    let anchors = from_pem_file(DEBIAN_BUNDLE_PATH).expect("Debian bundle should parse");
    assert_eq!(anchors.len(), DEBIAN_BUNDLE_CERT_COUNT);
}

#[test]
fn alpine_bundle_loads() {
    let bytes = std::fs::read(ALPINE_BUNDLE_PATH).expect("fixture missing");
    // Sanity-check the oracle constant against the bytes on disk.
    assert_eq!(
        count_begin_boundaries(&bytes),
        ALPINE_BUNDLE_CERT_COUNT,
        "fixture refresh changed cert count; update ALPINE_BUNDLE_CERT_COUNT",
    );
    let anchors = from_pem(&bytes).expect("Alpine bundle should parse");
    assert_eq!(anchors.len(), ALPINE_BUNDLE_CERT_COUNT);
}

#[test]
fn alpine_bundle_loads_via_file_helper() {
    let anchors = from_pem_file(ALPINE_BUNDLE_PATH).expect("Alpine bundle should parse");
    assert_eq!(anchors.len(), ALPINE_BUNDLE_CERT_COUNT);
}

#[test]
fn fedora_bundle_loads() {
    let bytes = std::fs::read(FEDORA_BUNDLE_PATH).expect("fixture missing");
    // Sanity-check the oracle constant against the bytes on disk.
    assert_eq!(
        count_begin_boundaries(&bytes),
        FEDORA_BUNDLE_CERT_COUNT,
        "fixture refresh changed cert count; update FEDORA_BUNDLE_CERT_COUNT",
    );
    let anchors = from_pem(&bytes).expect("Fedora bundle should parse");
    assert_eq!(anchors.len(), FEDORA_BUNDLE_CERT_COUNT);
}

#[test]
fn fedora_bundle_loads_via_file_helper() {
    let anchors = from_pem_file(FEDORA_BUNDLE_PATH).expect("Fedora bundle should parse");
    assert_eq!(anchors.len(), FEDORA_BUNDLE_CERT_COUNT);
}

#[test]
fn single_cert_pem_loads() {
    let anchors = from_pem_file(CERT1_PEM_PATH).expect("cert1.pem should parse");
    assert_eq!(anchors.len(), 1);
}

#[test]
fn single_cert_der_loads_and_matches_pem() {
    // Oracle: OpenSSL converted cert1.pem -> cert1.der. The two must
    // resolve to the same TrustAnchor (subject, SPKI). This catches PEM
    // vs DER drift and silent base64/whitespace corruption in the
    // fixture or the loader.
    let from_pem_anchors = from_pem_file(CERT1_PEM_PATH).unwrap();
    let from_der_anchor = from_der_file(CERT1_DER_PATH).unwrap();
    assert_eq!(from_pem_anchors.len(), 1);
    assert_eq!(from_pem_anchors[0].subject, from_der_anchor.subject);
    assert_eq!(
        from_pem_anchors[0].subject_public_key_info,
        from_der_anchor.subject_public_key_info,
    );
}

#[test]
fn from_der_iter_loads_multiple() {
    let der1 = std::fs::read(CERT1_DER_PATH).unwrap();
    // Convert cert2 PEM to DER on the fly using x509-cert's loader to
    // avoid hand-committing a second DER fixture. der::DecodePem and
    // der::Encode are reachable through x509-cert.
    use der::{DecodePem, Encode};
    let pem_bytes = std::fs::read(CERT2_PEM_PATH).unwrap();
    let cert2 = x509_cert::Certificate::from_pem(&pem_bytes).unwrap();
    let der2 = cert2.to_der().unwrap();

    let anchors = from_der_iter([der1.as_slice(), der2.as_slice()]).unwrap();
    assert_eq!(anchors.len(), 2);
}

#[test]
fn from_der_iter_empty_is_no_certificates() {
    let empty: Vec<Vec<u8>> = Vec::new();
    assert!(matches!(from_der_iter(empty), Err(Error::NoCertificates)));
}

#[test]
fn from_der_iter_reports_index_of_malformed_entry() {
    let good = std::fs::read(CERT1_DER_PATH).unwrap();
    let bad = vec![0xffu8; 32];
    // Position 1 (0-indexed): first good, second bad.
    let inputs: [&[u8]; 2] = [good.as_slice(), bad.as_slice()];
    match from_der_iter(inputs) {
        Err(Error::MalformedAnchor { index, source: _ }) => assert_eq!(index, 1),
        other => panic!("expected MalformedAnchor {{ index: 1, .. }}, got {other:?}"),
    }
}

#[test]
fn pem_with_bom_loads() {
    // Synthetic: prefix a known-good single-cert PEM with a UTF-8 BOM.
    // Oracle: cert1.pem was authored by `openssl x509` from the Debian
    // bundle; the BOM is the only difference in this input.
    let mut bytes = b"\xef\xbb\xbf".to_vec();
    bytes.extend_from_slice(&std::fs::read(CERT1_PEM_PATH).unwrap());
    let anchors = from_pem(&bytes).expect("BOM-prefixed PEM should parse");
    assert_eq!(anchors.len(), 1);
}

#[test]
fn pem_with_crlf_line_endings_loads() {
    // Convert LF -> CRLF in the known-good cert1.pem text.
    let text = std::fs::read_to_string(CERT1_PEM_PATH).unwrap();
    let crlf = text.replace('\n', "\r\n");
    let anchors = from_pem(crlf.as_bytes()).expect("CRLF PEM should parse");
    assert_eq!(anchors.len(), 1);
}

#[test]
fn pem_with_header_comment_block_loads() {
    // Real-world bundles (Debian intermediate format, ca-certificates
    // pre-`update-ca-certificates`) prefix each cert with metadata lines:
    //
    //     Subject: CN=...
    //     Issuer: CN=...
    //     Serial Number: ...
    //
    // `x509-cert::load_pem_chain` scans for the BEGIN/END markers and
    // skips text outside them. Note: trailing non-whitespace content
    // after the final END boundary is rejected (see
    // `trailing_non_whitespace_after_last_end_is_rejected`).
    let cert = std::fs::read_to_string(CERT1_PEM_PATH).unwrap();
    let with_header = format!(
        "## This is a CA bundle. Do not edit by hand.\n\
         Subject: CN=ACCVRAIZ1, OU=PKIACCV, O=ACCV, C=ES\n\
         Issuer: CN=ACCVRAIZ1, OU=PKIACCV, O=ACCV, C=ES\n\
         Serial Number: 5ec3b7a6437fa4e0\n\
         \n\
         {cert}"
    );
    let anchors = from_pem(with_header.as_bytes()).expect("header-commented PEM should parse");
    assert_eq!(anchors.len(), 1);
}

#[test]
fn pem_inter_cert_metadata_loads() {
    // Two-cert PEM with OpenSSL-style Subject/Issuer/Serial metadata
    // lines between the certs. The metadata between END of cert 1 and
    // BEGIN of cert 2 must be tolerated.
    let c1 = std::fs::read_to_string(CERT1_PEM_PATH).unwrap();
    let c2 = std::fs::read_to_string(CERT2_PEM_PATH).unwrap();
    let bundle = format!(
        "{c1}\n\
         Subject: CN=AC RAIZ FNMT-RCM, OU=AC RAIZ FNMT-RCM, O=FNMT-RCM, C=ES\n\
         Issuer: CN=AC RAIZ FNMT-RCM, OU=AC RAIZ FNMT-RCM, O=FNMT-RCM, C=ES\n\
         Serial Number: 5d938d306736c8061d1ac7548469073\n\
         \n\
         {c2}"
    );
    let anchors = from_pem(bundle.as_bytes()).expect("inter-cert metadata PEM should parse");
    assert_eq!(anchors.len(), 2);
}

#[test]
fn trailing_non_whitespace_after_last_end_is_rejected() {
    // Documented limitation: x509-cert::load_pem_chain accepts trailing
    // whitespace (handled by `pem_with_trailing_whitespace_loads`) but
    // rejects arbitrary trailing text. This test pins that behaviour so
    // any future loosening is a deliberate, reviewable change.
    let cert = std::fs::read_to_string(CERT1_PEM_PATH).unwrap();
    let trailing = format!("{cert}\n## trailing comment\n");
    let err = from_pem(trailing.as_bytes());
    assert!(
        matches!(err, Err(Error::Pem(_))),
        "expected Pem error for trailing content, got {err:?}",
    );
}

#[test]
fn pem_with_trailing_whitespace_loads() {
    let mut bytes = std::fs::read(CERT1_PEM_PATH).unwrap();
    bytes.extend_from_slice(b"\n\n\r\n\n");
    let anchors = from_pem(&bytes).expect("trailing-whitespace PEM should parse");
    assert_eq!(anchors.len(), 1);
}

#[test]
fn pem_two_certs_back_to_back_no_blank_line_loads() {
    let c1 = std::fs::read(CERT1_PEM_PATH).unwrap();
    let c2 = std::fs::read(CERT2_PEM_PATH).unwrap();
    // Strip trailing newline from c1 so the END boundary is immediately
    // followed by the next BEGIN boundary.
    let mut bytes = Vec::new();
    let trimmed = c1
        .strip_suffix(b"\n")
        .or_else(|| c1.strip_suffix(b"\r\n"))
        .unwrap_or(&c1);
    bytes.extend_from_slice(trimmed);
    bytes.extend_from_slice(&c2);
    let anchors = from_pem(&bytes).expect("back-to-back PEM should parse");
    assert_eq!(anchors.len(), 2);
}

#[test]
fn empty_pem_file_is_no_certificates() {
    assert!(matches!(from_pem(b""), Err(Error::NoCertificates)));
}

#[test]
fn whitespace_only_pem_is_no_certificates() {
    assert!(matches!(
        from_pem(b"   \n\n\r\n\t\n"),
        Err(Error::NoCertificates),
    ));
}

#[test]
fn unknown_pem_label_errors() {
    // RFC 7468 strict: unknown PEM labels are an error, not silently
    // skipped. A `PRIVATE KEY` block must not be misread as a certificate.
    let bogus = b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
    // No BEGIN CERTIFICATE boundary at all, so we expect NoCertificates.
    assert!(matches!(from_pem(bogus), Err(Error::NoCertificates)));
}

#[test]
fn truncated_pem_block_errors() {
    // BEGIN boundary present (so we enter the loader) but no END
    // boundary follows. x509-cert reports `PostEncapsulationBoundary`,
    // which our mapper surfaces as `Error::Pem`.
    let truncated = b"-----BEGIN CERTIFICATE-----\nMIIH0zCCBbug\n";
    match from_pem(truncated) {
        Err(Error::Pem(_)) => {}
        other => panic!("expected Error::Pem, got {other:?}"),
    }
}

#[test]
fn garbage_after_begin_boundary_errors() {
    // BEGIN/END frame present but the base64 body is non-PEM-valid.
    let bad = b"-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n-----END CERTIFICATE-----\n";
    let err = from_pem(bad);
    assert!(
        matches!(err, Err(Error::Pem(_)) | Err(Error::Der(_))),
        "expected Pem or Der error, got {err:?}",
    );
}

#[test]
fn from_der_garbage_errors() {
    assert!(matches!(from_der(&[0xff; 32]), Err(Error::Der(_))));
}

#[test]
fn from_der_file_missing_path_errors() {
    let err = from_der_file("/nonexistent/path/that/should/not/exist.der");
    assert!(matches!(err, Err(Error::Io(_))), "got {err:?}");
}
