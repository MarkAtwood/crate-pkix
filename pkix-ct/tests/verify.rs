//! Integration tests for SCT signature verification (PKIX-baac.3).
//!
//! # Fixtures
//!
//! Fixtures under `tests/fixtures/sct-oracle/` are produced by
//! `gen_x509_entry_sct.py` (in the same directory). That script is the
//! independent oracle: it uses pyca/cryptography's ECDSA primitive to
//! sign the RFC 6962 §3.2 `digitally-signed` input, never invoking any
//! pkix-ct code. The wire-format SCT, the signed-input bytes, the log's
//! private key (PEM), the log's SubjectPublicKeyInfo (DER), the
//! resulting `log_id` (32 bytes), and the certificate the SCT commits
//! to (DER) are all committed verbatim. See the script's docstring for
//! the exact byte layout and re-generation procedure.
//!
//! A second independent oracle, `openssl dgst -verify`, confirms the
//! fixtures sign-and-verify correctly outside pkix-ct (the procedure is
//! recorded in the script's commit message / module docs). The Rust
//! tests below therefore exercise pkix-ct's verification path against
//! a fixture whose correctness is established by two unrelated tools.
//!
//! # Coverage
//!
//! - **Positive**: real-world-shaped x509_entry SCT verifies cleanly.
//! - **Negative**:
//!   - Tampered signature → `InvalidSignature`.
//!   - Wrong cert DER       → `InvalidSignature`.
//!   - Unknown log_id        → `UnknownLog`.
//!   - Timestamp outside log window → `SctTimestampOutsideLogWindow`.
//!   - Unsupported `(hash_alg, sig_alg)` → `UnsupportedSignatureAlgorithm`.
//!
//! Pre-cert (`precert_entry`) verification is PKIX-baac.4 and is not
//! covered here.

#![cfg(feature = "log-list")]

use std::fs;

use pkix_ct::{CtLog, CtLogList, Error, SctVerifier, SignedCertificateTimestamp};
use pkix_path::DefaultVerifier;

const FIXTURE_DIR: &str = "tests/fixtures/sct-oracle";

fn read_fixture(name: &str) -> Vec<u8> {
    let path = format!("{FIXTURE_DIR}/{name}");
    fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

/// Build a `CtLogList` containing exactly the oracle log, with an
/// open window.
fn oracle_log_list() -> CtLogList {
    let log_spki = read_fixture("log-spki.der");
    let log_id_bytes = read_fixture("log-id.bin");
    let log_id: [u8; 32] = log_id_bytes
        .as_slice()
        .try_into()
        .expect("log-id.bin is 32 bytes");

    let mut logs = CtLogList::new();
    logs.insert(CtLog {
        log_id,
        key_der: log_spki,
        description: "oracle".into(),
        url: "http://example.invalid/ct/".into(),
        usable_from_ms: None,
        retired_at_ms: None,
    })
    .expect("oracle log self-consistency");
    logs
}

/// Build a `CtLogList` containing exactly the oracle log, but pinned to
/// a narrow usable window for testing the timestamp-window guard.
fn oracle_log_list_with_window(
    usable_from_ms: Option<u64>,
    retired_at_ms: Option<u64>,
) -> CtLogList {
    let log_spki = read_fixture("log-spki.der");
    let log_id_bytes = read_fixture("log-id.bin");
    let log_id: [u8; 32] = log_id_bytes.as_slice().try_into().unwrap();

    let mut logs = CtLogList::new();
    logs.insert(CtLog {
        log_id,
        key_der: log_spki,
        description: "oracle".into(),
        url: "http://example.invalid/ct/".into(),
        usable_from_ms,
        retired_at_ms,
    })
    .unwrap();
    logs
}

fn load_oracle_sct() -> SignedCertificateTimestamp {
    let sct_bytes = read_fixture("sct.bin");
    SignedCertificateTimestamp::from_bytes(&sct_bytes).expect("parse oracle sct.bin")
}

// --- positive ------------------------------------------------------------

#[test]
fn verifies_real_world_shaped_x509_entry_sct() {
    let logs = oracle_log_list();
    let v = SctVerifier::new(logs, DefaultVerifier);
    let sct = load_oracle_sct();
    let cert_der = read_fixture("cert.der");

    let log = v.verify_sct_for_cert(&sct, &cert_der).expect("verify");
    assert_eq!(log.description, "oracle");

    // Independent cross-check: pyca-recorded sct fields match what pkix-ct parsed.
    assert_eq!(sct.version, 0);
    assert_eq!(sct.hash_alg, 4, "RFC 5246 §7.4.1.4.1: SHA-256 = 4");
    assert_eq!(sct.sig_alg, 3, "RFC 5246 §7.4.1.4.1: ECDSA = 3");
    assert_eq!(sct.timestamp_ms, 1_750_032_000_000);
    assert_eq!(
        sct.signature.len(),
        72,
        "ECDSA-DER signature, expected 72 bytes per meta.json"
    );
}

// --- negative: tampered signature ----------------------------------------

#[test]
fn rejects_tampered_signature() {
    let logs = oracle_log_list();
    let v = SctVerifier::new(logs, DefaultVerifier);
    let mut sct = load_oracle_sct();

    // Flip a single byte mid-signature. ECDSA-DER signatures cannot
    // tolerate any internal change.
    assert!(!sct.signature.is_empty());
    let mid = sct.signature.len() / 2;
    sct.signature[mid] ^= 0xAA;

    let cert_der = read_fixture("cert.der");
    assert_eq!(
        v.verify_sct_for_cert(&sct, &cert_der),
        Err(Error::InvalidSignature)
    );
}

// --- negative: wrong cert ------------------------------------------------

#[test]
fn rejects_wrong_cert() {
    let logs = oracle_log_list();
    let v = SctVerifier::new(logs, DefaultVerifier);
    let sct = load_oracle_sct();

    // Use a different cert DER — any other parseable cert will do.
    // We reuse a stable fixture from elsewhere in the workspace.
    let other = fs::read("../pkix-path/tests/fixtures/ec-p256-sha256.der")
        .expect("read pkix-path fixture as wrong-cert");
    assert_eq!(
        v.verify_sct_for_cert(&sct, &other),
        Err(Error::InvalidSignature)
    );
}

// --- negative: unknown log id --------------------------------------------

#[test]
fn rejects_unknown_log_id() {
    // Empty log list: oracle log_id is unknown.
    let v = SctVerifier::new(CtLogList::new(), DefaultVerifier);
    let sct = load_oracle_sct();
    let cert_der = read_fixture("cert.der");
    assert_eq!(
        v.verify_sct_for_cert(&sct, &cert_der),
        Err(Error::UnknownLog)
    );
}

#[test]
fn rejects_real_world_cert_with_retired_logs_as_unknown() {
    // The pyca/cryptography-scts.pem fixture's SCTs are from
    // Google Argon2018 and Cloudflare Nimbus 2018, both long retired
    // and absent from the oracle log list. Each SCT in that fixture
    // should resolve to UnknownLog when verified against this list.
    use pkix_ct::SctList;
    use x509_cert::der::DecodePem;
    use x509_cert::Certificate;
    let pem = fs::read_to_string("tests/fixtures/cryptography-scts.pem").unwrap();
    let cert = Certificate::from_pem(&pem).unwrap();
    let exts = cert.tbs_certificate.extensions.as_ref().unwrap();
    let sct_ext = exts
        .iter()
        .find(|e| e.extn_id.to_string() == "1.3.6.1.4.1.11129.2.4.2")
        .unwrap();
    let scts = SctList::from_extension_value(sct_ext.extn_value.as_bytes()).unwrap();
    assert!(!scts.0.is_empty());

    let v = SctVerifier::new(oracle_log_list(), DefaultVerifier);
    // We don't have a final cert for these SCTs (they're precert SCTs
    // anyway); the log_id check fires before the cert is needed.
    let dummy_cert = read_fixture("cert.der");
    for sct in &scts.0 {
        assert_eq!(
            v.verify_sct_for_cert(sct, &dummy_cert),
            Err(Error::UnknownLog),
        );
    }
}

// --- negative: timestamp window ------------------------------------------

#[test]
fn rejects_sct_before_log_usable_from() {
    let sct = load_oracle_sct();
    let cert_der = read_fixture("cert.der");

    // Oracle SCT timestamp = 1_750_032_000_000. Set usable_from to one
    // ms later: SCT must be rejected.
    let logs = oracle_log_list_with_window(Some(sct.timestamp_ms + 1), None);
    let v = SctVerifier::new(logs, DefaultVerifier);
    assert_eq!(
        v.verify_sct_for_cert(&sct, &cert_der),
        Err(Error::SctTimestampOutsideLogWindow)
    );
}

#[test]
fn accepts_sct_exactly_at_log_usable_from() {
    let sct = load_oracle_sct();
    let cert_der = read_fixture("cert.der");

    // Lower bound is inclusive: SCT timestamp == usable_from must pass.
    let logs = oracle_log_list_with_window(Some(sct.timestamp_ms), None);
    let v = SctVerifier::new(logs, DefaultVerifier);
    assert!(v.verify_sct_for_cert(&sct, &cert_der).is_ok());
}

#[test]
fn rejects_sct_at_or_after_log_retired_at() {
    let sct = load_oracle_sct();
    let cert_der = read_fixture("cert.der");

    // Upper bound is exclusive: SCT timestamp == retired_at must fail.
    let logs = oracle_log_list_with_window(None, Some(sct.timestamp_ms));
    let v = SctVerifier::new(logs, DefaultVerifier);
    assert_eq!(
        v.verify_sct_for_cert(&sct, &cert_der),
        Err(Error::SctTimestampOutsideLogWindow)
    );
}

// --- negative: unsupported algorithm -------------------------------------

#[test]
fn rejects_unsupported_signature_algorithm() {
    let mut sct = load_oracle_sct();
    // DSA (sig_alg=2) is in RFC 5246 but excluded by project policy and
    // by pkix-path's backends. The verifier should short-circuit before
    // dispatch, before touching the signature bytes at all.
    sct.sig_alg = 2;

    let logs = oracle_log_list();
    let v = SctVerifier::new(logs, DefaultVerifier);
    let cert_der = read_fixture("cert.der");
    assert_eq!(
        v.verify_sct_for_cert(&sct, &cert_der),
        Err(Error::UnsupportedSignatureAlgorithm {
            hash_alg: 4,
            sig_alg: 2,
        })
    );
}

#[test]
fn rejects_unsupported_version() {
    let mut sct = load_oracle_sct();
    sct.version = 1; // RFC 9162 v2 — not deployed, parser would have caught
                     // it, but exercise the SctVerifier guard explicitly.
    let logs = oracle_log_list();
    let v = SctVerifier::new(logs, DefaultVerifier);
    let cert_der = read_fixture("cert.der");
    assert_eq!(
        v.verify_sct_for_cert(&sct, &cert_der),
        Err(Error::UnsupportedVersion(1))
    );
}
