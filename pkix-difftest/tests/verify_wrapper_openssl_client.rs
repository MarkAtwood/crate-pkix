//! Wrapper-level differential test (PKIX-fmtv.18.3).
//!
//! Compares `pkix_chain::verify_tls_client_dns` against `openssl verify
//! -purpose sslclient -verify_hostname X` over the curated clientAuth-EKU
//! corpus in `pkix-chain/tests/fixtures/`.
//!
//! ## Why OpenSSL is a strong oracle here
//!
//! Unlike pyca's `build_client_verifier()` (which does not bind subject
//! and does not enforce EKU under `permit_all` EE policy), OpenSSL's
//! `-purpose sslclient -verify_hostname X` enforces both:
//!
//! - **id-kp-clientAuth EKU** at the verifier level (`-purpose sslclient`
//!   rejects a serverAuth-only leaf with "unsuitable certificate
//!   purpose"), matching what `BasicTlsClientProfile` enforces.
//!
//! - **dNSName SAN binding** via `-verify_hostname` (rejects a hostname
//!   mismatch with "hostname mismatch"), matching what
//!   `verify_tls_client_dns(..., Some(name))` enforces.
//!
//! This makes OpenSSL the canonical differential oracle for
//! `verify_tls_client_dns`.
//!
//! ## Running
//!
//! ```sh
//! cargo test -p pkix-difftest --test verify_wrapper_openssl_client -- --nocapture
//! ```

#![forbid(unsafe_code)]

use std::path::PathBuf;

use pkix_chain::{
    verify_tls_client_dns, DefaultVerifier, Error, IdentityError, NoAiaFetcher, NoRevocation,
    ServerName, TrustAnchor,
};
use pkix_difftest::oracles;
use pkix_difftest::{Chain, Verdict};
use pkix_profiles::{BasicTlsClientProfile, Rfc5280Profile};
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

const NOW: u64 = 1_780_272_000;

// ---------------------------------------------------------------------------
// Outcome vocabulary
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum RustOutcome {
    Ok,
    NoMatchingSan,
    MissingSan,
    Path,
    Other(String),
}

impl RustOutcome {
    fn from_result<T>(r: Result<T, Error>) -> Self {
        match r {
            Ok(_) => RustOutcome::Ok,
            Err(Error::Identity(IdentityError::NoMatchingSan)) => RustOutcome::NoMatchingSan,
            Err(Error::Identity(IdentityError::MissingSan)) => RustOutcome::MissingSan,
            Err(Error::Path(_)) => RustOutcome::Path,
            Err(other) => RustOutcome::Other(format!("{other:?}")),
        }
    }

    fn is_pass(&self) -> bool {
        matches!(self, RustOutcome::Ok)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AgreementKind {
    Agree,
    LooserThanOpenssl,
    StricterThanOpenssl,
}

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Profile {
    Rfc5280,
    BasicClient,
}

struct ClientCase<'a> {
    name: &'a str,
    fixture: &'a str,
    /// Some(hostname) → bind both sides; None → no binding on either side.
    hostname: Option<&'a str>,
    profile: Profile,
    expected_rust: RustOutcome,
}

#[rustfmt::skip]
fn client_cases() -> Vec<ClientCase<'static>> {
    use Profile::*;
    use RustOutcome::*;
    vec![
        // clientAuth-EKU leaf with matching DNS SAN — both pass under either profile.
        ClientCase {
            name: "match_under_rfc5280",
            fixture: "leaf-clientauth-dns.der",
            hostname: Some("client.example.com"),
            profile: Rfc5280,
            expected_rust: Ok,
        },
        ClientCase {
            name: "match_under_basic_client",
            fixture: "leaf-clientauth-dns.der",
            hostname: Some("client.example.com"),
            profile: BasicClient,
            expected_rust: Ok,
        },

        // clientAuth-EKU leaf with mismatched DNS SAN. Rust: NoMatchingSan.
        // OpenSSL: hostname mismatch. Both reject.
        ClientCase {
            name: "san_mismatch",
            fixture: "leaf-clientauth-dns.der",
            hostname: Some("other.example.com"),
            profile: Rfc5280,
            expected_rust: NoMatchingSan,
        },

        // serverAuth-only leaf under BasicTlsClientProfile. Rust: Error::Path
        // (EKU mismatch). OpenSSL: "unsuitable certificate purpose" under
        // -purpose sslclient. Both reject.
        ClientCase {
            name: "eku_mismatch_basic_client",
            fixture: "host-exact-foo.der",
            hostname: Some("foo.example.com"),
            profile: BasicClient,
            expected_rust: Path,
        },

        // clientAuth-mailbox leaf with hostname binding. Leaf has rfc822Name
        // SAN, no dNSName SAN. Rust: NoMatchingSan when asked to bind DNS
        // name. OpenSSL: hostname mismatch (no DNS SAN present). Both
        // reject.
        ClientCase {
            name: "mailbox_leaf_dns_binding_rejected",
            fixture: "leaf-clientauth-mailbox.der",
            hostname: Some("client.example.com"),
            profile: Rfc5280,
            expected_rust: NoMatchingSan,
        },

        // identity=None on a clientAuth chain → Rust succeeds (path-only).
        // OpenSSL succeeds too when -verify_hostname is omitted.
        ClientCase {
            name: "no_binding_clientauth_ok",
            fixture: "leaf-clientauth-dns.der",
            hostname: None,
            profile: Rfc5280,
            expected_rust: Ok,
        },

        // identity=None on a serverAuth-only chain under BasicTlsClient →
        // Rust rejects EKU. OpenSSL rejects "unsuitable purpose".
        ClientCase {
            name: "no_binding_eku_rejected",
            fixture: "host-exact-foo.der",
            hostname: None,
            profile: BasicClient,
            expected_rust: Path,
        },
    ]
}

// ---------------------------------------------------------------------------
// Test driver
// ---------------------------------------------------------------------------

#[test]
fn verify_tls_client_dns_diff_against_openssl() {
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root.clone())];

    let mut rows: Vec<Row> = Vec::new();
    for case in client_cases() {
        let leaf = load_fixture(case.fixture);
        let chain = [leaf.clone()];

        // --- Rust verdict ---
        let server_name = case
            .hostname
            .map(|s| ServerName::dns_name(s).expect("parse DNS"));
        let server_name_ref = server_name.as_ref();
        let rust = match case.profile {
            Profile::Rfc5280 => RustOutcome::from_result(verify_tls_client_dns(
                &chain,
                &anchors,
                server_name_ref,
                &Rfc5280Profile,
                NOW,
                &DefaultVerifier,
                &NoRevocation,
                &NoAiaFetcher,
            )),
            Profile::BasicClient => RustOutcome::from_result(verify_tls_client_dns(
                &chain,
                &anchors,
                server_name_ref,
                &BasicTlsClientProfile,
                NOW,
                &DefaultVerifier,
                &NoRevocation,
                &NoAiaFetcher,
            )),
        };
        assert_eq!(
            rust, case.expected_rust,
            "Rust outcome diverged from expected for {} (fixture {}, hostname {:?}, profile {:?})",
            case.name, case.fixture, case.hostname, case.profile,
        );

        // --- OpenSSL verdict ---
        let diff_chain = Chain {
            certs_der: vec![cert_der(&leaf), cert_der(&root)],
            crls: Vec::new(),
            root_in_chain: true,
            label: case.name.to_string(),
            validation_time_unix: Some(NOW),
        };
        let args = oracles::openssl::VerifyArgs {
            purpose: Some("sslclient"),
            verify_hostname: case.hostname,
            ..oracles::openssl::VerifyArgs::default()
        };
        let openssl =
            expect_openssl_available(oracles::openssl::verify_with_args(&diff_chain, &args));
        let kind = classify(rust.is_pass(), openssl.is_pass());

        rows.push(Row {
            case: case.name.to_string(),
            fixture: case.fixture.to_string(),
            hostname: case
                .hostname
                .map_or_else(|| "none".to_string(), str::to_string),
            profile: format!("{:?}", case.profile),
            rust: format!("{rust:?}"),
            openssl: openssl_label(&openssl),
            kind,
        });
    }

    eprintln!();
    eprintln!("=== verify_tls_client_dns diff vs `openssl verify -purpose sslclient` ===");
    emit_matrix(&rows);
    let summary = summarize(&rows);
    eprintln!();
    eprintln!(
        "client: {n} cases — {agree} agree, {looser} Rust-looser, {stricter} Rust-stricter",
        n = rows.len(),
        agree = summary.agree,
        looser = summary.looser,
        stricter = summary.stricter,
    );

    assert_eq!(
        summary.looser, 0,
        "client: no Rust-looser cases tolerated — OpenSSL refused while \
         verify_tls_client_dns passed; investigate"
    );
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

fn cert_der(c: &Certificate) -> Vec<u8> {
    use der::Encode as _;
    let mut out = Vec::new();
    c.encode_to_vec(&mut out).expect("re-encode DER");
    out
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../pkix-chain/tests/fixtures")
}

fn load_fixture(name: &str) -> Certificate {
    let path = fixtures_dir().join(name);
    let der = std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
    Certificate::from_der(&der).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

fn expect_openssl_available(result: std::io::Result<Verdict>) -> Verdict {
    match result {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            panic!(
                "openssl binary not on $PATH; install OpenSSL ≥ 1.1 or set \
                 PKIX_DIFFTEST_OPENSSL_BIN. Original: {e}"
            );
        }
        Err(e) => panic!("openssl oracle harness error: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

struct Row {
    case: String,
    fixture: String,
    hostname: String,
    profile: String,
    rust: String,
    openssl: String,
    kind: AgreementKind,
}

struct Summary {
    agree: usize,
    looser: usize,
    stricter: usize,
}

fn classify(rust_pass: bool, openssl_pass: bool) -> AgreementKind {
    match (rust_pass, openssl_pass) {
        (true, true) | (false, false) => AgreementKind::Agree,
        (true, false) => AgreementKind::LooserThanOpenssl,
        (false, true) => AgreementKind::StricterThanOpenssl,
    }
}

fn openssl_label(v: &Verdict) -> String {
    match v {
        Verdict::Pass => "pass".to_string(),
        Verdict::Fail { .. } => "fail".to_string(),
    }
}

fn emit_matrix(rows: &[Row]) {
    eprintln!(
        "{:34}  {:30}  {:20}  {:12}  {:18}  {:7}  agreement",
        "case", "fixture", "hostname", "profile", "rust", "openssl"
    );
    eprintln!("{}", "-".repeat(150));
    for r in rows {
        eprintln!(
            "{:34}  {:30}  {:20}  {:12}  {:18}  {:7}  {:?}",
            r.case, r.fixture, r.hostname, r.profile, r.rust, r.openssl, r.kind
        );
    }
}

fn summarize(rows: &[Row]) -> Summary {
    let mut s = Summary {
        agree: 0,
        looser: 0,
        stricter: 0,
    };
    for r in rows {
        match r.kind {
            AgreementKind::Agree => s.agree += 1,
            AgreementKind::LooserThanOpenssl => s.looser += 1,
            AgreementKind::StricterThanOpenssl => s.stricter += 1,
        }
    }
    s
}
