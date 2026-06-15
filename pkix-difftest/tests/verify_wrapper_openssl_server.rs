//! Wrapper-level differential test (PKIX-fmtv.18.2).
//!
//! Compares `pkix_chain::verify_tls_server` against `openssl verify
//! -purpose sslserver -verify_hostname X` (or `-verify_ip X` for IP-literal
//! SANs) over the curated RFC 6125 corpus that ships in
//! `pkix-chain/tests/fixtures/` (authored under PKIX-fmtv.22).
//!
//! Companion of `verify_wrapper_pyca.rs` (PKIX-fmtv.19) — both tests drive
//! the same in-test row table so the per-case agreement matrices line up
//! 1:1 in `baseline-verify-openssl.md` / `baseline-verify-pyca.md`.
//!
//! ## Why OpenSSL is the stronger oracle for verify_tls_server
//!
//! OpenSSL's `-purpose sslserver` enforces id-kp-serverAuth EKU and
//! requires a SAN on the leaf for hostname/IP binding. Unlike pyca's
//! webpki_defaults_ee policy, OpenSSL does NOT require
//! authorityKeyIdentifier on the leaf — which means we can compare
//! against minimal-extension corpus fixtures directly without the
//! permit_all gymnastics needed for pyca.
//!
//! ## Running
//!
//! ```sh
//! cargo test -p pkix-difftest --test verify_wrapper_openssl_server -- --nocapture
//! ```
//!
//! When `openssl` is missing from `$PATH`, the test panics with a clear
//! message — OpenSSL is named in AGENTS.md as a required test oracle, so
//! we do not silently skip.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use pkix_chain::{
    verify_tls_server, DefaultVerifier, Error, IdentityError, NoAiaFetcher, NoRevocation,
    ServerName, TrustAnchor,
};
use pkix_difftest::oracles;
use pkix_difftest::{Chain, Verdict};
use pkix_profiles::Rfc5280Profile;
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

const NOW: u64 = 1_780_272_000;

// ---------------------------------------------------------------------------
// Outcome vocabulary (matches verify_wrapper_pyca.rs)
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
// Server-mode corpus — identical row table to verify_wrapper_pyca.rs
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Target<'a> {
    Dns(&'a str),
    Ip(&'a str),
}

struct ServerCase<'a> {
    name: &'a str,
    fixture: &'a str,
    target: Target<'a>,
    expected_rust: RustOutcome,
}

#[rustfmt::skip]
fn server_cases() -> Vec<ServerCase<'static>> {
    use RustOutcome::*;
    use Target::*;
    vec![
        ServerCase { name: "exact_match",                       fixture: "host-exact-foo.der",              target: Dns("foo.example.com"),     expected_rust: Ok },
        ServerCase { name: "exact_mismatch",                    fixture: "host-exact-foo.der",              target: Dns("bar.example.com"),     expected_rust: NoMatchingSan },
        ServerCase { name: "exact_parent_does_not_match",       fixture: "host-exact-foo.der",              target: Dns("example.com"),         expected_rust: NoMatchingSan },
        ServerCase { name: "wildcard_matches_single_label",     fixture: "host-wildcard.der",               target: Dns("foo.example.com"),     expected_rust: Ok },
        ServerCase { name: "wildcard_parent_rejected",          fixture: "host-wildcard.der",               target: Dns("example.com"),         expected_rust: NoMatchingSan },
        ServerCase { name: "wildcard_deeper_rejected",          fixture: "host-wildcard.der",               target: Dns("foo.bar.example.com"), expected_rust: NoMatchingSan },
        ServerCase { name: "wildcard_partial_label_rejected",   fixture: "host-wildcard-partial-label.der", target: Dns("foo.example.com"),     expected_rust: NoMatchingSan },
        ServerCase { name: "wildcard_internal_rejected",        fixture: "host-wildcard-internal.der",      target: Dns("foo.bar.example.com"), expected_rust: NoMatchingSan },
        ServerCase { name: "wildcard_public_suffix_rejected",   fixture: "host-wildcard-tld.der",           target: Dns("foo.com"),             expected_rust: NoMatchingSan },
        ServerCase { name: "case_san_upper_target_lower",       fixture: "host-mixed-case-san.der",         target: Dns("foo.example.com"),     expected_rust: Ok },
        ServerCase { name: "case_san_lower_target_upper",       fixture: "host-exact-foo.der",              target: Dns("FOO.example.com"),     expected_rust: Ok },
        ServerCase { name: "idn_alabel_san_alabel_target",      fixture: "host-idn-alabel.der",             target: Dns("xn--bcher-kva.example"), expected_rust: Ok },
        ServerCase { name: "ipv4_san_matches_ipv4_target",      fixture: "host-ipv4.der",                   target: Ip("192.0.2.5"),            expected_rust: Ok },
        ServerCase { name: "ipv4_san_mismatch",                 fixture: "host-ipv4.der",                   target: Ip("192.0.2.6"),            expected_rust: NoMatchingSan },
        ServerCase { name: "ipv6_san_matches_ipv6_target",      fixture: "host-ipv6.der",                   target: Ip("2001:db8::1"),          expected_rust: Ok },
        ServerCase { name: "ipv6_san_mismatch",                 fixture: "host-ipv6.der",                   target: Ip("2001:db8::2"),          expected_rust: NoMatchingSan },
        ServerCase { name: "ipv4_san_v6_target_rejected",       fixture: "host-ipv4.der",                   target: Ip("2001:db8::42"),         expected_rust: NoMatchingSan },
        ServerCase { name: "dns_san_ip_target_rejected",        fixture: "host-exact-foo.der",              target: Ip("192.0.2.5"),            expected_rust: NoMatchingSan },
        ServerCase { name: "multi_san_first_matches",           fixture: "host-multi-san.der",              target: Dns("api.example.com"),     expected_rust: Ok },
        ServerCase { name: "multi_san_middle_matches",          fixture: "host-multi-san.der",              target: Dns("www.example.com"),     expected_rust: Ok },
        ServerCase { name: "multi_san_wildcard_matches",        fixture: "host-multi-san.der",              target: Dns("static.cdn.example.com"), expected_rust: Ok },
        ServerCase { name: "multi_san_none_match",              fixture: "host-multi-san.der",              target: Dns("other.example.com"),   expected_rust: NoMatchingSan },
        ServerCase { name: "missing_san_rejected",              fixture: "leaf-no-san.der",                 target: Dns("foo.example.com"),     expected_rust: MissingSan },
    ]
}

// ---------------------------------------------------------------------------
// Test driver
// ---------------------------------------------------------------------------

#[test]
fn verify_tls_server_diff_against_openssl() {
    let root = load_fixture("root.der");
    let anchors = [TrustAnchor::from_cert(root.clone())];

    let mut rows: Vec<Row> = Vec::new();
    for case in server_cases() {
        let leaf = load_fixture(case.fixture);
        let leaf_for_chain = leaf.clone();
        let chain = [leaf_for_chain];

        // Rust verdict via verify_tls_server under Rfc5280Profile.
        // (Same profile choice as hostname_corpus.rs and
        // verify_wrapper_pyca.rs — exposes IdentityError outcomes rather
        // than promoting SAN-absent to Error::Path under BasicTlsProfile.)
        let server_name = match case.target {
            Target::Dns(s) => ServerName::dns_name(s).expect("parse DNS"),
            Target::Ip(s) => ServerName::ip_address(s).expect("parse IP"),
        };
        let rust = RustOutcome::from_result(verify_tls_server(
            &chain,
            &anchors,
            &server_name,
            &Rfc5280Profile,
            NOW,
            &DefaultVerifier,
            &NoRevocation,
            &NoAiaFetcher,
        ));
        assert_eq!(
            rust, case.expected_rust,
            "Rust outcome diverged from hostname_corpus expectation for \
             {} (fixture {}, target {:?})",
            case.name, case.fixture, case.target,
        );

        // OpenSSL verdict via -purpose sslserver -verify_hostname/-verify_ip.
        let diff_chain = make_diff_chain(&leaf, &root, &case);
        let args = build_args(&case);
        let openssl =
            expect_openssl_available(oracles::openssl::verify_with_args(&diff_chain, &args));
        let kind = classify(rust.is_pass(), openssl.is_pass());

        rows.push(Row {
            case: case.name.to_string(),
            fixture: case.fixture.to_string(),
            target: format!("{:?}", case.target),
            rust: format!("{rust:?}"),
            openssl: openssl_label(&openssl),
            kind,
        });
    }

    eprintln!();
    eprintln!("=== verify_tls_server diff vs `openssl verify -purpose sslserver` ===");
    emit_matrix(&rows);
    let summary = summarize(&rows);
    eprintln!();
    eprintln!(
        "server: {n} cases — {agree} agree, {looser} Rust-looser, {stricter} Rust-stricter",
        n = rows.len(),
        agree = summary.agree,
        looser = summary.looser,
        stricter = summary.stricter,
    );

    // Same hard invariant as the pyca counterpart: zero Rust-looser cases.
    // Rust-stricter divergences are allowed but loud — they go in the
    // baseline-verify-openssl.md table as documented semantic differences.
    assert_eq!(
        summary.looser, 0,
        "server: no Rust-looser cases tolerated — OpenSSL refused while \
         verify_tls_server passed; investigate"
    );
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

fn build_args<'a>(case: &'a ServerCase<'a>) -> oracles::openssl::VerifyArgs<'a> {
    let mut args = oracles::openssl::VerifyArgs {
        purpose: Some("sslserver"),
        ..oracles::openssl::VerifyArgs::default()
    };
    match case.target {
        Target::Dns(s) => args.verify_hostname = Some(s),
        Target::Ip(s) => args.verify_ip = Some(s),
    }
    args
}

fn make_diff_chain(leaf: &Certificate, root: &Certificate, case: &ServerCase<'_>) -> Chain {
    Chain {
        certs_der: vec![cert_der(leaf), cert_der(root)],
        crls: Vec::new(),
        root_in_chain: true,
        label: case.name.to_string(),
        validation_time_unix: Some(NOW),
    }
}

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
    target: String,
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
        "{:38}  {:34}  {:28}  {:18}  {:7}  agreement",
        "case", "fixture", "target", "rust", "openssl"
    );
    eprintln!("{}", "-".repeat(150));
    for r in rows {
        eprintln!(
            "{:38}  {:34}  {:28}  {:18}  {:7}  {:?}",
            r.case, r.fixture, r.target, r.rust, r.openssl, r.kind
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
