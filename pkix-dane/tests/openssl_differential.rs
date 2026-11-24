//! Differential test: does `pkix-dane` agree with OpenSSL's DANE engine?
//!
//! `fixtures/digests.txt` already uses `openssl dgst` as the oracle for the
//! *hashing*. This file goes after the layer above it — the per-usage match
//! decision — by driving OpenSSL's own DANE implementation and comparing
//! verdicts on identical inputs.
//!
//! The method is an actual TLS handshake, because that is the only interface
//! OpenSSL exposes to its DANE engine: `openssl s_server` presents a
//! certificate and `openssl s_client -dane_tlsa_rrdata` validates it against a
//! TLSA record supplied on the command line. OpenSSL reports a failure to
//! match as `verify error:num=65:no matching DANE TLSA records`
//! (`X509_V_ERR_DANE_NO_MATCH`), which is the signal read here.
//!
//! `-dane_ee_no_namechecks` is passed throughout. OpenSSL applies name checks
//! to DANE-EE by default; RFC 7671 §5.1 says a DANE-EE match stands on its
//! own, and `verify_dane_ee` implements that. Disabling them narrows the
//! comparison to the matching decision itself, which is what is under test
//! here — the fixture's SAN matches anyway, so it changes no outcome.
//!
//! # Skipping
//!
//! Everything here needs an `openssl` binary with DANE support and a loopback
//! socket. Where either is missing the test prints why and passes rather than
//! failing: a differential oracle that cannot run is an absent oracle, not a
//! defect in the code under test. Run with `--nocapture` to see skip reasons.

mod support;

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use pkix_dane::{
    verify_dane_ee, DaneError, PresentedCert, TlsaMatchingType, TlsaRecord, TlsaSelector, TlsaUsage,
};
use support::{hex, parse, secure};
use x509_cert::Certificate;

/// Common name and SAN of the generated server certificate, and the DANE base
/// domain handed to `s_client`.
const DOMAIN: &str = "dane-differential.test";

/// Kills the `s_server` child on drop, including when a test panics.
struct ServerGuard(Child);

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Runs `openssl` with `args`, returning combined stdout+stderr.
fn openssl(args: &[&str]) -> Option<String> {
    let out = Command::new("openssl").args(args).output().ok()?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Some(text)
}

/// Whether this OpenSSL build exposes the DANE flags this test needs.
fn openssl_has_dane() -> bool {
    openssl(&["s_client", "-help"]).is_some_and(|h| h.contains("-dane_tlsa_rrdata"))
}

/// Generates a self-signed server certificate in `dir`.
///
/// Self-signed is adequate: this file compares DANE-EE matching, which
/// consults no issuer. Keys are written under `CARGO_TARGET_TMPDIR` and never
/// committed, which is why this test generates its own material rather than
/// reusing `fixtures/` — those fixtures deliberately ship without keys.
fn generate_server_cert(dir: &Path, stem: &str) -> Option<(PathBuf, PathBuf, Vec<u8>)> {
    let key = dir.join(format!("{stem}.key.pem"));
    let pem = dir.join(format!("{stem}.pem"));
    let der = dir.join(format!("{stem}.der"));

    openssl(&[
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:prime256v1",
        "-keyout",
        key.to_str()?,
        "-out",
        pem.to_str()?,
        "-days",
        "365",
        "-nodes",
        "-subj",
        &format!("/CN={DOMAIN}"),
        "-addext",
        &format!("subjectAltName=DNS:{DOMAIN}"),
        // Distinct keys per stem come free: `req -newkey` generates a fresh
        // key each call, so the second certificate differs in both bytes and
        // public key.
    ])?;
    openssl(&[
        "x509",
        "-in",
        pem.to_str()?,
        "-outform",
        "DER",
        "-out",
        der.to_str()?,
    ])?;

    let der_bytes = std::fs::read(&der).ok()?;
    Some((pem, key, der_bytes))
}

/// Asks the OS for a free loopback port by binding and immediately releasing.
///
/// Inherently racy — another process could take the port in between — but the
/// alternative is a hardcoded port, which collides with concurrent test runs
/// far more often than this loses a race.
fn free_port() -> Option<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").ok()?;
    let port = listener.local_addr().ok()?.port();
    drop(listener);
    Some(port)
}

/// Starts `s_server` and waits for it to accept connections.
fn start_server(cert: &Path, key: &Path, port: u16) -> Option<ServerGuard> {
    let child = Command::new("openssl")
        .args([
            "s_server",
            "-cert",
            cert.to_str()?,
            "-key",
            key.to_str()?,
            "-port",
            &port.to_string(),
            "-quiet",
            "-naccept",
            "64",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let guard = ServerGuard(child);

    // Poll rather than sleep a fixed interval: the server is usually ready in
    // milliseconds, and a fixed sleep would be both slower and less reliable.
    for _ in 0..50 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Some(guard);
        }
        std::thread::sleep(std::time::Duration::from_millis(40));
    }
    None
}

/// OpenSSL's verdict on one TLSA record.
#[derive(Debug, PartialEq, Eq)]
enum OpensslVerdict {
    Matched,
    NoMatch,
}

/// Asks OpenSSL whether `rrdata` matches the certificate the server presents.
///
/// `rrdata` is presentation form: `"<usage> <selector> <matching> <hex>"`.
fn ask_openssl(port: u16, rrdata: &str) -> Option<OpensslVerdict> {
    let out = Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &format!("127.0.0.1:{port}"),
            "-dane_tlsa_domain",
            DOMAIN,
            "-dane_tlsa_rrdata",
            rrdata,
            "-dane_ee_no_namechecks",
            "-verify_return_error",
        ])
        .stdin(Stdio::null())
        .output()
        .ok()?;
    let text = {
        let mut t = String::from_utf8_lossy(&out.stdout).into_owned();
        t.push_str(&String::from_utf8_lossy(&out.stderr));
        t
    };

    // num=65 is X509_V_ERR_DANE_NO_MATCH.
    if text.contains("num=65") {
        Some(OpensslVerdict::NoMatch)
    } else if text.contains("CN = dane-differential.test") || text.contains("Verify return code: 0")
    {
        Some(OpensslVerdict::Matched)
    } else {
        // Anything else means the handshake failed for an unrelated reason,
        // and comparing verdicts would be meaningless.
        None
    }
}

/// This crate's verdict on the same record.
fn ask_pkix_dane(cert_der: &[u8], parsed: &Certificate, record: TlsaRecord) -> OpensslVerdict {
    let presented = PresentedCert::new(cert_der, parsed);
    let response = secure(vec![record]);
    match verify_dane_ee(&presented, &response) {
        Ok(_) => OpensslVerdict::Matched,
        Err(DaneError::NoMatch { .. }) => OpensslVerdict::NoMatch,
        Err(other) => panic!("unexpected error from verify_dane_ee: {other}"),
    }
}

/// Computes the association data OpenSSL would expect, using `openssl dgst` —
/// never this crate's own hashing, which is the point of a differential.
fn association_data(
    dir: &Path,
    stem: &str,
    cert_pem: &Path,
    selector: TlsaSelector,
    matching: TlsaMatchingType,
) -> Option<Vec<u8>> {
    let content = dir.join(format!("{stem}.selected.bin"));
    match selector {
        TlsaSelector::Cert => {
            openssl(&[
                "x509",
                "-in",
                cert_pem.to_str()?,
                "-outform",
                "DER",
                "-out",
                content.to_str()?,
            ])?;
        }
        TlsaSelector::Spki => {
            let pubkey = dir.join(format!("{stem}.pub.pem"));
            let text = openssl(&["x509", "-in", cert_pem.to_str()?, "-noout", "-pubkey"])?;
            std::fs::write(&pubkey, text).ok()?;
            openssl(&[
                "pkey",
                "-pubin",
                "-in",
                pubkey.to_str()?,
                "-outform",
                "DER",
                "-out",
                content.to_str()?,
            ])?;
        }
        _ => return None,
    }

    match matching {
        TlsaMatchingType::Full => std::fs::read(&content).ok(),
        TlsaMatchingType::Sha256 | TlsaMatchingType::Sha512 => {
            let alg = if matching == TlsaMatchingType::Sha256 {
                "-sha256"
            } else {
                "-sha512"
            };
            let out = openssl(&["dgst", alg, "-hex", content.to_str()?])?;
            let digest = out.rsplit('=').next()?.trim().to_owned();
            Some(hex(&digest))
        }
        _ => None,
    }
}

#[test]
fn agrees_with_openssl_on_dane_ee_across_the_assigned_grid() {
    if !openssl_has_dane() {
        println!("SKIP: no openssl binary with -dane_tlsa_rrdata support");
        return;
    }

    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("dane-differential");
    if std::fs::create_dir_all(&dir).is_err() {
        println!("SKIP: could not create {}", dir.display());
        return;
    }

    let Some((cert_pem, cert_key, cert_der)) = generate_server_cert(&dir, "server") else {
        println!("SKIP: could not generate a server certificate");
        return;
    };
    let parsed = parse(&cert_der);

    // A second, unrelated certificate supplies the negative cases. Flipping a
    // bit in the correct association data looked simpler but is a worse
    // negative: for matching type Full the result is a malformed certificate
    // or SPKI, which OpenSSL rejects as bad rrdata rather than reporting as a
    // non-match, so the two implementations are no longer being asked the same
    // question. Another valid certificate's data is well-formed and simply
    // wrong, which is exactly the case that matters.
    let Some((other_pem, _, _)) = generate_server_cert(&dir, "other") else {
        println!("SKIP: could not generate the second certificate");
        return;
    };

    let Some(port) = free_port() else {
        println!("SKIP: could not find a free loopback port");
        return;
    };
    let Some(_server) = start_server(&cert_pem, &cert_key, port) else {
        println!("SKIP: openssl s_server did not come up on port {port}");
        return;
    };

    let selectors = [(TlsaSelector::Cert, 0_u8), (TlsaSelector::Spki, 1_u8)];
    let matchings = [
        (TlsaMatchingType::Full, 0_u8),
        (TlsaMatchingType::Sha256, 1_u8),
        (TlsaMatchingType::Sha512, 2_u8),
    ];

    let mut compared = 0_usize;
    for (selector, sel_octet) in selectors {
        for (matching, match_octet) in matchings {
            let Some(data) = association_data(&dir, "server", &cert_pem, selector, matching) else {
                println!("SKIP case {selector:?}/{matching:?}: could not compute rrdata");
                continue;
            };
            let Some(wrong) = association_data(&dir, "other", &other_pem, selector, matching)
            else {
                println!("SKIP negative {selector:?}/{matching:?}: could not compute rrdata");
                continue;
            };

            // Positive case: the correct association data.
            let rrdata = format!(
                "3 {sel_octet} {match_octet} {}",
                data.iter().map(|b| format!("{b:02x}")).collect::<String>()
            );
            if let Some(theirs) = ask_openssl(port, &rrdata) {
                let ours = ask_pkix_dane(
                    &cert_der,
                    &parsed,
                    TlsaRecord::new(TlsaUsage::DaneEe, selector, matching, data.clone()),
                );
                assert_eq!(
                    ours, theirs,
                    "disagreement on a matching record, selector {selector:?} \
                     matching {matching:?}"
                );
                assert_eq!(
                    ours,
                    OpensslVerdict::Matched,
                    "the correct association data should match, selector {selector:?} \
                     matching {matching:?}"
                );
                compared += 1;
            } else {
                println!("SKIP positive case {selector:?}/{matching:?}: handshake inconclusive");
            }

            // Negative case: another certificate's association data — valid,
            // well-formed, and wrong. Stays *usable* for every matching type,
            // so this exercises the comparison rather than the usability
            // filter.
            assert_ne!(
                wrong, data,
                "the two certificates should differ under {selector:?}/{matching:?}"
            );
            let rrdata = format!(
                "3 {sel_octet} {match_octet} {}",
                wrong.iter().map(|b| format!("{b:02x}")).collect::<String>()
            );
            if let Some(theirs) = ask_openssl(port, &rrdata) {
                let ours = ask_pkix_dane(
                    &cert_der,
                    &parsed,
                    TlsaRecord::new(TlsaUsage::DaneEe, selector, matching, wrong),
                );
                assert_eq!(
                    ours, theirs,
                    "disagreement on a non-matching record, selector {selector:?} \
                     matching {matching:?}"
                );
                assert_eq!(
                    ours,
                    OpensslVerdict::NoMatch,
                    "corrupted association data should not match, selector {selector:?} \
                     matching {matching:?}"
                );
                compared += 1;
            } else {
                println!("SKIP negative case {selector:?}/{matching:?}: handshake inconclusive");
            }
        }
    }

    println!("compared {compared} verdicts against OpenSSL's DANE engine");
    assert!(
        compared >= 2,
        "the differential should have compared at least one positive and one \
         negative case; got {compared}. If every case skipped, OpenSSL ran but \
         no handshake reached a verdict, which is itself worth investigating."
    );
}
