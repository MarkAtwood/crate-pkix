//! External oracle: `openssl verify` subprocess.
//!
//! Primary external oracle for the diff harness. AGENTS.md names OpenSSL as
//! an acceptable test oracle, and `openssl verify` is the de-facto reference
//! for X.509 path validation behaviour in the wild.
//!
//! ## Subprocess discipline
//!
//! * No shell. We invoke `openssl` directly via `std::process::Command` with
//!   explicit `arg(...)` calls. Every chain cert lands in a `tempfile::TempDir`
//!   on the filesystem with a fixed filename — there is no untrusted input
//!   anywhere on the command line.
//! * RAII cleanup via `tempfile`. Tempdir is dropped at function exit, success
//!   or failure.
//! * Binary location: `openssl` from `$PATH` by default. Override via
//!   `$PKIX_DIFFTEST_OPENSSL_BIN` for testing the missing-binary path or
//!   pinning to a specific build.
//!
//! ## OpenSSL version pinning (or lack thereof)
//!
//! This oracle binds to whatever `openssl` happens to be on `$PATH`. That is
//! intentional: divergences between OpenSSL major versions (1.1 vs 3.0 vs 3.x)
//! are themselves a divergence class the harness is meant to surface. If a
//! caller needs reproducible reports, pin the binary via the env var and note
//! the version in the report header.
//!
//! ## Exit code semantics (OpenSSL 3.0)
//!
//! Empirically (Ubuntu 24.04, OpenSSL 3.0.13):
//! * Exit 0  — verification passed.
//! * Exit 2  — verification failed (e.g. signature, expiry, name constraint).
//!   Despite the bead's working assumption that exit 1 = fail, exit 2 = usage,
//!   `openssl verify` actually emits exit 2 for verification failures and the
//!   diagnostic prints to stderr. Exit 1 has not been observed in our probes.
//!
//! We treat *any* non-zero exit as a verification failure with the reason
//! lifted from stderr. Genuine harness errors — binary not found, the
//! tempdir could not be created, an output line could not be parsed as UTF-8
//! — are propagated as `io::Error` so the classifier can distinguish them
//! from real `Verdict::Fail`s.

use std::io;
use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

use crate::{Chain, Verdict};

/// Environment variable name to override the `openssl` binary path. Tests use
/// this to inject a missing-binary path; users can use it to pin a specific
/// OpenSSL build for reproducible reports.
pub const OPENSSL_BIN_ENV: &str = "PKIX_DIFFTEST_OPENSSL_BIN";

/// Run `openssl verify` over the chain, picking the binary from
/// `$PKIX_DIFFTEST_OPENSSL_BIN` if set, else `openssl` from `$PATH`.
///
/// See [`verify_with_bin`] for the same semantics with an explicit binary path
/// (used by tests that want to exercise the missing-binary error path without
/// touching process-global env state). See [`verify_with_args`] for the
/// purpose-aware entry point used by the wrapper-level differential tests
/// (PKIX-fmtv.18.x).
///
/// Returns:
/// * `Ok(Verdict::Pass)` when OpenSSL exits 0.
/// * `Ok(Verdict::Fail { reason })` when OpenSSL exits non-zero. `reason` is
///   the OpenSSL error string lifted from stderr, e.g. `certificate signature
///   failure` or `certificate is not yet valid`.
/// * `Err(io::Error)` for harness errors: missing `openssl` binary, tempdir
///   creation failure, malformed-input chain, etc.
pub fn verify(chain: &Chain) -> io::Result<Verdict> {
    let bin = std::env::var(OPENSSL_BIN_ENV).unwrap_or_else(|_| "openssl".to_string());
    verify_with_bin(chain, &bin)
}

/// Per-purpose / per-identity flags for `openssl verify`. Used by the
/// wrapper-level differential tests (PKIX-fmtv.18.x) so that each
/// `verify_*` wrapper can be compared against the matching
/// `openssl verify -purpose ... -verify_hostname/email/ip ...` invocation.
///
/// The all-default value (everything `None`) reproduces the chain-shape
/// behaviour of [`verify`] / [`verify_with_bin`] — those entry points are
/// kept stable so the existing chain-shape callers (PKITS / x509-limbo /
/// pem-tree corpora) are unaffected.
///
/// At most one of `verify_hostname` / `verify_email` / `verify_ip` should
/// be set per call; OpenSSL accepts all three but the wrapper-level diff
/// always binds a single identity. The struct does not enforce this — the
/// caller's matrix-driver code is responsible for picking the right field.
#[derive(Clone, Debug, Default)]
pub struct VerifyArgs<'a> {
    /// OpenSSL purpose, e.g. `sslserver`, `sslclient`, `smimesign`,
    /// `smimeencrypt`, `codesign`, `timestampsign`, `ocsphelper`. Passed
    /// through as `-purpose <value>`.
    pub purpose: Option<&'a str>,
    /// Hostname to bind against the leaf's SAN dNSName entries. Passed
    /// through as `-verify_hostname <value>`. RFC 6125 §6.4 wildcard /
    /// case / IDN semantics are OpenSSL's responsibility — the diff
    /// surface is exactly the comparison `verify_tls_server` /
    /// `verify_tls_client_dns` need.
    pub verify_hostname: Option<&'a str>,
    /// Mailbox to bind against rfc822Name SAN entries. Passed through as
    /// `-verify_email <value>`. RFC 5280 §4.2.1.6 case-folding semantics
    /// are OpenSSL's responsibility.
    pub verify_email: Option<&'a str>,
    /// IP literal to bind against iPAddress SAN entries. Passed through
    /// as `-verify_ip <value>`. Both v4 dotted-decimal and v6
    /// colon-hex forms are accepted by OpenSSL.
    pub verify_ip: Option<&'a str>,
}

/// `openssl verify` over the chain with per-purpose / per-identity flags.
///
/// Picks the binary the same way [`verify`] does
/// (`$PKIX_DIFFTEST_OPENSSL_BIN`, else `openssl` from `$PATH`).
///
/// See [`VerifyArgs`] for the flag set this wraps. The plain [`verify`]
/// entry point is equivalent to calling this with
/// `VerifyArgs::default()`.
pub fn verify_with_args(chain: &Chain, args: &VerifyArgs<'_>) -> io::Result<Verdict> {
    let bin = std::env::var(OPENSSL_BIN_ENV).unwrap_or_else(|_| "openssl".to_string());
    verify_with_bin_and_args(chain, &bin, args)
}

/// Same as [`verify`] but takes the binary path as an explicit argument.
///
/// The chain must end in the trust anchor (`Chain::root_in_chain == true`);
/// the last cert is used as `-CAfile` and everything before the leaf is
/// concatenated as `-untrusted`.
///
/// Tests use this entry point instead of the env-driven [`verify`] so they
/// can race-isolate from other tests in the same `cargo test` run.
pub fn verify_with_bin(chain: &Chain, bin: &str) -> io::Result<Verdict> {
    verify_with_bin_and_args(chain, bin, &VerifyArgs::default())
}

/// Combined entry point: explicit binary path AND per-purpose args.
///
/// Used by the wrapper-level differential test driver
/// (`tests/verify_wrapper_openssl_*.rs`) where the binary path must be
/// resolved once and reused across many chains, and where per-case args
/// vary.
pub fn verify_with_bin_and_args(
    chain: &Chain,
    bin: &str,
    args: &VerifyArgs<'_>,
) -> io::Result<Verdict> {
    if !chain.root_in_chain {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "openssl oracle requires the trust anchor to be present as the last cert",
        ));
    }
    if chain.certs_der.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "openssl oracle requires at least 2 certs (leaf + root)",
        ));
    }

    let dir = TempDir::new()?;
    let has_intermediates = write_chain_to_tempdir(chain, dir.path())?;
    let has_crls = write_crls_to_tempdir(chain, dir.path())?;

    let mut cmd = Command::new(bin);
    cmd.arg("verify")
        .arg("-CAfile")
        .arg(dir.path().join("root.pem"));
    // Only pass `-untrusted` when we actually have intermediates. OpenSSL 3.0
    // errors on `-untrusted <empty-file>` ("Could not read any untrusted
    // certificates from ..."), surfaced via PKITS 4.16.1 / 4.8.15 / 4.8.19
    // (the 2-cert chains: root + leaf, no intermediates).
    if has_intermediates {
        cmd.arg("-untrusted")
            .arg(dir.path().join("intermediates.pem"));
    }
    // When the chain carries CRLs, hand them to OpenSSL and ask it to
    // check every cert in the chain (matching RFC 5280 §6.3 baseline). The
    // sibling pkix-path oracle (PKIX-emf1.2) checks revocation per cert too;
    // pyca (PKIX-emf1.4) is decided separately. -crl_check_all is the
    // OpenSSL flag that maps closest to "check every certificate including
    // intermediates" rather than only the leaf.
    if has_crls {
        cmd.arg("-CRLfile")
            .arg(dir.path().join("crls.pem"))
            .arg("-crl_check_all");
    }
    // When the corpus loader pinned a per-chain validation time (limbo),
    // pass it via `-attime <unix-seconds>`. OpenSSL 1.1+ accepts this flag
    // and uses it as the wall clock for notBefore/notAfter and CRL
    // thisUpdate/nextUpdate checks. When `None`, OpenSSL falls back to its
    // own current clock — same behaviour PKITS / PEM-tree have always had.
    if let Some(secs) = chain.validation_time_unix {
        cmd.arg("-attime").arg(secs.to_string());
    }
    // Wrapper-level diff arguments (PKIX-fmtv.18.1). Each is opt-in via the
    // VerifyArgs struct; the chain-shape callers via verify() /
    // verify_with_bin() pass VerifyArgs::default() and pay no overhead.
    if let Some(p) = args.purpose {
        cmd.arg("-purpose").arg(p);
    }
    if let Some(h) = args.verify_hostname {
        cmd.arg("-verify_hostname").arg(h);
    }
    if let Some(e) = args.verify_email {
        cmd.arg("-verify_email").arg(e);
    }
    if let Some(ip) = args.verify_ip {
        cmd.arg("-verify_ip").arg(ip);
    }
    let output = cmd.arg(dir.path().join("leaf.pem")).output().map_err(|e| {
        // Most useful failure: NotFound → "binary not on PATH". Pass
        // through other kinds (Permission, etc.) verbatim. We preserve
        // ErrorKind::NotFound because the caller (and tests) keys on it.
        if e.kind() == io::ErrorKind::NotFound {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "openssl binary not found: tried `{bin}` \
                         (set {OPENSSL_BIN_ENV} to override)"
                ),
            )
        } else {
            e
        }
    })?;

    if output.status.success() {
        return Ok(Verdict::Pass);
    }

    // Non-zero exit. Lift a useful reason out of stderr.
    let stderr = String::from_utf8_lossy(&output.stderr);
    Ok(Verdict::Fail {
        reason: extract_reason(&stderr),
    })
}

/// Write the chain into the tempdir as up to three files:
/// `root.pem`, `intermediates.pem` (skipped when empty), `leaf.pem`.
///
/// Returns `true` when at least one intermediate exists and was written.
/// Callers use that to decide whether to pass `-untrusted` to `openssl
/// verify` — OpenSSL 3.0 rejects `-untrusted <empty-file>` with "Could not
/// read any untrusted certificates from ...".
fn write_chain_to_tempdir(chain: &Chain, dir: &Path) -> io::Result<bool> {
    let n = chain.certs_der.len();
    debug_assert!(n >= 2, "checked by caller");

    let leaf = der_to_pem(&chain.certs_der[0])?;
    std::fs::write(dir.join("leaf.pem"), leaf)?;

    let root = der_to_pem(&chain.certs_der[n - 1])?;
    std::fs::write(dir.join("root.pem"), root)?;

    let intermediate_count = n.saturating_sub(2);
    if intermediate_count == 0 {
        return Ok(false);
    }
    let mut intermediates = String::new();
    for der in &chain.certs_der[1..n - 1] {
        intermediates.push_str(&der_to_pem(der)?);
    }
    std::fs::write(dir.join("intermediates.pem"), intermediates)?;
    Ok(true)
}

fn der_to_pem(der: &[u8]) -> io::Result<String> {
    pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, der)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("PEM encode: {e}")))
}

/// Write `chain.crls` into the tempdir as a single concatenated `crls.pem`.
///
/// Returns `true` when at least one CRL was written, `false` when the chain
/// carried no CRLs. The caller uses the return value to decide whether to
/// add `-CRLfile crls.pem -crl_check_all` to the command line — passing
/// those flags with an empty / non-existent CRL file would surface as an
/// OpenSSL load error rather than an honest "no CRLs to check" outcome.
///
/// Each DER CRL is wrapped in an `X509 CRL` PEM block. OpenSSL's `-CRLfile`
/// accepts a multi-block PEM file, so a single file is enough regardless of
/// `chain.crls.len()`.
fn write_crls_to_tempdir(chain: &Chain, dir: &Path) -> io::Result<bool> {
    if chain.crls.is_empty() {
        return Ok(false);
    }
    let mut concat = String::new();
    for der in &chain.crls {
        let pem = pem_rfc7468::encode_string("X509 CRL", pem_rfc7468::LineEnding::LF, der)
            .map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("CRL PEM encode: {e}"))
            })?;
        concat.push_str(&pem);
    }
    std::fs::write(dir.join("crls.pem"), concat)?;
    Ok(true)
}

/// Extract a useful single-line reason from `openssl verify` stderr.
///
/// OpenSSL 3 prints something like:
/// ```text
/// C = US, O = Test Certificates 2011, CN = Bad Signed CA
/// error 7 at 1 depth lookup: certificate signature failure
/// error ee.pem: verification failed
/// 80...:error:068000DC:asn1 encoding routines:...
/// ```
///
/// We want the second line's substring after the last `: `. Falls back to the
/// trimmed first non-empty stderr line if no `error N at M depth ...: ...`
/// line is present.
fn extract_reason(stderr: &str) -> String {
    // Strip leading-byte whitespace and BOMs that real-world OpenSSL outputs do
    // not produce, but a defensively-coded extractor should tolerate.
    for line in stderr.lines() {
        let trimmed = line.trim();
        if let Some(reason) = parse_error_line(trimmed) {
            return reason.to_string();
        }
    }
    // No structured line — fall back to whichever non-empty line we find first.
    stderr
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map_or_else(
            || "openssl verify failed (no diagnostic on stderr)".to_string(),
            str::to_string,
        )
}

/// Returns `Some(reason)` for a line shaped like
/// `error <N> at <depth> [lookup]: <reason>`. `<reason>` is the substring
/// after the last `: `, trimmed.
fn parse_error_line(line: &str) -> Option<&str> {
    if !line.starts_with("error ") {
        return None;
    }
    // "error <file>: verification failed" is a noise tail line — skip it.
    if line.ends_with(": verification failed") {
        return None;
    }
    // The structured form has " at " before the depth. Use that as a marker.
    if !line.contains(" at ") {
        return None;
    }
    // Reason is after the last ": ".
    line.rsplit_once(": ").map(|(_, reason)| reason.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_error_line_signature_failure() {
        let line = "error 7 at 1 depth lookup: certificate signature failure";
        assert_eq!(
            parse_error_line(line),
            Some("certificate signature failure")
        );
    }

    #[test]
    fn parse_error_line_not_yet_valid() {
        let line = "error 9 at 1 depth lookup: certificate is not yet valid";
        assert_eq!(parse_error_line(line), Some("certificate is not yet valid"));
    }

    #[test]
    fn parse_error_line_skips_verification_failed_tail() {
        let line = "error ee.pem: verification failed";
        assert_eq!(parse_error_line(line), None);
    }

    #[test]
    fn parse_error_line_skips_unrelated_lines() {
        assert_eq!(parse_error_line("C = US, O = Test, CN = Foo"), None);
        assert_eq!(parse_error_line(""), None);
        assert_eq!(parse_error_line("80...:error:068000DC:asn1..."), None);
    }

    #[test]
    fn extract_reason_full_stderr() {
        let stderr = "\
C = US, O = Test Certificates 2011, CN = Bad Signed CA
error 7 at 1 depth lookup: certificate signature failure
error ee.pem: verification failed
80...:error:068000DC:asn1 encoding routines:...
";
        assert_eq!(extract_reason(stderr), "certificate signature failure");
    }

    #[test]
    fn extract_reason_falls_back_to_first_line_when_no_structured_error() {
        let stderr =
            "Could not read certificate file from /dev/null\nUnable to load certificate file\n";
        assert_eq!(
            extract_reason(stderr),
            "Could not read certificate file from /dev/null"
        );
    }

    #[test]
    fn extract_reason_handles_empty_stderr() {
        let r = extract_reason("");
        assert!(r.contains("no diagnostic"));
    }
}
