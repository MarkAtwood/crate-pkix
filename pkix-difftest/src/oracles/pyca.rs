//! External oracle: pyca/cryptography Python sidecar.
//!
//! Wraps `pkix-difftest/python/pyca_oracle.py`, a Python script that calls
//! `cryptography.x509.verification.PolicyBuilder.build_client_verifier()` on
//! a chain piped in as JSON and prints a verdict JSON to stdout. AGENTS.md
//! names pyca/cryptography as one of the project's acceptable test oracles.
//!
//! ## Why a subprocess
//!
//! Inline interpreter via `PyO3` would lock the harness to a specific Python
//! ABI version and add ~500KB of binary size. The OpenSSL oracle is already
//! a subprocess; the per-call overhead (~30ms Python startup) is acceptable
//! for the harness (PKITS = 249 chains × 30ms = ~8s).
//!
//! ## Python interpreter resolution
//!
//! Order of preference:
//! 1. `$PYCA_DIFFTEST_PYTHON` env var (explicit pin / venv).
//! 2. `<repo-root>/pkix-difftest/python/.venv/bin/python` (matches the
//!    canonical bootstrap from `setup-venv.sh`).
//! 3. `python3` from `$PATH` (works only if the system `cryptography`
//!    package is ≥ 43.0; will exit 2 from the sidecar otherwise).
//!
//! See [`verify_with_python`] for the explicit-path entry point used by
//! tests.
//!
//! ## Failure semantics
//!
//! * `Ok(Verdict::Pass)` — sidecar exit 0, stdout JSON `{verdict: "pass"}`.
//! * `Ok(Verdict::Fail { reason })` — sidecar exit 0, stdout JSON
//!   `{verdict: "fail", reason: ...}`.
//! * `Err(io::Error)` — anything else: missing python, sidecar exit 1
//!   (parse error or harness-side cert failure), exit 2 (cryptography too
//!   old), unparseable stdout, missing sidecar script.
//!
//! Tests that exercise the harness end-to-end need a venv. Use
//! `pkix-difftest/python/setup-venv.sh` once before running them.

use std::io;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::{Chain, Verdict};

/// Environment variable to override the Python interpreter path.
pub const PYCA_PYTHON_ENV: &str = "PYCA_DIFFTEST_PYTHON";

/// Run the pyca sidecar over the chain, picking the Python interpreter from
/// the resolution order described in the module docs.
pub fn verify(chain: &Chain) -> io::Result<Verdict> {
    let python = resolve_python();
    let script = sidecar_script_path()?;
    verify_with_python(chain, &python, &script)
}

/// Same as [`verify`] but with the Python interpreter and sidecar script
/// path supplied explicitly. Tests use this entry point to race-isolate
/// from `$PYCA_DIFFTEST_PYTHON`.
pub fn verify_with_python(
    chain: &Chain,
    python: &Path,
    sidecar_script: &Path,
) -> io::Result<Verdict> {
    if !chain.root_in_chain {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "pyca oracle requires the trust anchor to be present as the last cert",
        ));
    }
    if chain.certs_der.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "pyca oracle requires at least 2 certs (leaf + root)",
        ));
    }

    let spec = build_spec_json(chain)?;

    let mut child = Command::new(python)
        .arg(sidecar_script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            // NotFound is the most useful failure to surface clearly.
            if e.kind() == io::ErrorKind::NotFound {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "pyca python interpreter not found: tried `{}` \
                         (set {PYCA_PYTHON_ENV} or run \
                         pkix-difftest/python/setup-venv.sh)",
                        python.display()
                    ),
                )
            } else {
                e
            }
        })?;

    // Write the spec to stdin and close it so the sidecar's `json.load`
    // sees EOF.
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "could not open sidecar stdin"))?;
        stdin.write_all(spec.as_bytes())?;
    } // stdin dropped → closed.

    let output = child.wait_with_output()?;
    if !output.status.success() {
        // Sidecar exit codes:
        //  1: harness/parse error → io::Error
        //  2: cryptography too old → io::Error
        //  other: anything else (signal, panic) → io::Error
        let stderr = String::from_utf8_lossy(&output.stderr);
        let kind = match output.status.code() {
            // Map "old cryptography" to NotFound so the caller sees it the
            // same way as "missing binary": both are "we can't even ask".
            Some(2) => io::ErrorKind::NotFound,
            _ => io::ErrorKind::Other,
        };
        return Err(io::Error::new(
            kind,
            format!(
                "pyca sidecar exited {} ({}): {}",
                output.status.code().unwrap_or(-1),
                stderr.trim().lines().next().unwrap_or(""),
                stderr.trim()
            ),
        ));
    }

    parse_verdict(&output.stdout)
}

fn build_spec_json(chain: &Chain) -> io::Result<String> {
    // Encode each cert as PEM and bucket into leaf / intermediates / roots.
    let n = chain.certs_der.len();
    debug_assert!(n >= 2);

    let leaf_pem = pem_rfc7468::encode_string(
        "CERTIFICATE",
        pem_rfc7468::LineEnding::LF,
        &chain.certs_der[0],
    )
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("PEM encode: {e}")))?;
    let root_pem = pem_rfc7468::encode_string(
        "CERTIFICATE",
        pem_rfc7468::LineEnding::LF,
        &chain.certs_der[n - 1],
    )
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("PEM encode: {e}")))?;
    let mut intermediates: Vec<String> = Vec::with_capacity(n.saturating_sub(2));
    for der in &chain.certs_der[1..n - 1] {
        intermediates.push(
            pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, der).map_err(
                |e| io::Error::new(io::ErrorKind::InvalidData, format!("PEM encode: {e}")),
            )?,
        );
    }

    // We use serde_json for the value the sidecar will deserialise — it
    // handles string escaping correctly even for certs with weird DN bytes
    // that contain quotes or backslashes once base64-encoded (PEM should
    // never have them, but defensive encoding is free).
    let spec = serde_json::json!({
        "leaf": leaf_pem,
        "intermediates": intermediates,
        "roots": [root_pem],
    });
    serde_json::to_string(&spec)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("JSON encode: {e}")))
}

fn parse_verdict(stdout: &[u8]) -> io::Result<Verdict> {
    let v: serde_json::Value = serde_json::from_slice(stdout).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "pyca sidecar stdout is not JSON: {e} (stdout: {:?})",
                String::from_utf8_lossy(stdout)
            ),
        )
    })?;
    let verdict = v.get("verdict").and_then(|x| x.as_str()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "pyca sidecar JSON missing \"verdict\" field",
        )
    })?;
    match verdict {
        "pass" => Ok(Verdict::Pass),
        "fail" => {
            let reason = v
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("(no reason supplied)")
                .to_string();
            Ok(Verdict::Fail { reason })
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("pyca sidecar JSON: unknown verdict {other:?}"),
        )),
    }
}

fn resolve_python() -> PathBuf {
    if let Ok(env_path) = std::env::var(PYCA_PYTHON_ENV) {
        return PathBuf::from(env_path);
    }
    if let Some(venv) = default_venv_python() {
        if venv.exists() {
            return venv;
        }
    }
    PathBuf::from("python3")
}

/// Returns the path to the .venv-shipped Python interpreter relative to the
/// repository root (`<repo>/pkix-difftest/python/.venv/bin/python`), or
/// `None` if we cannot locate the repo root from the current working
/// directory.
fn default_venv_python() -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    // The harness binary is usually run from the workspace root. Walk up
    // looking for `pkix-difftest/python/.venv/bin/python`.
    for ancestor in cwd.ancestors() {
        let candidate = ancestor.join("pkix-difftest/python/.venv/bin/python");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn sidecar_script_path() -> io::Result<PathBuf> {
    // Resolved relative to the workspace root, similarly to the venv.
    let cwd = std::env::current_dir()?;
    for ancestor in cwd.ancestors() {
        let candidate = ancestor.join("pkix-difftest/python/pyca_oracle.py");
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "pkix-difftest/python/pyca_oracle.py not found relative to current directory",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_verdict_pass() {
        let v = parse_verdict(br#"{"verdict": "pass", "reason": null}"#).unwrap();
        assert_eq!(v, Verdict::Pass);
    }

    #[test]
    fn parse_verdict_fail_with_reason() {
        let v = parse_verdict(br#"{"verdict": "fail", "reason": "boom"}"#).unwrap();
        assert_eq!(
            v,
            Verdict::Fail {
                reason: "boom".to_string()
            }
        );
    }

    #[test]
    fn parse_verdict_fail_without_reason() {
        let v = parse_verdict(br#"{"verdict": "fail"}"#).unwrap();
        match v {
            Verdict::Fail { reason } => assert!(reason.contains("no reason")),
            Verdict::Pass => panic!("expected Fail"),
        }
    }

    #[test]
    fn parse_verdict_rejects_unknown_verdict() {
        let err = parse_verdict(br#"{"verdict": "maybe"}"#).unwrap_err();
        assert!(err.to_string().contains("unknown verdict"));
    }

    #[test]
    fn parse_verdict_rejects_missing_verdict() {
        let err = parse_verdict(br#"{"reason": "x"}"#).unwrap_err();
        assert!(err.to_string().contains("missing \"verdict\""));
    }

    #[test]
    fn parse_verdict_rejects_non_json() {
        let err = parse_verdict(b"hello world").unwrap_err();
        assert!(err.to_string().contains("not JSON"));
    }
}
