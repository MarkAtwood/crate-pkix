#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! Subprocess + NDJSON-parsing bridge to [ZLint][zlint].
//!
//! `pkix-zlint-bridge` provides Rust-shaped infrastructure for running
//! zlint on X.509 certificates: subprocess plumbing, output parsing,
//! verdict normalization, and a per-certificate cache. It is consumed by:
//!
//! - **`pkix-policy-zlint`** — a runtime adapter that exposes each of
//!   zlint's ~400 checks as a workspace [`pkix_lint::Lint`] impl, so
//!   that compliance-rule selection happens at the
//!   [`pkix_lint::LintRunner`] level.
//! - **`pkix-difftest`**'s zlint oracle — differential testing of
//!   workspace lints against zlint's verdicts on the same certificate.
//!
//! Per AGENTS.md non-negotiable #5 (three-mode policy-class model), the
//! workspace does not transcribe CA/B Forum or other industry-forum
//! rules into Rust. Instead, this bridge defers to zlint at runtime
//! and normalises its output into the workspace's [`pkix_lint`]
//! vocabulary. zlint stays the source of truth for the checks it
//! covers; the workspace contributes the framework, not the policy.
//!
//! Per AGENTS.md non-negotiable #6 (cache-friendliness), the bridge
//! exposes both a single-certificate entry point and a batch entry
//! point, with a per-certificate verdict cache so adapters spinning
//! up one `Lint` impl per zlint check pay only one subprocess cost
//! per certificate, not one per check.
//!
//! # Status
//!
//! Version 0.0.0. [`ZlintBridge::enumerate_lints`] is functional;
//! per-certificate verdicts (`run_on_cert` + cache, `run_on_certs`
//! batch) arrive via PKIX-jy95.7.3 and PKIX-jy95.7.4.
//!
//! # Design decisions (frozen)
//!
//! - **Granularity** (PKIX-jy95.1): per-check verdicts. The adapter
//!   layer can then surface each check as an individual [`pkix_lint::Lint`].
//! - **Severity mapping** (PKIX-jy95.2): zlint catalog severities
//!   `notice` / `warning` / `error` / `fatal` map to [`pkix_lint::Severity`]
//!   `Notice` / `Warn` / `Error` / `Fatal`. Per-cert verdicts `NA` / `NE`
//!   collapse to [`Verdict::NotApplicable`] (not-applicable is not a
//!   compliance signal); `pass` maps to [`Verdict::Pass`]; the four
//!   failing verdict levels map to like-named [`Verdict`] variants.
//! - **Batch shape** (PKIX-jy95.3): multi-file invocation
//!   (`zlint <f1> <f2> ...`) with NDJSON output, one JSON object per
//!   line in input order. zlint does not support multi-cert stdin
//!   streaming, so the bridge writes inputs to temporary files for
//!   the batch entry point.
//! - **Error discrimination** (PKIX-jy95.4): bridge-level errors
//!   ([`BridgeError`]) fail the whole call; per-certificate errors
//!   ([`PerCertError`]) live as `Result` values inside batch returns
//!   so a single malformed cert does not poison the batch.
//!
//! [zlint]: https://github.com/zmap/zlint

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

/// A single zlint check's per-certificate verdict.
///
/// Mirrors zlint's `LintStatus` vocabulary
/// (`v3/lint/result.go`). The not-applicable cases (`NA`, `NE`)
/// collapse into [`Verdict::NotApplicable`]: from a compliance
/// standpoint, both mean "this check did not run on this cert," and
/// the bridge does not need to distinguish "not applicable to this
/// cert kind" from "not effective at the cert's profile."
///
/// Ordering follows zlint's severity ordering plus the
/// `NotApplicable < Pass` convention used in [`pkix_lint::Severity`]:
/// `NotApplicable < Pass < Notice < Warn < Error < Fatal`. The total
/// order is meaningful and matches the workspace's general worst-of
/// aggregation semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Verdict {
    /// Check did not apply to the certificate (zlint `NA` or `NE`).
    NotApplicable,
    /// Check passed (zlint `pass`).
    Pass,
    /// Check produced a notice-level finding (zlint `notice`).
    Notice,
    /// Check produced a warning-level finding (zlint `warn`).
    Warn,
    /// Check produced an error-level finding (zlint `error`).
    Error,
    /// Check produced a fatal-level finding (zlint `fatal`).
    Fatal,
}

// ---------------------------------------------------------------------------
// Catalog metadata
// ---------------------------------------------------------------------------

/// Static catalog metadata for one zlint check.
///
/// Produced by `ZlintBridge::enumerate_lints` (PKIX-jy95.7.2) by
/// parsing the output of `zlint -list-lints-json`. The `severity`
/// field is the *declared* severity from the catalog (derived from
/// the check name prefix per zlint convention: `e_*` = `Error`,
/// `w_*` = `Warn`, `n_*` = `Notice`) and does not change per
/// certificate. Per-certificate outcomes are reported via
/// [`Verdict`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ZlintLintInfo {
    /// Stable check identifier (e.g., `e_basic_constraints_not_critical`).
    pub check_id: String,
    /// Human-readable description from zlint's catalog.
    pub description: String,
    /// Citation (e.g., `BRs: 7.1.2.7.7`, `RFC 5280: 4.2.1.9`).
    pub citation: String,
    /// Source body (e.g., `CABF_BR`, `RFC5280`, `Apple`).
    pub source: String,
    /// Declared severity from the catalog.
    pub severity: pkix_lint::Severity,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Bridge-level errors that fail the whole call.
///
/// These errors indicate something is wrong with the bridge itself or
/// with the zlint binary — not with any individual certificate.
/// Callers handle them at the bridge level (typically: log, retry on
/// transient failures, or fail the surrounding operation). Per-cert
/// failures are reported separately via [`PerCertError`] inside the
/// batch return shape so they do not poison the whole call.
///
/// Variants are `#[non_exhaustive]` so future bridge failure modes
/// (zlint version mismatch, environment misconfiguration, etc.) can
/// be added without a breaking change.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum BridgeError {
    /// The configured zlint binary was not found on `PATH` or at the
    /// configured path.
    BinaryNotFound {
        /// The path the bridge attempted to invoke.
        path: PathBuf,
    },
    /// The configured zlint binary exists but is not executable.
    BinaryNotExecutable {
        /// The path the bridge attempted to invoke.
        path: PathBuf,
    },
    /// The zlint subprocess exited with a non-zero status that the
    /// bridge could not classify as a per-certificate error.
    SubprocessFailed {
        /// Exit code, or `None` if the process was terminated by a signal.
        exit_code: Option<i32>,
        /// Captured stderr (best-effort; may be truncated for very
        /// large outputs).
        stderr: String,
    },
    /// The zlint subprocess was terminated by a signal.
    SubprocessKilled {
        /// Signal number, or `None` if the platform did not report one.
        signal: Option<i32>,
    },
    /// The zlint subprocess exceeded the configured timeout and was
    /// killed by the bridge.
    SubprocessTimeout {
        /// The timeout that was exceeded.
        timeout: Duration,
    },
    /// The zlint subprocess produced output the bridge could not
    /// parse. Indicates either a zlint version mismatch or a
    /// catastrophic upstream regression; either way, the bridge
    /// cannot proceed.
    OutputParseError {
        /// Human-readable diagnostic. Includes the offending text
        /// snippet where useful.
        detail: String,
    },
}

impl core::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BinaryNotFound { path } => {
                write!(f, "zlint binary not found at {}", path.display())
            }
            Self::BinaryNotExecutable { path } => {
                write!(f, "zlint binary at {} is not executable", path.display())
            }
            Self::SubprocessFailed { exit_code, stderr } => match exit_code {
                Some(code) => write!(
                    f,
                    "zlint subprocess exited with code {code}: {}",
                    truncate_for_display(stderr)
                ),
                None => write!(
                    f,
                    "zlint subprocess exited abnormally: {}",
                    truncate_for_display(stderr)
                ),
            },
            Self::SubprocessKilled { signal } => match signal {
                Some(sig) => write!(f, "zlint subprocess killed by signal {sig}"),
                None => write!(f, "zlint subprocess killed by unknown signal"),
            },
            Self::SubprocessTimeout { timeout } => {
                write!(f, "zlint subprocess exceeded timeout {timeout:?}")
            }
            Self::OutputParseError { detail } => write!(f, "zlint output parse error: {detail}"),
        }
    }
}

impl std::error::Error for BridgeError {}

/// Per-certificate errors. These do not fail the whole batch.
///
/// When `ZlintBridge::run_on_certs` (PKIX-jy95.7.4) processes a
/// batch, each input certificate's outcome is reported as a separate
/// `Result<_, PerCertError>` so a single malformed certificate does
/// not poison the others' verdicts.
///
/// Variants are `#[non_exhaustive]` so future per-cert failure modes
/// can be added without a breaking change.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum PerCertError {
    /// The certificate's DER bytes did not parse as an X.509
    /// certificate.
    MalformedDer {
        /// Diagnostic from zlint or the bridge's pre-parse check.
        detail: String,
    },
    /// The certificate is of a kind zlint does not support (for
    /// example, an attribute certificate or a CRL passed where a
    /// `Certificate` was expected).
    UnsupportedCertType {
        /// Diagnostic from zlint.
        detail: String,
    },
    /// Any other per-cert error not covered by the more specific
    /// variants above.
    Other {
        /// Diagnostic from zlint.
        detail: String,
    },
}

impl core::fmt::Display for PerCertError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MalformedDer { detail } => write!(f, "malformed certificate DER: {detail}"),
            Self::UnsupportedCertType { detail } => {
                write!(f, "unsupported certificate type: {detail}")
            }
            Self::Other { detail } => write!(f, "per-cert error: {detail}"),
        }
    }
}

impl std::error::Error for PerCertError {}

// Best-effort truncation of long stderr blobs for human-readable Display.
// The full string is preserved on the struct; this only affects rendering.
fn truncate_for_display(s: &str) -> String {
    const MAX: usize = 512;
    if s.len() <= MAX {
        s.to_string()
    } else {
        let mut out = s.chars().take(MAX).collect::<String>();
        out.push_str("... (truncated)");
        out
    }
}

// ---------------------------------------------------------------------------
// Bridge configuration + handle
// ---------------------------------------------------------------------------

/// Runtime configuration for [`ZlintBridge`].
///
/// Defaults to invoking `zlint` from `PATH` with a 60-second timeout.
/// Override either field to point at a vendored binary, a CI-built
/// development snapshot, or to tighten/loosen the timeout for batch
/// workloads.
///
/// `Clone + Debug + PartialEq + Eq + Send + Sync + non_exhaustive` per
/// AGENTS.md non-negotiable #6.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct BridgeConfig {
    /// Path to the zlint binary. Resolved via `PATH` when relative.
    /// Defaults to `"zlint"`.
    pub zlint_path: PathBuf,
    /// Per-invocation timeout for the zlint subprocess. Defaults to
    /// 60 seconds. For batch invocations, this is the timeout for
    /// the single zlint call that processes the whole batch; batch
    /// size and timeout interact and callers may need to raise the
    /// timeout for large batches.
    pub timeout: Duration,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            zlint_path: PathBuf::from("zlint"),
            timeout: Duration::from_secs(60),
        }
    }
}

/// Bridge handle. Methods on this type invoke the zlint subprocess.
///
/// Construct with [`ZlintBridge::new`]. The handle owns its
/// [`BridgeConfig`]; share or clone the config separately if needed.
///
/// # Status
///
/// [`ZlintBridge::new`] currently accepts any config without
/// validating that the zlint binary exists or is executable —
/// validation happens lazily on the first
/// [`ZlintBridge::enumerate_lints`] / `run_on_cert` /
/// `run_on_certs` call and surfaces as
/// [`BridgeError::BinaryNotFound`] /
/// [`BridgeError::BinaryNotExecutable`]. Eager validation may be
/// added in a future minor version; the fallible `new` signature
/// allows that to land additively.
#[derive(Debug)]
pub struct ZlintBridge {
    config: BridgeConfig,
}

impl ZlintBridge {
    /// Construct a bridge from the given configuration.
    ///
    /// # Errors
    ///
    /// Currently infallible (the scaffold accepts any config). Future
    /// child epics will add binary-existence and version-pinning
    /// checks here; this signature is fallible from the start so
    /// adding those checks is non-breaking.
    pub fn new(config: BridgeConfig) -> Result<Self, BridgeError> {
        Ok(Self { config })
    }

    /// Return a reference to the bridge's configuration.
    ///
    /// Useful for diagnostics and round-trip tests.
    pub fn config(&self) -> &BridgeConfig {
        &self.config
    }

    /// Enumerate every zlint check in the installed catalog.
    ///
    /// Spawns `<zlint_path> -list-lints-json` and parses the
    /// line-delimited JSON output (one object per check, each with
    /// `name`, `description`, `citation`, `source`). Severity is
    /// derived from the check name prefix per zlint's catalog
    /// convention: `e_*` -> [`Severity::Error`], `w_*` ->
    /// [`Severity::Warn`], `n_*` -> [`Severity::Notice`].
    ///
    /// The returned vector preserves zlint's output order. The
    /// catalog is static across one zlint binary; consumers that
    /// call this method repeatedly should cache the result
    /// externally.
    ///
    /// # Errors
    ///
    /// - [`BridgeError::BinaryNotFound`] — the zlint binary is not
    ///   on `PATH` or at the configured path.
    /// - [`BridgeError::BinaryNotExecutable`] — the binary exists
    ///   but cannot be executed.
    /// - [`BridgeError::SubprocessTimeout`] — the zlint subprocess
    ///   exceeded [`BridgeConfig::timeout`] and was killed.
    /// - [`BridgeError::SubprocessFailed`] — zlint exited with a
    ///   non-zero status; stderr is captured for diagnostics.
    /// - [`BridgeError::SubprocessKilled`] — zlint was terminated
    ///   by a signal (Unix only; expressed as
    ///   `SubprocessFailed { exit_code: None }` on platforms where
    ///   signal information is not available).
    /// - [`BridgeError::OutputParseError`] — a line of zlint's
    ///   output could not be parsed as JSON, or a check name
    ///   carried an unrecognised severity prefix.
    ///
    /// [`Severity::Error`]: pkix_lint::Severity::Error
    /// [`Severity::Warn`]: pkix_lint::Severity::Warn
    /// [`Severity::Notice`]: pkix_lint::Severity::Notice
    pub fn enumerate_lints(&self) -> Result<Vec<ZlintLintInfo>, BridgeError> {
        let mut cmd = Command::new(&self.config.zlint_path);
        cmd.arg("-list-lints-json");
        let output = run_subprocess(cmd, &self.config.zlint_path, self.config.timeout)?;

        if !output.status.success() {
            return Err(classify_exit(output.status, &output.stderr));
        }

        parse_list_lints_ndjson(&output.stdout)
    }
}

// ---------------------------------------------------------------------------
// Subprocess plumbing helpers (shared with future run_on_cert /
// run_on_certs methods).
// ---------------------------------------------------------------------------

/// Map an `io::Error` from `Command::spawn` to a `BridgeError`.
fn spawn_error(path: &Path, err: std::io::Error) -> BridgeError {
    match err.kind() {
        std::io::ErrorKind::NotFound => BridgeError::BinaryNotFound {
            path: path.to_path_buf(),
        },
        std::io::ErrorKind::PermissionDenied => BridgeError::BinaryNotExecutable {
            path: path.to_path_buf(),
        },
        _ => BridgeError::SubprocessFailed {
            exit_code: None,
            stderr: err.to_string(),
        },
    }
}

/// Run a subprocess to completion, honouring the bridge's timeout.
///
/// stdin is closed; stdout and stderr are captured. Output is
/// drained on dedicated reader threads to avoid the classic
/// pipe-buffer deadlock where the child blocks writing to a full
/// pipe while the parent waits for the child to exit.
///
/// On timeout, the child is killed and reaped before this returns
/// [`BridgeError::SubprocessTimeout`]. Reader threads are joined
/// after the child exits (or is killed) so we never leak threads
/// past the function return.
fn run_subprocess(
    mut cmd: Command,
    path: &Path,
    timeout: Duration,
) -> Result<std::process::Output, BridgeError> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| spawn_error(path, e))?;

    // Take pipe handles before the wait loop so the reader threads
    // can drain them. If the underlying piped() spec succeeded these
    // are always Some; treat `take()` returning None as a
    // bridge-internal invariant violation surfaced as
    // SubprocessFailed rather than panicking.
    let stdout_pipe = child
        .stdout
        .take()
        .ok_or_else(|| BridgeError::SubprocessFailed {
            exit_code: None,
            stderr: "child stdout pipe missing".into(),
        })?;
    let stderr_pipe = child
        .stderr
        .take()
        .ok_or_else(|| BridgeError::SubprocessFailed {
            exit_code: None,
            stderr: "child stderr pipe missing".into(),
        })?;

    let stdout_thread = std::thread::spawn(move || drain_pipe(stdout_pipe));
    let stderr_thread = std::thread::spawn(move || drain_pipe(stderr_pipe));

    let status = wait_for_child(&mut child, timeout)?;

    // Reader threads exit naturally when the child closes its
    // stdout/stderr; join collects the buffered bytes.
    let stdout = stdout_thread
        .join()
        .map_err(|_| BridgeError::SubprocessFailed {
            exit_code: status.code(),
            stderr: "stdout reader thread panicked".into(),
        })?
        .map_err(|e| BridgeError::SubprocessFailed {
            exit_code: status.code(),
            stderr: format!("stdout drain io error: {e}"),
        })?;
    let stderr = stderr_thread
        .join()
        .map_err(|_| BridgeError::SubprocessFailed {
            exit_code: status.code(),
            stderr: "stderr reader thread panicked".into(),
        })?
        .map_err(|e| BridgeError::SubprocessFailed {
            exit_code: status.code(),
            stderr: format!("stderr drain io error: {e}"),
        })?;

    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

/// Drain a pipe to end-of-file. Returns the buffered bytes or an
/// `io::Error` on read failure.
fn drain_pipe<R: std::io::Read>(mut pipe: R) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    pipe.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Wait for a child process with a deadline. On timeout, kills and
/// reaps the child before returning [`BridgeError::SubprocessTimeout`].
fn wait_for_child(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<std::process::ExitStatus, BridgeError> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(BridgeError::SubprocessTimeout { timeout });
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                return Err(BridgeError::SubprocessFailed {
                    exit_code: None,
                    stderr: e.to_string(),
                });
            }
        }
    }
}

/// Classify a non-zero exit status into the right `BridgeError`.
fn classify_exit(status: std::process::ExitStatus, stderr_bytes: &[u8]) -> BridgeError {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        if let Some(sig) = status.signal() {
            return BridgeError::SubprocessKilled { signal: Some(sig) };
        }
    }
    let stderr = String::from_utf8_lossy(stderr_bytes).into_owned();
    BridgeError::SubprocessFailed {
        exit_code: status.code(),
        stderr,
    }
}

/// Parse the line-delimited JSON output of `zlint -list-lints-json`
/// into a `Vec<ZlintLintInfo>`.
fn parse_list_lints_ndjson(stdout: &[u8]) -> Result<Vec<ZlintLintInfo>, BridgeError> {
    let text = std::str::from_utf8(stdout).map_err(|e| BridgeError::OutputParseError {
        detail: format!("zlint stdout is not valid UTF-8: {e}"),
    })?;

    let mut out = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let info = parse_list_lints_line(line).map_err(|detail| BridgeError::OutputParseError {
            detail: format!("line {}: {}", lineno + 1, detail),
        })?;
        out.push(info);
    }

    if out.is_empty() {
        return Err(BridgeError::OutputParseError {
            detail: "zlint -list-lints-json produced no entries".into(),
        });
    }

    Ok(out)
}

/// Parse one JSON line + derive severity. Returns the per-line
/// `detail` string on failure for the caller to wrap in
/// `BridgeError::OutputParseError`.
///
/// Parsing is done via `serde_json::Value` field access so the
/// non-public `RawLintInfo` shape does not need to leak serde
/// `Derive` impls into the always-on dependency set; the public
/// types' optional `serde` feature stays orthogonal.
///
/// Field requirements track zlint's actual catalog shape:
/// - `name` is required (we derive `severity` from it; without it
///   the entry is unusable).
/// - `description`, `citation`, `source` are optional and default
///   to the empty string when missing. zlint's catalog has several
///   entries without `citation` (CRL-shape checks, community-source
///   checks) and being strict here would refuse to enumerate the
///   real catalog.
fn parse_list_lints_line(line: &str) -> Result<ZlintLintInfo, String> {
    let value: serde_json::Value =
        serde_json::from_str(line).map_err(|e| format!("malformed JSON: {e}"))?;
    let obj = value
        .as_object()
        .ok_or_else(|| "expected JSON object at top level".to_string())?;
    let name = json_required_string(obj, "name")?;
    let description = json_optional_string(obj, "description")?;
    let citation = json_optional_string(obj, "citation")?;
    let source = json_optional_string(obj, "source")?;
    let severity = severity_for_check_name(&name)?;
    Ok(ZlintLintInfo {
        check_id: name,
        description,
        citation,
        source,
        severity,
    })
}

/// Extract a required string field from a JSON object. Missing
/// fields and non-string types are both errors.
fn json_required_string(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<String, String> {
    obj.get(key)
        .ok_or_else(|| format!("missing required field {key:?}"))?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("field {key:?} is not a string"))
}

/// Extract an optional string field from a JSON object. Missing
/// fields and JSON `null` are reported as the empty string. A
/// present-but-non-string value is still an error so callers can
/// rely on the returned `String` actually reflecting the JSON
/// value when it is set.
fn json_optional_string(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<String, String> {
    match obj.get(key) {
        None => Ok(String::new()),
        Some(serde_json::Value::Null) => Ok(String::new()),
        Some(v) => v
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("field {key:?} is not a string")),
    }
}

/// zlint's catalog convention: every check name starts with a single
/// underscore-separated prefix that encodes the declared severity.
/// We accept `e_`, `w_`, and `n_`; anything else is a catalog-shape
/// violation and surfaces as a parse error so a future upstream
/// catalog change does not silently mis-severity our findings.
fn severity_for_check_name(name: &str) -> Result<pkix_lint::Severity, String> {
    if let Some(rest) = name.strip_prefix("e_") {
        if rest.is_empty() {
            return Err(format!("empty check id after e_ prefix: {name:?}"));
        }
        Ok(pkix_lint::Severity::Error)
    } else if let Some(rest) = name.strip_prefix("w_") {
        if rest.is_empty() {
            return Err(format!("empty check id after w_ prefix: {name:?}"));
        }
        Ok(pkix_lint::Severity::Warn)
    } else if let Some(rest) = name.strip_prefix("n_") {
        if rest.is_empty() {
            return Err(format!("empty check id after n_ prefix: {name:?}"));
        }
        Ok(pkix_lint::Severity::Notice)
    } else {
        Err(format!(
            "unrecognised zlint catalog severity prefix in {name:?}; expected e_/w_/n_"
        ))
    }
}

// ---------------------------------------------------------------------------
// Send + Sync compile-time assertions (AGENTS.md non-negotiable #6,
// PKIX-2l0v.2 pattern). Adding a new public type that should preserve
// the Send+Sync invariant should extend this block.
// ---------------------------------------------------------------------------

const _: fn() = || {
    fn _assert_send_sync<T: Send + Sync>() {}
    _assert_send_sync::<Verdict>();
    _assert_send_sync::<ZlintLintInfo>();
    _assert_send_sync::<BridgeError>();
    _assert_send_sync::<PerCertError>();
    _assert_send_sync::<BridgeConfig>();
    _assert_send_sync::<ZlintBridge>();
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the worst-of ordering: less-severe variants compare less
    /// than more-severe variants. Locks the variant declaration order.
    #[test]
    fn verdict_ordering_is_total_and_severity_ascending() {
        assert!(Verdict::NotApplicable < Verdict::Pass);
        assert!(Verdict::Pass < Verdict::Notice);
        assert!(Verdict::Notice < Verdict::Warn);
        assert!(Verdict::Warn < Verdict::Error);
        assert!(Verdict::Error < Verdict::Fatal);
    }

    /// Defaults match the documented values. A future revision that
    /// changes either is a breaking change; this test prevents
    /// silent drift.
    #[test]
    fn bridge_config_default_zlint_and_60s_timeout() {
        let c = BridgeConfig::default();
        assert_eq!(c.zlint_path, PathBuf::from("zlint"));
        assert_eq!(c.timeout, Duration::from_secs(60));
    }

    /// Every `BridgeError` variant produces non-empty `Display`
    /// output. Guards against accidentally adding a variant whose
    /// match arm forgets to write anything to the formatter.
    #[test]
    fn bridge_error_display_all_variants_non_empty() {
        let cases: &[BridgeError] = &[
            BridgeError::BinaryNotFound {
                path: PathBuf::from("/no/such"),
            },
            BridgeError::BinaryNotExecutable {
                path: PathBuf::from("/no/exec"),
            },
            BridgeError::SubprocessFailed {
                exit_code: Some(1),
                stderr: "bad".into(),
            },
            BridgeError::SubprocessFailed {
                exit_code: None,
                stderr: "abnormal".into(),
            },
            BridgeError::SubprocessKilled { signal: Some(9) },
            BridgeError::SubprocessKilled { signal: None },
            BridgeError::SubprocessTimeout {
                timeout: Duration::from_secs(5),
            },
            BridgeError::OutputParseError {
                detail: "garbage".into(),
            },
        ];
        for err in cases {
            let s = format!("{err}");
            assert!(!s.is_empty(), "empty Display for {err:?}");
        }
    }

    /// `SubprocessFailed`'s `Display` truncates very long stderr blobs
    /// but the underlying `stderr` String is preserved on the struct
    /// for callers that want full diagnostics.
    #[test]
    fn bridge_error_display_truncates_long_stderr() {
        let long = "x".repeat(2048);
        let err = BridgeError::SubprocessFailed {
            exit_code: Some(7),
            stderr: long.clone(),
        };
        let rendered = format!("{err}");
        assert!(
            rendered.contains("... (truncated)"),
            "expected truncation marker: {rendered}"
        );
        if let BridgeError::SubprocessFailed { stderr, .. } = err {
            assert_eq!(stderr.len(), 2048, "stderr preserved on struct");
        } else {
            unreachable!();
        }
    }

    /// Every `PerCertError` variant produces non-empty `Display`.
    #[test]
    fn per_cert_error_display_all_variants_non_empty() {
        let cases: &[PerCertError] = &[
            PerCertError::MalformedDer { detail: "x".into() },
            PerCertError::UnsupportedCertType { detail: "y".into() },
            PerCertError::Other { detail: "z".into() },
        ];
        for err in cases {
            assert!(!format!("{err}").is_empty(), "empty Display for {err:?}");
        }
    }

    /// `ZlintBridge::new` is currently infallible (scaffold). This
    /// test pins the contract so future runtime validation does not
    /// silently change the success path for a default config — if
    /// validation against `PATH` lands later, this test will need
    /// updating with `BridgeConfig::zlint_path` pointed at a fixture.
    #[test]
    fn bridge_new_with_default_config_ok() {
        let b = ZlintBridge::new(BridgeConfig::default()).expect("default ok");
        assert_eq!(b.config().zlint_path, PathBuf::from("zlint"));
    }

    /// `BridgeError` and `PerCertError` are real `std::error::Error`s.
    /// Verifies the trait impls compile and behave (no `source` on
    /// the leaf errors today, but `error::Error::description` /
    /// `source` are accessible via the impl).
    #[test]
    fn errors_implement_std_error() {
        fn takes_error(_: &dyn std::error::Error) {}
        let b = BridgeError::OutputParseError { detail: "x".into() };
        let p = PerCertError::Other { detail: "y".into() };
        takes_error(&b);
        takes_error(&p);
    }

    /// `severity_for_check_name` covers every documented prefix and
    /// rejects malformed input. Pins the zlint catalog-prefix
    /// convention; if upstream changes the convention this test
    /// flags it.
    #[test]
    fn severity_for_check_name_recognises_documented_prefixes() {
        use pkix_lint::Severity;
        assert_eq!(
            severity_for_check_name("e_basic_constraints_not_critical"),
            Ok(Severity::Error)
        );
        assert_eq!(
            severity_for_check_name("w_some_warning"),
            Ok(Severity::Warn)
        );
        assert_eq!(
            severity_for_check_name("n_some_notice"),
            Ok(Severity::Notice)
        );
    }

    /// Empty body after a recognised prefix is rejected — catches
    /// catalog-shape regressions.
    #[test]
    fn severity_for_check_name_rejects_empty_body() {
        assert!(severity_for_check_name("e_").is_err());
        assert!(severity_for_check_name("w_").is_err());
        assert!(severity_for_check_name("n_").is_err());
    }

    /// Unrecognised prefixes (and missing prefix) surface as parse
    /// errors so a silent upstream change cannot mis-label findings.
    #[test]
    fn severity_for_check_name_rejects_unknown_prefix() {
        for bad in &[
            "q_invalid_prefix",
            "info_no_underscore_prefix",
            "_leading_underscore_only",
            "noprefix",
            "",
        ] {
            assert!(
                severity_for_check_name(bad).is_err(),
                "should reject {bad:?}"
            );
        }
    }

    /// `parse_list_lints_ndjson` handles a small synthetic catalog
    /// covering each severity prefix and ignoring blank lines.
    #[test]
    fn parse_list_lints_ndjson_handles_three_prefixes_and_blank_lines() {
        let ndjson = b"\
{\"name\":\"e_x\",\"description\":\"D1\",\"citation\":\"C1\",\"source\":\"S1\"}\n\
\n\
{\"name\":\"w_y\",\"description\":\"D2\",\"citation\":\"C2\",\"source\":\"S2\"}\n\
{\"name\":\"n_z\",\"description\":\"D3\",\"citation\":\"C3\",\"source\":\"S3\"}\n";
        let parsed = parse_list_lints_ndjson(ndjson).expect("parse");
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].check_id, "e_x");
        assert_eq!(parsed[0].severity, pkix_lint::Severity::Error);
        assert_eq!(parsed[1].check_id, "w_y");
        assert_eq!(parsed[1].severity, pkix_lint::Severity::Warn);
        assert_eq!(parsed[2].check_id, "n_z");
        assert_eq!(parsed[2].severity, pkix_lint::Severity::Notice);
    }

    /// Empty output (or only-whitespace output) surfaces as a parse
    /// error — zlint always emits at least one entry.
    #[test]
    fn parse_list_lints_ndjson_rejects_empty_output() {
        assert!(matches!(
            parse_list_lints_ndjson(b""),
            Err(BridgeError::OutputParseError { .. })
        ));
        assert!(matches!(
            parse_list_lints_ndjson(b"\n\n   \n"),
            Err(BridgeError::OutputParseError { .. })
        ));
    }

    /// Malformed JSON on a single line surfaces as a parse error.
    #[test]
    fn parse_list_lints_ndjson_rejects_malformed_json() {
        let ndjson = b"\
{\"name\":\"e_x\",\"description\":\"D1\",\"citation\":\"C1\",\"source\":\"S1\"}\n\
not even close to json\n";
        let err = parse_list_lints_ndjson(ndjson).expect_err("malformed should fail");
        match err {
            BridgeError::OutputParseError { detail } => {
                assert!(detail.contains("line 2"), "expected line number: {detail}");
            }
            other => panic!("expected OutputParseError, got {other:?}"),
        }
    }

    /// A JSON object missing the `name` field is rejected — name
    /// is the only required field; without it we cannot derive a
    /// severity or use the entry.
    #[test]
    fn parse_list_lints_ndjson_rejects_missing_name_field() {
        let ndjson = b"{\"description\":\"D\",\"citation\":\"C\",\"source\":\"S\"}\n";
        let err = parse_list_lints_ndjson(ndjson).expect_err("missing name should fail");
        assert!(matches!(err, BridgeError::OutputParseError { .. }));
    }

    /// Missing `citation` is tolerated and defaults to empty —
    /// zlint's catalog has several entries (CRL checks, community
    /// checks) that omit citation entirely.
    #[test]
    fn parse_list_lints_ndjson_tolerates_missing_optional_fields() {
        let ndjson = b"{\"name\":\"e_x\",\"description\":\"D\",\"source\":\"S\"}\n";
        let parsed =
            parse_list_lints_ndjson(ndjson).expect("optional citation should be tolerated");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].check_id, "e_x");
        assert_eq!(parsed[0].citation, "");
        assert_eq!(parsed[0].description, "D");
        assert_eq!(parsed[0].source, "S");
    }

    /// A bare `name` field is sufficient — all other fields default
    /// to empty. Robust against catalog-entry shape regressions.
    #[test]
    fn parse_list_lints_ndjson_handles_bare_name_only() {
        let ndjson = b"{\"name\":\"w_x\"}\n";
        let parsed = parse_list_lints_ndjson(ndjson).expect("bare name should parse");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].check_id, "w_x");
        assert_eq!(parsed[0].severity, pkix_lint::Severity::Warn);
        assert_eq!(parsed[0].description, "");
        assert_eq!(parsed[0].citation, "");
        assert_eq!(parsed[0].source, "");
    }

    /// `null` for an optional field is treated as missing (empty
    /// string), not a type error.
    #[test]
    fn parse_list_lints_ndjson_treats_null_optional_as_empty() {
        let ndjson = b"{\"name\":\"n_x\",\"description\":null,\"citation\":null,\"source\":null}\n";
        let parsed = parse_list_lints_ndjson(ndjson).expect("null optionals -> empty");
        assert_eq!(parsed[0].description, "");
        assert_eq!(parsed[0].citation, "");
        assert_eq!(parsed[0].source, "");
    }

    /// Non-string types in optional fields are still rejected — we
    /// only relax the missing-field case, not the type contract.
    #[test]
    fn parse_list_lints_ndjson_rejects_non_string_optional() {
        let ndjson = b"{\"name\":\"e_x\",\"citation\":42}\n";
        let err = parse_list_lints_ndjson(ndjson).expect_err("non-string citation should fail");
        assert!(matches!(err, BridgeError::OutputParseError { .. }));
    }

    /// A JSON object whose check name has an unrecognised severity
    /// prefix surfaces as a parse error.
    #[test]
    fn parse_list_lints_ndjson_rejects_unknown_severity_prefix() {
        let ndjson =
            b"{\"name\":\"q_oops\",\"description\":\"D\",\"citation\":\"C\",\"source\":\"S\"}\n";
        let err = parse_list_lints_ndjson(ndjson).expect_err("bad prefix should fail");
        match err {
            BridgeError::OutputParseError { detail } => {
                assert!(
                    detail.contains("unrecognised") || detail.contains("expected e_/w_/n_"),
                    "expected severity-prefix detail: {detail}"
                );
            }
            other => panic!("expected OutputParseError, got {other:?}"),
        }
    }
}
