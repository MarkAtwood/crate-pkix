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

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
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

/// Unified error type for single-certificate entry points.
///
/// [`ZlintBridge::run_on_cert`] can fail for two distinct reasons:
/// the bridge could not run (binary missing, subprocess timeout,
/// output parse error) or the specific certificate is unsuitable
/// (malformed DER, unsupported type). This enum lets callers
/// pattern-match on the cause and choose hard-fail vs lenient
/// behaviour per AGENTS.md non-negotiable #6 (cache friendliness
/// extends to error introspection).
///
/// The batch entry point `ZlintBridge::run_on_certs` (PKIX-jy95.7.4)
/// uses a different return shape: bridge-level errors fail the whole
/// batch (`Result<_, BridgeError>` outer), per-certificate errors are
/// reported per index (`Result<_, PerCertError>` inner). This single
/// cert API folds both into one error so callers do not have to
/// double-unwrap for the common one-cert case.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Error {
    /// The bridge itself failed (binary missing, subprocess crash,
    /// timeout, output parse error). The call did not produce a
    /// verdict because zlint could not be invoked, or did not
    /// produce parseable output.
    Bridge(BridgeError),
    /// The certificate is not something zlint can lint (malformed
    /// DER, attribute certificate, etc.). The bridge ran but zlint
    /// rejected the input.
    Cert(PerCertError),
}

impl From<BridgeError> for Error {
    fn from(e: BridgeError) -> Self {
        Self::Bridge(e)
    }
}

impl From<PerCertError> for Error {
    fn from(e: PerCertError) -> Self {
        Self::Cert(e)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Bridge(e) => write!(f, "zlint bridge error: {e}"),
            Self::Cert(e) => write!(f, "zlint cert error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bridge(e) => Some(e),
            Self::Cert(e) => Some(e),
        }
    }
}

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
    /// Per-certificate verdict cache keyed by SHA-256 of the DER
    /// bytes. Architecturally required by PKIX-jy95.1: the runtime
    /// adapter `pkix-policy-zlint` will spin up one
    /// [`pkix_lint::Lint`] impl per zlint check (~400 impls), each
    /// of which calls [`ZlintBridge::run_on_cert`] for its own
    /// check_id. Without the cache, that triggers 400 subprocess
    /// invocations per certificate. With the cache, the first
    /// `Lint` invocation pays the subprocess cost and every
    /// subsequent invocation on the same cert is an
    /// in-memory `HashMap` clone.
    cache: Mutex<HashMap<[u8; 32], HashMap<String, Verdict>>>,
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
        Ok(Self {
            config,
            cache: Mutex::new(HashMap::new()),
        })
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

    /// Run every zlint check on a single DER-encoded certificate.
    ///
    /// Returns a `HashMap` keyed by the zlint `check_id` (the same
    /// string [`ZlintLintInfo::check_id`] uses) mapped to the
    /// per-cert [`Verdict`].
    ///
    /// # Caching
    ///
    /// Results are cached on the bridge by `SHA-256(cert_der)`.
    /// Subsequent calls with bytes that hash to the same key return
    /// the cached map without re-spawning zlint. The cache lives for
    /// the lifetime of the `ZlintBridge` handle; consumers that
    /// want cross-handle persistence layer their own.
    ///
    /// # Errors
    ///
    /// - [`Error::Bridge`] — the bridge could not run zlint (binary
    ///   missing, timeout, subprocess crash, output parse error).
    /// - [`Error::Cert`] — zlint ran and rejected the input.
    ///   [`PerCertError::MalformedDer`] for parse failures;
    ///   [`PerCertError::Other`] for any other non-zero exit.
    pub fn run_on_cert(&self, cert_der: &[u8]) -> Result<HashMap<String, Verdict>, Error> {
        let key = sha256_digest(cert_der);
        if let Some(hit) = self.cache_get(&key) {
            return Ok(hit);
        }

        let path = write_temp_der(cert_der, &key).map_err(Error::Bridge)?;
        let mut cmd = Command::new(&self.config.zlint_path);
        cmd.arg("-format").arg("der").arg(&path);
        let result = run_subprocess(cmd, &self.config.zlint_path, self.config.timeout);

        // Best-effort cleanup. We do not propagate cleanup errors
        // because they do not change the call's correctness; a
        // stale file is at worst a disk-space leak the OS will
        // reap when /tmp turns over.
        let _ = std::fs::remove_file(&path);

        let output = result.map_err(Error::Bridge)?;

        if !output.status.success() {
            return Err(Error::Cert(classify_zlint_cert_error(&output.stderr)));
        }

        let verdicts = parse_per_cert_output(&output.stdout)
            .map_err(|detail| Error::Bridge(BridgeError::OutputParseError { detail }))?;

        self.cache_put(key, verdicts.clone());
        Ok(verdicts)
    }

    /// Cache helper: return a clone of the cached entry if present.
    ///
    /// Returns by clone so the caller does not hold the cache lock
    /// across its own work. This is a deliberate space-time tradeoff
    /// (HashMap clone is O(n) on entry count, ~400 entries) for the
    /// cache lookup; profiling can revisit if it shows up as a hot
    /// spot.
    fn cache_get(&self, key: &[u8; 32]) -> Option<HashMap<String, Verdict>> {
        self.cache.lock().ok()?.get(key).cloned()
    }

    /// Cache helper: insert (or overwrite) an entry.
    ///
    /// A poisoned mutex is treated as "skip the cache for this call"
    /// rather than propagating the panic — the caller already has a
    /// valid verdict map and a future call will recompute.
    fn cache_put(&self, key: [u8; 32], value: HashMap<String, Verdict>) {
        if let Ok(mut guard) = self.cache.lock() {
            guard.insert(key, value);
        }
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

/// Compute SHA-256 of the DER bytes for use as a cache key.
fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Write the DER bytes to a temporary file and return its path.
///
/// The filename is `pkix-zlint-bridge-<sha256-hex>.der` under the
/// platform temp directory. Same input bytes always produce the same
/// path, which makes concurrent writes idempotent (both writers
/// write the same bytes) and the cleanup unambiguous (the caller
/// removes the file once zlint has read it).
fn write_temp_der(bytes: &[u8], key: &[u8; 32]) -> Result<PathBuf, BridgeError> {
    let mut path = std::env::temp_dir();
    path.push(format!("pkix-zlint-bridge-{}.der", hex_encode(key)));
    std::fs::write(&path, bytes).map_err(|e| BridgeError::SubprocessFailed {
        exit_code: None,
        stderr: format!("temp file write failed at {}: {e}", path.display()),
    })?;
    Ok(path)
}

/// Lowercase hex encoding of a byte slice. Local helper to avoid
/// adding a `hex` crate dependency for one 64-character string per
/// call.
fn hex_encode(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // u8 hex is infallible.
        write!(&mut out, "{b:02x}").expect("write to String is infallible");
    }
    out
}

/// Classify zlint's stderr for a non-zero per-cert exit into the
/// right `PerCertError` variant.
///
/// zlint's malformed-cert error message starts with `level=fatal
/// msg="unable to parse input as any known type, errors: [...]"`
/// (verified locally against zlint dev-unknown 2026-05-12). The
/// embedded `errors:` list itself contains substrings like
/// `parsing as certificate`. We match on either to be robust
/// against minor wording drift between zlint releases.
fn classify_zlint_cert_error(stderr_bytes: &[u8]) -> PerCertError {
    let stderr = String::from_utf8_lossy(stderr_bytes).into_owned();
    if stderr.contains("unable to parse input")
        || stderr.contains("parsing as certificate")
        || stderr.contains("malformed")
    {
        PerCertError::MalformedDer { detail: stderr }
    } else {
        PerCertError::Other { detail: stderr }
    }
}

/// Parse zlint's per-cert JSON output into a `HashMap<check_id,
/// Verdict>`.
///
/// zlint emits a single top-level JSON object whose keys are check
/// names and whose values are objects with a `result` string field.
/// Anything else is an output-parse error.
fn parse_per_cert_output(stdout: &[u8]) -> Result<HashMap<String, Verdict>, String> {
    let text = std::str::from_utf8(stdout).map_err(|e| format!("stdout not valid UTF-8: {e}"))?;
    let value: serde_json::Value =
        serde_json::from_str(text.trim()).map_err(|e| format!("malformed JSON: {e}"))?;
    let obj = value
        .as_object()
        .ok_or_else(|| "expected JSON object at top level".to_string())?;

    let mut out = HashMap::with_capacity(obj.len());
    for (name, entry) in obj {
        let result_str = entry
            .as_object()
            .and_then(|o| o.get("result"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("entry {name:?} missing 'result' string"))?;
        let verdict = verdict_from_str(result_str).map_err(|e| format!("entry {name:?}: {e}"))?;
        out.insert(name.clone(), verdict);
    }
    Ok(out)
}

/// Map a zlint verdict string into a [`Verdict`].
///
/// zlint emits one of `NA` (not applicable) / `NE` (not effective)
/// / `pass` / `notice` / `warn` / `error` / `fatal`. The two
/// not-applicable forms collapse into [`Verdict::NotApplicable`]
/// because neither carries a compliance signal.
fn verdict_from_str(s: &str) -> Result<Verdict, String> {
    match s {
        "NA" | "NE" => Ok(Verdict::NotApplicable),
        "pass" => Ok(Verdict::Pass),
        "notice" => Ok(Verdict::Notice),
        "warn" => Ok(Verdict::Warn),
        "error" => Ok(Verdict::Error),
        "fatal" => Ok(Verdict::Fatal),
        other => Err(format!(
            "unknown zlint verdict {other:?}; expected NA / NE / pass / notice / warn / error / fatal"
        )),
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
    _assert_send_sync::<Error>();
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

    // ---- run_on_cert helpers (PKIX-jy95.7.3) -------------------------

    /// Each documented zlint verdict string maps to the expected
    /// `Verdict`. `NA` and `NE` collapse to `NotApplicable`.
    #[test]
    fn verdict_from_str_recognises_all_documented_verdicts() {
        assert_eq!(verdict_from_str("NA"), Ok(Verdict::NotApplicable));
        assert_eq!(verdict_from_str("NE"), Ok(Verdict::NotApplicable));
        assert_eq!(verdict_from_str("pass"), Ok(Verdict::Pass));
        assert_eq!(verdict_from_str("notice"), Ok(Verdict::Notice));
        assert_eq!(verdict_from_str("warn"), Ok(Verdict::Warn));
        assert_eq!(verdict_from_str("error"), Ok(Verdict::Error));
        assert_eq!(verdict_from_str("fatal"), Ok(Verdict::Fatal));
    }

    /// Unknown verdict strings surface as parse errors so future
    /// zlint additions to the verdict vocabulary fail loudly.
    #[test]
    fn verdict_from_str_rejects_unknown_verdicts() {
        for bad in &["", "PASS", "warning", "info", "unknown"] {
            assert!(verdict_from_str(bad).is_err(), "should reject {bad:?}");
        }
    }

    /// Happy-path per-cert JSON parsing yields a complete map.
    #[test]
    fn parse_per_cert_output_handles_typical_layout() {
        let json = br#"{"e_x":{"result":"NA"},"e_y":{"result":"pass"},"w_z":{"result":"warn"}}"#;
        let parsed = parse_per_cert_output(json).expect("parse");
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed.get("e_x"), Some(&Verdict::NotApplicable));
        assert_eq!(parsed.get("e_y"), Some(&Verdict::Pass));
        assert_eq!(parsed.get("w_z"), Some(&Verdict::Warn));
    }

    /// Missing `result` field on an entry surfaces a clear parse
    /// error naming the offending check.
    #[test]
    fn parse_per_cert_output_rejects_missing_result() {
        let json = br#"{"e_x":{"description":"nope"}}"#;
        let err = parse_per_cert_output(json).expect_err("missing result should fail");
        assert!(
            err.contains("e_x"),
            "error should name offending entry: {err}"
        );
        assert!(
            err.contains("result"),
            "error should mention 'result': {err}"
        );
    }

    /// Unknown verdict string inside an entry's `result` surfaces a
    /// per-entry parse error.
    #[test]
    fn parse_per_cert_output_rejects_unknown_verdict() {
        let json = br#"{"e_x":{"result":"undocumented_verdict"}}"#;
        let err = parse_per_cert_output(json).expect_err("unknown verdict should fail");
        assert!(
            err.contains("e_x"),
            "error should name offending entry: {err}"
        );
        assert!(
            err.contains("unknown zlint verdict"),
            "error should mention unknown verdict: {err}"
        );
    }

    /// Non-object top level is rejected.
    #[test]
    fn parse_per_cert_output_rejects_non_object_top_level() {
        for bad in &[b"[]" as &[u8], b"\"string\"", b"42"] {
            assert!(parse_per_cert_output(bad).is_err());
        }
    }

    /// Empty JSON object parses to an empty map. zlint will not
    /// normally emit this, but it is a defensible non-error edge.
    #[test]
    fn parse_per_cert_output_empty_object_returns_empty_map() {
        let parsed = parse_per_cert_output(b"{}").expect("empty object ok");
        assert!(parsed.is_empty());
    }

    /// Whitespace around the JSON object is tolerated (zlint
    /// sometimes adds a trailing newline).
    #[test]
    fn parse_per_cert_output_tolerates_surrounding_whitespace() {
        let json = b"\n  {\"e_x\":{\"result\":\"pass\"}}  \n\n";
        let parsed = parse_per_cert_output(json).expect("trim should work");
        assert_eq!(parsed.get("e_x"), Some(&Verdict::Pass));
    }

    /// The malformed-cert classifier recognises the documented
    /// zlint error strings and falls back to `Other` otherwise.
    #[test]
    fn classify_zlint_cert_error_recognises_malformed_strings() {
        let cases: &[(&[u8], bool)] = &[
            (
                b"time=\"...\" level=fatal msg=\"unable to parse input as any known type, errors: [parsing as certificate: asn1...]\"",
                true,
            ),
            (b"parsing as certificate: asn1: structure error", true),
            (b"malformed input", true),
            (b"some unrelated zlint error message", false),
        ];
        for (stderr, expect_malformed) in cases {
            let err = classify_zlint_cert_error(stderr);
            match err {
                PerCertError::MalformedDer { .. } => {
                    assert!(expect_malformed, "unexpected MalformedDer for {stderr:?}");
                }
                PerCertError::Other { .. } => {
                    assert!(
                        !expect_malformed,
                        "expected MalformedDer but got Other for {stderr:?}"
                    );
                }
                other => panic!("unexpected classification {other:?}"),
            }
        }
    }

    /// `Error::Bridge` and `Error::Cert` both Display + source.
    #[test]
    fn unified_error_display_and_source() {
        use std::error::Error as _;
        let b = Error::Bridge(BridgeError::OutputParseError { detail: "x".into() });
        let c = Error::Cert(PerCertError::MalformedDer { detail: "y".into() });
        assert!(format!("{b}").contains("bridge error"));
        assert!(format!("{c}").contains("cert error"));
        assert!(b.source().is_some());
        assert!(c.source().is_some());
    }

    /// SHA-256 helper produces the well-known empty-input digest.
    /// Independent oracle: well-known empty SHA-256 from FIPS 180-4
    /// (and confirmable via `printf '' | sha256sum`).
    #[test]
    fn sha256_digest_matches_known_empty_input() {
        let d = sha256_digest(b"");
        let expected: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(d, expected);
    }

    /// Hex encode round-trips byte values 0x00 through 0xff (with a
    /// small sample) and produces lowercase output.
    #[test]
    fn hex_encode_lowercase_round_trip() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0xab, 0xcd]), "00ffabcd");
        assert_eq!(hex_encode(&[]), "");
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
