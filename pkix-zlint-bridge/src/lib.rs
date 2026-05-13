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
//! Scaffold-only at version 0.0.0 (PKIX-jy95.7.1): public types and
//! Send/Sync invariants are pinned; subprocess invocation arrives via
//! child epics PKIX-jy95.7.2 (`enumerate_lints`), .7.3 (`run_on_cert`
//! + cache), and .7.4 (`run_on_certs` batch).
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

use std::path::PathBuf;
use std::time::Duration;

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
/// Scaffold only. [`ZlintBridge::new`] accepts any config without
/// validating that the zlint binary exists or is executable —
/// runtime validation lands with the per-method implementations
/// (PKIX-jy95.7.2 / .7.3 / .7.4).
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
}
