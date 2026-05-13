//! zlint lint-domain oracle backed by `pkix-zlint-bridge`.
//!
//! See the parent module ([`super`]) for the trait surface and the broader
//! PKIX-hbzo.1 context.
//!
//! # Verdict mapping
//!
//! zlint's per-check [`Verdict`] enum maps into [`NormalizedFinding`] as
//! follows (per PKIX-jy95.2 severity-mapping decision memory):
//!
//! | zlint `Verdict`      | `NormalizedFinding` | Notes |
//! |----------------------|---------------------|-------|
//! | `NotApplicable`      | *(dropped)*         | Not a finding; lint did not run. |
//! | `Pass`               | *(dropped)*         | Not a finding; lint passed. |
//! | `Notice`             | `Severity::Notice`  | |
//! | `Warn`               | `Severity::Warn`    | |
//! | `Error`              | `Severity::Error`   | |
//! | `Fatal`              | `Severity::Fatal`   | |
//!
//! The `_` arm in the match handles future zlint Verdict variants
//! (`#[non_exhaustive]`) by dropping them; the parallel arm in the
//! match-on-error path covers `pkix_zlint_bridge::Error`.

use std::sync::Arc;

use pkix_zlint_bridge::{Error as BridgeCallError, Verdict, VerdictMap, ZlintBridge};

use super::{LintOracle, LintOracleResult, NormalizedFinding, OracleSource};

/// Differential lint oracle backed by zlint via `pkix-zlint-bridge`.
///
/// Holds an `Arc<ZlintBridge>` so the same bridge handle (and its
/// per-cert SHA-256 verdict cache) can be shared across reconciliation
/// call sites. The bridge is `Send + Sync` (compile-time asserted in the
/// bridge crate), so `ZlintOracle` is `Send + Sync` by composition.
///
/// # Subprocess lifecycle
///
/// Every call to [`LintOracle::lint_cert`] dispatches through
/// [`ZlintBridge::run_on_cert`], which: (a) checks the per-cert cache by
/// SHA-256, (b) on cache miss, spawns one zlint subprocess and parses the
/// per-check verdict output, (c) populates the cache and returns.
///
/// The cache makes repeat-lint of the same cert cheap (a `HashMap` clone).
/// In a 3-way differential run the same cert is linted by each oracle
/// exactly once, so cache hits are rare in that workload — the cache
/// matters more when the same oracle is queried by N adapter shims (the
/// `pkix-policy-zlint` ~400-Lint pattern documented in PKIX-jy95.1).
pub struct ZlintOracle {
    bridge: Arc<ZlintBridge>,
}

impl ZlintOracle {
    /// Construct from an existing bridge handle.
    ///
    /// Use this when sharing one bridge (and its cache) across multiple
    /// oracle wrappers. The typical pattern in the reconciliation layer
    /// (PKIX-hbzo.1.3) is to construct one bridge per differential run and
    /// hand `Arc` clones to every per-cert call site.
    #[must_use]
    pub fn new(bridge: Arc<ZlintBridge>) -> Self {
        Self { bridge }
    }

    /// Construct from a fresh bridge with default config.
    ///
    /// Convenience for unit tests and one-shot usage. Equivalent to
    /// `ZlintOracle::new(Arc::new(ZlintBridge::new(BridgeConfig::default())?))`.
    ///
    /// # Errors
    ///
    /// Propagates any error from `ZlintBridge::new`. As of bridge version
    /// `0.0.0`, `new` is infallible, but the signature is kept fallible so
    /// future binary-existence / version-pinning checks land additively.
    pub fn with_default_bridge() -> Result<Self, pkix_zlint_bridge::BridgeError> {
        let bridge = ZlintBridge::new(pkix_zlint_bridge::BridgeConfig::default())?;
        Ok(Self {
            bridge: Arc::new(bridge),
        })
    }

    /// Map a zlint verdict map into a sorted list of actionable findings.
    ///
    /// Free helper rather than a method on `ZlintOracle` so unit tests can
    /// exercise the verdict-to-finding mapping without spinning up a real
    /// bridge or invoking zlint.
    pub(crate) fn normalize_verdicts(verdicts: &VerdictMap) -> Vec<NormalizedFinding> {
        let mut findings: Vec<NormalizedFinding> = verdicts
            .iter()
            .filter_map(|(check_id, verdict)| {
                let severity = verdict_to_severity(*verdict)?;
                Some(NormalizedFinding {
                    id: check_id.clone(),
                    severity,
                    source: OracleSource::Zlint,
                })
            })
            .collect();
        // Deterministic order — `VerdictMap` is `HashMap`-backed, so without
        // this sort baseline diffs would flap on `HashMap` iteration order
        // changes across stdlib versions.
        findings.sort_by(|a, b| a.id.cmp(&b.id));
        findings
    }
}

impl LintOracle for ZlintOracle {
    fn source(&self) -> OracleSource {
        OracleSource::Zlint
    }

    fn lint_cert(&self, cert_der: &[u8]) -> LintOracleResult {
        match self.bridge.run_on_cert(cert_der) {
            Ok(verdicts) => LintOracleResult {
                findings: Self::normalize_verdicts(&verdicts),
                oracle_error: None,
            },
            // Per-cert errors: malformed DER, unsupported cert type, etc.
            // These do not invalidate the oracle for other certs; surface
            // as oracle_error so the reconciliation layer treats this cert
            // as "zlint could not check" rather than as a bridge crash.
            Err(BridgeCallError::Cert(per_cert)) => {
                LintOracleResult::oracle_error(format!("zlint per-cert error: {per_cert}"))
            }
            // Bridge-level errors: binary missing, subprocess crash, timeout.
            // Still surfaced as oracle_error (not panic, not Result::Err)
            // because a missing zlint binary in CI is something the
            // baseline runner should report cleanly, not crash on.
            Err(BridgeCallError::Bridge(bridge_err)) => {
                LintOracleResult::oracle_error(format!("zlint bridge error: {bridge_err}"))
            }
            // `pkix_zlint_bridge::Error` is `#[non_exhaustive]`. New variants
            // arriving via a bridge minor-version bump should fail loudly here,
            // not silently produce empty findings.
            Err(other) => LintOracleResult::oracle_error(format!(
                "unrecognized zlint bridge error variant: {other:?}"
            )),
        }
    }
}

/// Translate one zlint [`Verdict`] to the [`pkix_lint::Severity`] it
/// normalises to.
///
/// Returns `None` for verdicts that are not actionable findings:
/// `Verdict::NotApplicable` and `Verdict::Pass` are explicitly dropped;
/// any future `#[non_exhaustive]` variant also drops through the catch-all
/// arm. The catch-all arm exists because [`Verdict`] is `#[non_exhaustive]`
/// in `pkix-zlint-bridge`; a bridge minor-version bump could introduce a
/// new variant that this adapter has not been taught to handle, and we
/// would rather drop silently than panic. The collapse of the
/// "intentionally not-a-finding" arm with the "future variant" arm is
/// intentional: both produce no finding, and clippy's preferred shape
/// (a single `_ => return None`) lines up with that semantics.
fn verdict_to_severity(verdict: Verdict) -> Option<pkix_lint::Severity> {
    Some(match verdict {
        Verdict::Notice => pkix_lint::Severity::Notice,
        Verdict::Warn => pkix_lint::Severity::Warn,
        Verdict::Error => pkix_lint::Severity::Error,
        Verdict::Fatal => pkix_lint::Severity::Fatal,
        // `Verdict::NotApplicable`, `Verdict::Pass`, and any future
        // non_exhaustive variants. See function docs.
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn vmap(pairs: &[(&str, Verdict)]) -> VerdictMap {
        let mut m: HashMap<String, Verdict> = HashMap::new();
        for (k, v) in pairs {
            m.insert((*k).to_string(), *v);
        }
        m
    }

    #[test]
    fn verdict_to_severity_maps_all_actionable_levels() {
        assert_eq!(
            verdict_to_severity(Verdict::Notice),
            Some(pkix_lint::Severity::Notice)
        );
        assert_eq!(
            verdict_to_severity(Verdict::Warn),
            Some(pkix_lint::Severity::Warn)
        );
        assert_eq!(
            verdict_to_severity(Verdict::Error),
            Some(pkix_lint::Severity::Error)
        );
        assert_eq!(
            verdict_to_severity(Verdict::Fatal),
            Some(pkix_lint::Severity::Fatal)
        );
    }

    #[test]
    fn verdict_to_severity_drops_nonfinding_levels() {
        assert_eq!(verdict_to_severity(Verdict::NotApplicable), None);
        assert_eq!(verdict_to_severity(Verdict::Pass), None);
    }

    #[test]
    fn normalize_verdicts_filters_and_sorts() {
        let input = vmap(&[
            ("e_b", Verdict::Error),
            ("n_a", Verdict::Notice),
            ("pass_check", Verdict::Pass),
            ("na_check", Verdict::NotApplicable),
            ("w_z", Verdict::Warn),
        ]);
        let findings = ZlintOracle::normalize_verdicts(&input);

        // Pass and NotApplicable dropped; remaining sorted by id.
        let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, ["e_b", "n_a", "w_z"]);

        // Source uniformly Zlint.
        for f in &findings {
            assert_eq!(f.source, OracleSource::Zlint);
        }

        // Severity preserved.
        assert_eq!(findings[0].severity, pkix_lint::Severity::Error);
        assert_eq!(findings[1].severity, pkix_lint::Severity::Notice);
        assert_eq!(findings[2].severity, pkix_lint::Severity::Warn);
    }

    #[test]
    fn normalize_verdicts_empty_input_yields_empty() {
        let findings = ZlintOracle::normalize_verdicts(&vmap(&[]));
        assert!(findings.is_empty());
    }

    #[test]
    fn normalize_verdicts_all_pass_yields_empty() {
        let input = vmap(&[("a", Verdict::Pass), ("b", Verdict::NotApplicable)]);
        let findings = ZlintOracle::normalize_verdicts(&input);
        assert!(findings.is_empty());
    }
}
