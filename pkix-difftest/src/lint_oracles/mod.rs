//! Lint-domain differential oracles (PKIX-hbzo.1).
//!
//! The path-validation oracle layer (`crate::oracles`) answers
//! `(chain) -> Verdict`. The lint-domain oracle layer here answers
//! `(cert_der) -> Vec<NormalizedFinding>`. The two layers do not share
//! types because the questions they answer do not share shape: a chain
//! verdict is one Pass-or-Fail-plus-reason; lint findings are an
//! unordered set of `(id, severity)` records per certificate.
//!
//! # Implementations
//!
//! - [`crate::lint_oracles::zlint::ZlintOracle`] — subprocess to zlint via
//!   `pkix-zlint-bridge` (PKIX-jy95.7). Covers zlint's full ~400-check
//!   catalog including all CA/B Forum BR and RFC 5280 checks zlint ships.
//! - [`crate::lint_oracles::pkix_lint_cabf::PkixLintCabfOracle`] —
//!   in-process pkix-lint-cabf reference CA/B Forum TLS BR lints (six
//!   lints currently: `cabf.br.tls.validity.max`,
//!   `cabf.br.tls.alg.sha1_prohibited`, `cabf.br.tls.rsa.min_key_size`,
//!   `cabf.br.tls.san.required`, `cabf.br.tls.eku.server_auth`,
//!   `cabf.br.tls.bc.ca_flag`).
//! - `PkilintOracle` — planned. Tracked as `PKIX-hbzo.1.2`, blocked on
//!   `pkix-pkilint-bridge` (PKIX-jy95.8).
//!
//! Each oracle returns a [`crate::lint_oracles::LintOracleResult`] whose
//! `findings` field carries only **actionable** findings (Notice / Warn /
//! Error / Fatal). Pass and NotApplicable verdicts are dropped at the
//! normalisation boundary; the reconciliation layer (PKIX-hbzo.1.3) only
//! cares about which lints fired, not which abstained.
//!
//! # Why this is a separate module
//!
//! `crate::oracles::*` will never have a lint-shaped oracle, and the
//! `LintOracle` trait here will never have a chain-shaped impl. Keeping the
//! two trait families in sibling modules makes that semantic split explicit
//! and avoids a forced unification (e.g., an enum of `Either<Verdict,
//! Vec<Finding>>`) that would only ever be witnessed by one variant per
//! call site.

pub mod pkix_lint_cabf;
pub mod zlint;

// ---------------------------------------------------------------------------
// OracleSource
// ---------------------------------------------------------------------------

/// Identifier for a lint-domain oracle.
///
/// Deliberately not `#[non_exhaustive]`: adding a new oracle is an
/// architectural event (new subprocess, new dep, possibly new CI
/// requirement) that should force every match site to be revisited.
/// Same reasoning as [`crate::OracleName`] for the chain-validation layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OracleSource {
    /// Reference CA/B Forum TLS BR lints from the `pkix-lint-cabf` crate.
    PkixLintCabf,
    /// zlint subprocess via `pkix-zlint-bridge`.
    Zlint,
    /// pkilint subprocess (planned — PKIX-hbzo.1.2, blocked on PKIX-jy95.8).
    /// Defined here so reports and tests can name the variant before the
    /// impl lands. Constructing one currently means "this finding came from
    /// a future pkilint integration" — there is no in-tree producer yet.
    Pkilint,
}

impl OracleSource {
    /// Short string label for reports.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PkixLintCabf => "pkix-lint-cabf",
            Self::Zlint => "zlint",
            Self::Pkilint => "pkilint",
        }
    }
}

impl core::fmt::Display for OracleSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// NormalizedFinding
// ---------------------------------------------------------------------------

/// One finding from one oracle on one certificate.
///
/// Cross-oracle vocabulary: each oracle produces findings in its own native
/// shape (zlint's `VerdictMap<check_id, Verdict>`, pkix-lint's
/// `Vec<Finding>`, eventually pkilint's structured output), and the
/// per-oracle adapter normalises them into this type.
///
/// `id` carries the oracle-native lint identifier verbatim — no
/// cross-oracle aliasing happens at the adapter layer. The reconciliation
/// step (PKIX-hbzo.1.3) is where mapping between, e.g., zlint's
/// `e_subject_common_name_not_from_san` and pkix-lint-cabf's
/// `cabf.br.tls.san.required` lives.
///
/// `severity` is the **observed** severity (zlint per-cert verdict for the
/// zlint oracle; the `LintResult` variant for pkix-lint-cabf), not the
/// declared severity from the lint catalog metadata. The two coincide for
/// checks that always fire at one level (zlint's `e_*` prefix), but pkix-lint
/// allows the same lint to emit Warn, Error, or Fatal depending on detail.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NormalizedFinding {
    /// Oracle-native lint identifier.
    pub id: String,
    /// Observed severity for this cert.
    pub severity: pkix_lint::Severity,
    /// Which oracle produced this finding.
    pub source: OracleSource,
}

// Send + Sync compile-time assertion per AGENTS.md PKIX-2l0v.2 const-block
// pattern. NormalizedFinding flows through the reconciliation layer
// (PKIX-hbzo.1.3) which is expected to run oracles in parallel; the
// invariant must hold or the harness deadlocks (or worse, races) when the
// thread pool dispatches calls.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<NormalizedFinding>();
    assert_send_sync::<LintOracleResult>();
    assert_send_sync::<OracleSource>();
};

// ---------------------------------------------------------------------------
// LintOracleResult
// ---------------------------------------------------------------------------

/// Outcome of asking one oracle about one certificate.
///
/// `findings` is the (possibly empty) list of actionable findings.
/// Deterministically sorted by `id` so baseline diffs are stable across
/// `HashMap` iteration order changes (zlint's `VerdictMap` is a `HashMap` —
/// without the sort, two runs against the same cert could produce two
/// different orderings).
///
/// `oracle_error` is `Some(reason)` when the oracle ran but could not produce
/// a verdict for this specific cert (typically: zlint rejected the DER as
/// malformed, or the `pkix-lint-cabf` adapter could not parse the input as
/// `x509_cert::Certificate`). A per-cert oracle error does NOT mean "the
/// cert is invalid" — only "this oracle could not check it." The
/// reconciliation layer treats `oracle_error.is_some()` as a `ToolError`
/// classification distinct from "the oracle ran and emitted no findings."
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LintOracleResult {
    /// Actionable findings, sorted by `id`.
    pub findings: Vec<NormalizedFinding>,
    /// Per-cert oracle failure detail, if any.
    pub oracle_error: Option<String>,
}

impl LintOracleResult {
    /// Construct an empty result with no findings and no oracle error.
    ///
    /// Convenience for unit tests and for the "ran cleanly, found nothing"
    /// case (which is distinct from `oracle_error = Some(...)`).
    #[must_use]
    pub fn ok_empty() -> Self {
        Self {
            findings: Vec::new(),
            oracle_error: None,
        }
    }

    /// Construct an oracle-error result with no findings.
    pub fn oracle_error(reason: impl Into<String>) -> Self {
        Self {
            findings: Vec::new(),
            oracle_error: Some(reason.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// LintOracle
// ---------------------------------------------------------------------------

/// A lint-domain oracle: maps `(cert_der) -> findings`.
///
/// Impls live in this crate. pkix-difftest is dev tooling
/// (`publish = false`) so this trait is not part of any public API surface;
/// the only consumer is the reconciliation layer at PKIX-hbzo.1.3, which
/// dispatches per-oracle through a `&dyn LintOracle` to keep the call-site
/// uniform.
///
/// Implementations should treat `lint_cert` as **referentially transparent**
/// for a given cert: callers may invoke it multiple times on the same input
/// and expect the same result. The [`zlint::ZlintOracle`] adapter relies on
/// `pkix-zlint-bridge`'s per-cert SHA-256 cache so repeated calls cost a
/// hashmap clone, not a subprocess.
///
/// Implementations must be `Send + Sync` — the reconciliation layer may
/// dispatch oracles across threads. Both shipped impls (`ZlintOracle`,
/// `PkixLintCabfOracle`) are `Send + Sync` by construction.
pub trait LintOracle: Send + Sync {
    /// Identifier for this oracle.
    fn source(&self) -> OracleSource;

    /// Lint a single DER-encoded certificate.
    ///
    /// Always returns a [`LintOracleResult`] — adapters do not surface
    /// errors as `Result::Err`. Per-cert oracle failures are reported via
    /// `oracle_error`; bridge-level failures (e.g., zlint binary missing)
    /// are also surfaced via `oracle_error` so a single missing tool does
    /// not crash the whole differential run.
    fn lint_cert(&self, cert_der: &[u8]) -> LintOracleResult;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pkix_lint::Severity;

    #[test]
    fn oracle_source_as_str() {
        assert_eq!(OracleSource::PkixLintCabf.as_str(), "pkix-lint-cabf");
        assert_eq!(OracleSource::Zlint.as_str(), "zlint");
        assert_eq!(OracleSource::Pkilint.as_str(), "pkilint");
    }

    #[test]
    fn lint_oracle_result_constructors() {
        let empty = LintOracleResult::ok_empty();
        assert!(empty.findings.is_empty());
        assert!(empty.oracle_error.is_none());

        let err = LintOracleResult::oracle_error("zlint binary not found");
        assert!(err.findings.is_empty());
        assert_eq!(err.oracle_error.as_deref(), Some("zlint binary not found"));
    }

    #[test]
    fn normalized_finding_equality_is_by_value() {
        // Hash + Eq derive matter for the reconciliation layer (PKIX-hbzo.1.3)
        // which uses HashSet<NormalizedFinding> set-difference for the
        // PkixStricter / PkixLaxer classification. Pin the contract here so
        // a future refactor that swaps id from String to Cow<'static, str>
        // does not silently change set-difference semantics.
        let a = NormalizedFinding {
            id: "cabf.br.tls.validity.max".to_string(),
            severity: Severity::Error,
            source: OracleSource::PkixLintCabf,
        };
        let b = a.clone();
        assert_eq!(a, b);

        let c = NormalizedFinding {
            id: "cabf.br.tls.validity.max".to_string(),
            severity: Severity::Error,
            source: OracleSource::Zlint, // <- different source
        };
        assert_ne!(a, c, "source is part of identity");
    }
}
