//! Verdict tuple classification.
//!
//! Given a set of `(OracleName, Verdict)` tuples for one chain, decide which
//! divergence class the tuple belongs to. The classifier exists to bucket
//! the harness output into actionable categories — `LooserThanWild` is a
//! likely bug in pkix-path, `Agreement` is noise we can drop from the report,
//! and the middle classes are interop edge cases worth investigating.
//!
//! ## Class precedence
//!
//! The five classes have a strict precedence (worst-first):
//!
//! 1. [`Class::LooserThanWild`] — we accept where the world rejects.
//!    Possible bug in pkix-path.
//! 2. [`Class::StricterThanWild`] — we reject where the world accepts.
//!    Could be intentional spec-strictness or an interop gap.
//! 3. [`Class::OracleDivergence`] — pkix-path agrees with at least one
//!    oracle, and the oracles disagree among themselves. The spec is
//!    genuinely ambiguous; record for posterity.
//! 4. [`Class::DiagnosticDivergence`] — everyone agrees on Pass/Fail but
//!    the *reason* strings differ. Low-signal.
//! 5. [`Class::Agreement`] — all verdicts and reason strings match. Noise.
//!
//! Tie-breaking: when a tuple could fit multiple buckets, the lowest-numbered
//! (worst) class wins. This matters for the report — a `LooserThanWild`
//! tuple that ALSO has reason-string divergence among the oracles that
//! failed should be reported as `LooserThanWild`, not `DiagnosticDivergence`.
//!
//! ## Ground-truth disagreement
//!
//! When the corpus carries an expected verdict (PKITS' `ShouldValidate`),
//! we orthogonally flag tuples where pkix-path's verdict diverges from
//! ground truth. This is independent of oracle classification — a chain can
//! be in `Agreement` but disagree with ground truth (all three oracles got
//! it "wrong" relative to PKITS), or in `LooserThanWild` and agree with
//! ground truth (the world is wrong; PKITS and pkix-path are right).

use std::cmp::Ordering;

use crate::{OracleName, Verdict};

/// One of the 5 divergence classes. Ordering is *worst-first* so a `Vec` of
/// `Class` sorts the bad ones to the top of the report.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Class {
    LooserThanWild,
    StricterThanWild,
    OracleDivergence,
    DiagnosticDivergence,
    Agreement,
}

impl Class {
    /// Numeric rank for ordering (0 = worst, 4 = noise). Used for sorting
    /// the report by severity.
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            Class::LooserThanWild => 0,
            Class::StricterThanWild => 1,
            Class::OracleDivergence => 2,
            Class::DiagnosticDivergence => 3,
            Class::Agreement => 4,
        }
    }

    /// Human-readable name for the class. Used in markdown headings.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Class::LooserThanWild => "LooserThanWild",
            Class::StricterThanWild => "StricterThanWild",
            Class::OracleDivergence => "OracleDivergence",
            Class::DiagnosticDivergence => "DiagnosticDivergence",
            Class::Agreement => "Agreement",
        }
    }
}

impl PartialOrd for Class {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Class {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

/// One classified outcome.
#[derive(Clone, Debug)]
pub struct Classified {
    /// Chain label / name from the corpus.
    pub name: String,
    /// Per-oracle verdicts. Order is preserved from the input.
    pub verdicts: Vec<(OracleName, Verdict)>,
    /// Bucket assignment.
    pub class: Class,
    /// Whether the harness verdict for `pkix-path` disagrees with the
    /// corpus's ground truth. `None` when the corpus does not carry one.
    pub ground_truth_agreement: Option<bool>,
}

/// Classify one chain's verdict tuple.
///
/// `verdicts` MUST contain at least one `(OracleName::PkixPath, _)` entry
/// — pkix-path is the system under test and is the reference for the
/// `LooserThanWild` / `StricterThanWild` direction. If no pkix-path entry
/// is present, the function falls back to `OracleDivergence` semantics
/// (treating any disagreement among oracles as oracle-vs-oracle).
///
/// `expected` is the ground truth for this chain, if the corpus carries
/// one; we use it to set `Classified::ground_truth_agreement`.
#[must_use]
pub fn classify(
    name: String,
    verdicts: Vec<(OracleName, Verdict)>,
    expected: Option<&Verdict>,
) -> Classified {
    let pkix_path_verdict = verdicts
        .iter()
        .find(|(o, _)| *o == OracleName::PkixPath)
        .map(|(_, v)| v.clone());
    let other_verdicts: Vec<&Verdict> = verdicts
        .iter()
        .filter(|(o, _)| *o != OracleName::PkixPath)
        .map(|(_, v)| v)
        .collect();

    let class = if let Some(pkix) = &pkix_path_verdict {
        classify_with_pkix_path(pkix, &other_verdicts, &verdicts)
    } else {
        // No pkix-path in the tuple — fall back to oracle-vs-oracle semantics.
        classify_oracles_only(&verdicts)
    };

    let ground_truth_agreement = expected.and_then(|e| {
        pkix_path_verdict
            .as_ref()
            .map(|pkix| verdicts_match_pass_fail(pkix, e))
    });

    Classified {
        name,
        verdicts,
        class,
        ground_truth_agreement,
    }
}

/// Decide the class given a known pkix-path verdict and the other oracles'
/// verdicts. Implements the precedence rules from the module docs.
fn classify_with_pkix_path(
    pkix: &Verdict,
    others: &[&Verdict],
    full: &[(OracleName, Verdict)],
) -> Class {
    let pkix_pass = pkix.is_pass();
    let any_oracle_pass = others.iter().any(|v| v.is_pass());
    let any_oracle_fail = others.iter().any(|v| !v.is_pass());

    // Precedence rule 1: LooserThanWild — pkix-path Pass, any oracle Fail.
    if pkix_pass && any_oracle_fail {
        return Class::LooserThanWild;
    }
    // Precedence rule 2: StricterThanWild — pkix-path Fail, any oracle Pass.
    if !pkix_pass && any_oracle_pass {
        return Class::StricterThanWild;
    }
    // At this point, pkix-path agrees with EVERY non-pkix oracle on
    // Pass/Fail (because a disagreement would have been caught above).
    // Now check oracle-vs-oracle for cases where pkix-path is on the
    // majority side but oracles disagree among themselves.
    let oracles_agree_on_pass_fail = others.windows(2).all(|w| w[0].is_pass() == w[1].is_pass());
    if !oracles_agree_on_pass_fail {
        // pkix-path agrees with at least one — by construction of the
        // precedence rules above, pkix-path's Pass/Fail equals the
        // pass-state shared by the non-pkix oracles after rules 1 & 2 are
        // ruled out. But the windows check would have caught
        // any internal disagreement. If we reach here, oracles_agree_on_pass_fail
        // is false AND we did not hit rules 1/2 — that's a contradiction
        // unless `others` is empty or has one element. So this branch is
        // unreachable for ≥2 non-pkix oracles. Keep the structure for
        // safety / future-proofing.
        return Class::OracleDivergence;
    }

    // All oracles (including pkix-path) agree on Pass/Fail. Check reasons.
    if all_reasons_match(full) {
        Class::Agreement
    } else {
        Class::DiagnosticDivergence
    }
}

fn classify_oracles_only(verdicts: &[(OracleName, Verdict)]) -> Class {
    if verdicts.is_empty() {
        return Class::Agreement;
    }
    let pass_states: Vec<bool> = verdicts.iter().map(|(_, v)| v.is_pass()).collect();
    let all_pass = pass_states.iter().all(|&p| p);
    let all_fail = pass_states.iter().all(|&p| !p);
    if !(all_pass || all_fail) {
        return Class::OracleDivergence;
    }
    if all_reasons_match(verdicts) {
        Class::Agreement
    } else {
        Class::DiagnosticDivergence
    }
}

/// True iff every verdict in `tuple` shares the same `(pass_state, reason)`.
fn all_reasons_match(tuple: &[(OracleName, Verdict)]) -> bool {
    let mut iter = tuple.iter().map(|(_, v)| v);
    let Some(first) = iter.next() else {
        return true;
    };
    iter.all(|v| v == first)
}

fn verdicts_match_pass_fail(a: &Verdict, b: &Verdict) -> bool {
    a.is_pass() == b.is_pass()
}

/// Sort a slice of `Classified` by class severity (worst first), with name
/// as the tiebreaker for stable, diff-friendly output.
pub fn sort_by_severity(classified: &mut [Classified]) {
    classified.sort_by(|a, b| a.class.cmp(&b.class).then_with(|| a.name.cmp(&b.name)));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pass() -> Verdict {
        Verdict::Pass
    }
    fn fail(r: &str) -> Verdict {
        Verdict::Fail { reason: r.into() }
    }

    #[test]
    fn agreement_when_all_pass_no_reason() {
        let v = vec![
            (OracleName::PkixPath, pass()),
            (OracleName::OpenSsl, pass()),
            (OracleName::Pyca, pass()),
        ];
        let c = classify("t".into(), v, None);
        assert_eq!(c.class, Class::Agreement);
    }

    #[test]
    fn agreement_when_all_fail_same_reason() {
        let v = vec![
            (OracleName::PkixPath, fail("X")),
            (OracleName::OpenSsl, fail("X")),
        ];
        let c = classify("t".into(), v, None);
        assert_eq!(c.class, Class::Agreement);
    }

    #[test]
    fn diagnostic_divergence_when_all_fail_with_different_reasons() {
        let v = vec![
            (OracleName::PkixPath, fail("path-says")),
            (OracleName::OpenSsl, fail("openssl-says")),
            (OracleName::Pyca, fail("pyca-says")),
        ];
        let c = classify("t".into(), v, None);
        assert_eq!(c.class, Class::DiagnosticDivergence);
    }

    #[test]
    fn looser_than_wild_pkix_pass_oracles_fail() {
        let v = vec![
            (OracleName::PkixPath, pass()),
            (OracleName::OpenSsl, fail("nope")),
            (OracleName::Pyca, fail("nope2")),
        ];
        let c = classify("t".into(), v, None);
        assert_eq!(c.class, Class::LooserThanWild);
    }

    #[test]
    fn looser_than_wild_when_one_oracle_disagrees() {
        // One Pass agreement does NOT save us if any oracle fails.
        let v = vec![
            (OracleName::PkixPath, pass()),
            (OracleName::OpenSsl, pass()),
            (OracleName::Pyca, fail("nope")),
        ];
        let c = classify("t".into(), v, None);
        assert_eq!(c.class, Class::LooserThanWild);
    }

    #[test]
    fn stricter_than_wild_pkix_fail_oracles_pass() {
        let v = vec![
            (OracleName::PkixPath, fail("ours")),
            (OracleName::OpenSsl, pass()),
            (OracleName::Pyca, pass()),
        ];
        let c = classify("t".into(), v, None);
        assert_eq!(c.class, Class::StricterThanWild);
    }

    #[test]
    fn oracle_divergence_when_oracles_split_and_pkix_agrees_with_one() {
        // pkix-path Pass; OpenSSL Pass; Pyca Fail. This hits LooserThanWild
        // by our precedence rules (any oracle Fail with pkix Pass).
        // For a true OracleDivergence with pkix-path agreeing with the
        // majority, we need: no oracle disagrees on pass-state with pkix
        // (so neither rule 1 nor 2 fires) AND oracles disagree among
        // themselves. With only 1 non-pkix oracle that's not possible.
        // Test the no-pkix path instead.
        let v = vec![
            (OracleName::OpenSsl, pass()),
            (OracleName::Pyca, fail("nope")),
        ];
        let c = classify("t".into(), v, None);
        assert_eq!(c.class, Class::OracleDivergence);
    }

    #[test]
    fn ground_truth_agreement_recorded_when_pkix_matches_expected() {
        let v = vec![(OracleName::PkixPath, pass())];
        let c = classify("t".into(), v, Some(&pass()));
        assert_eq!(c.ground_truth_agreement, Some(true));
    }

    #[test]
    fn ground_truth_disagreement_recorded_when_pkix_diverges() {
        let v = vec![(OracleName::PkixPath, fail("ours"))];
        let c = classify("t".into(), v, Some(&pass()));
        assert_eq!(c.ground_truth_agreement, Some(false));
    }

    #[test]
    fn ground_truth_none_when_corpus_has_no_expected() {
        let v = vec![(OracleName::PkixPath, pass())];
        let c = classify("t".into(), v, None);
        assert_eq!(c.ground_truth_agreement, None);
    }

    #[test]
    fn class_rank_ordering_is_worst_first() {
        let mut classes = vec![
            Class::Agreement,
            Class::LooserThanWild,
            Class::DiagnosticDivergence,
            Class::StricterThanWild,
            Class::OracleDivergence,
        ];
        classes.sort();
        assert_eq!(
            classes,
            vec![
                Class::LooserThanWild,
                Class::StricterThanWild,
                Class::OracleDivergence,
                Class::DiagnosticDivergence,
                Class::Agreement,
            ]
        );
    }

    #[test]
    fn sort_by_severity_uses_name_as_tiebreaker() {
        let mk = |name: &str, class: Class| Classified {
            name: name.into(),
            verdicts: vec![],
            class,
            ground_truth_agreement: None,
        };
        let mut items = vec![
            mk("z-good", Class::Agreement),
            mk("b-bad", Class::LooserThanWild),
            mk("a-bad", Class::LooserThanWild),
            mk("c-meh", Class::DiagnosticDivergence),
        ];
        sort_by_severity(&mut items);
        let names: Vec<_> = items.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["a-bad", "b-bad", "c-meh", "z-good"]);
    }
}
