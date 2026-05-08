//! Markdown + JSON reporters.
//!
//! Both writers are pure (no I/O beyond the supplied writer) so callers can
//! emit to a tempfile, stdout, an in-memory buffer, etc. Reports are
//! deterministic — no timestamps in the body, sorted classifier output —
//! so committing a baseline file produces a meaningful diff under
//! version control.
//!
//! The JSON output is the source of truth (machine-readable, lossless).
//! The markdown output is a curated human-readable summary with a sample
//! count per class so reports stay small even for million-chain corpora.

use std::io;

use crate::classify::{Class, Classified};
use crate::OracleName;

/// Options controlling markdown rendering.
#[derive(Clone, Debug)]
pub struct MarkdownOptions {
    /// Maximum number of sample chains to show under each class section.
    /// Default 10. Use a large number for "show everything"; 0 to skip
    /// per-class samples and show only the summary table.
    pub sample_size: usize,
    /// Optional title for the report (rendered as the H1 heading). If None,
    /// a default ("pkix-difftest report") is used.
    pub title: Option<String>,
}

impl Default for MarkdownOptions {
    fn default() -> Self {
        Self {
            sample_size: 10,
            title: None,
        }
    }
}

/// Write a markdown report to `out`. The slice is *not* sorted in place;
/// caller is responsible for calling `classify::sort_by_severity` if they
/// want worst-first order. We re-sort internally for the per-class samples,
/// but rely on the caller for the top-level summary table.
pub fn write_markdown(
    out: &mut impl io::Write,
    classified: &[Classified],
    options: &MarkdownOptions,
) -> io::Result<()> {
    let title = options.title.as_deref().unwrap_or("pkix-difftest report");
    writeln!(out, "# {title}")?;
    writeln!(out)?;

    // Summary table: counts per class.
    writeln!(out, "## Summary")?;
    writeln!(out)?;
    writeln!(out, "| Class | Count |")?;
    writeln!(out, "|---|---:|")?;
    let counts = count_per_class(classified);
    for class in CLASSES_WORST_FIRST {
        writeln!(
            out,
            "| {} | {} |",
            class.name(),
            counts[class.rank() as usize]
        )?;
    }
    writeln!(out, "| **Total** | {} |", classified.len())?;
    writeln!(out)?;

    // Ground-truth disagreements — orthogonal to oracle classification, so
    // surfaced as its own section regardless of the per-class buckets.
    let gt_disagreements: Vec<&Classified> = classified
        .iter()
        .filter(|c| c.ground_truth_agreement == Some(false))
        .collect();
    if !gt_disagreements.is_empty() {
        writeln!(out, "## Ground-truth disagreements")?;
        writeln!(out)?;
        writeln!(
            out,
            "{} chain(s) where pkix-path's verdict disagrees with the corpus's expected verdict. \
             This category is orthogonal to oracle-classification — it counts pkix-path-vs-PKITS \
             only, regardless of what the other oracles say.",
            gt_disagreements.len()
        )?;
        writeln!(out)?;
        for c in gt_disagreements.iter().take(options.sample_size) {
            write_chain_block(out, c)?;
        }
        if gt_disagreements.len() > options.sample_size {
            writeln!(
                out,
                "_({} additional ground-truth disagreement(s) omitted; see JSON report.)_",
                gt_disagreements.len() - options.sample_size
            )?;
            writeln!(out)?;
        }
    }

    if options.sample_size == 0 {
        return Ok(());
    }

    // Per-class samples, worst-first.
    for class in CLASSES_WORST_FIRST {
        let in_class: Vec<&Classified> = classified.iter().filter(|c| c.class == *class).collect();
        if in_class.is_empty() {
            continue;
        }
        writeln!(out, "## {} ({})", class.name(), in_class.len())?;
        writeln!(out)?;
        for c in in_class.iter().take(options.sample_size) {
            write_chain_block(out, c)?;
        }
        if in_class.len() > options.sample_size {
            writeln!(
                out,
                "_({} additional sample(s) in this class omitted; see JSON report.)_",
                in_class.len() - options.sample_size
            )?;
            writeln!(out)?;
        }
    }

    Ok(())
}

/// Worst-first iteration order for class loops. Const for clarity at every
/// call site that walks classes by precedence.
const CLASSES_WORST_FIRST: &[Class] = &[
    Class::LooserThanWild,
    Class::StricterThanWild,
    Class::OracleDivergence,
    Class::DiagnosticDivergence,
    Class::Agreement,
];

fn count_per_class(classified: &[Classified]) -> [usize; 5] {
    let mut counts = [0usize; 5];
    for c in classified {
        counts[c.class.rank() as usize] += 1;
    }
    counts
}

fn write_chain_block(out: &mut impl io::Write, c: &Classified) -> io::Result<()> {
    writeln!(out, "### `{}`", escape_md(&c.name))?;
    writeln!(out)?;
    if let Some(agreement) = c.ground_truth_agreement {
        writeln!(
            out,
            "* Ground truth: {}",
            if agreement { "matches" } else { "DISAGREES" }
        )?;
    }
    writeln!(out, "* Class: `{}`", c.class.name())?;
    writeln!(out, "* Verdicts:")?;
    for (oracle, verdict) in &c.verdicts {
        writeln!(out, "  * {}: {}", oracle, escape_md(&verdict.to_string()))?;
    }
    writeln!(out)?;
    Ok(())
}

/// Escape pipe and backtick characters that would break out of markdown
/// table cells / inline code spans. We do not need full markdown escaping —
/// chain names are filenames and verdict reasons are short error strings.
fn escape_md(s: &str) -> String {
    s.replace('`', "\\`").replace('|', "\\|")
}

/// Write a JSON report to `out`. The shape is:
/// ```json
/// {
///   "summary": { "LooserThanWild": N, ..., "total": N },
///   "ground_truth_disagreements": [...],
///   "classified": [{ "name": "...", "class": "...", "verdicts": [...], ... }, ...]
/// }
/// ```
pub fn write_json(out: &mut impl io::Write, classified: &[Classified]) -> io::Result<()> {
    let counts = count_per_class(classified);
    let mut summary = serde_json::Map::new();
    for class in CLASSES_WORST_FIRST {
        summary.insert(
            class.name().to_string(),
            serde_json::Value::from(counts[class.rank() as usize]),
        );
    }
    summary.insert(
        "total".to_string(),
        serde_json::Value::from(classified.len()),
    );

    let gt_disagreements: Vec<serde_json::Value> = classified
        .iter()
        .filter(|c| c.ground_truth_agreement == Some(false))
        .map(classified_to_json)
        .collect();

    let body = serde_json::json!({
        "summary": summary,
        "ground_truth_disagreements": gt_disagreements,
        "classified": classified.iter().map(classified_to_json).collect::<Vec<_>>(),
    });

    serde_json::to_writer_pretty(&mut *out, &body)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("JSON encode: {e}")))?;
    // serde_json::to_writer_pretty does not append a trailing newline.
    writeln!(out)?;
    Ok(())
}

fn classified_to_json(c: &Classified) -> serde_json::Value {
    serde_json::json!({
        "name": c.name,
        "class": c.class.name(),
        "ground_truth_agreement": c.ground_truth_agreement,
        "verdicts": c.verdicts.iter().map(verdict_pair_to_json).collect::<Vec<_>>(),
    })
}

fn verdict_pair_to_json(pair: &(OracleName, crate::Verdict)) -> serde_json::Value {
    use crate::Verdict;
    let (verdict, reason) = match &pair.1 {
        Verdict::Pass => ("pass", None),
        Verdict::Fail { reason } => ("fail", Some(reason.as_str())),
    };
    serde_json::json!({
        "oracle": pair.0.as_str(),
        "verdict": verdict,
        "reason": reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::{classify, sort_by_severity};
    use crate::Verdict;

    fn pass() -> Verdict {
        Verdict::Pass
    }
    fn fail(r: &str) -> Verdict {
        Verdict::Fail { reason: r.into() }
    }

    fn sample_classified() -> Vec<Classified> {
        vec![
            classify(
                "good".into(),
                vec![
                    (OracleName::PkixPath, pass()),
                    (OracleName::OpenSsl, pass()),
                ],
                Some(&pass()),
            ),
            classify(
                "bad-diag".into(),
                vec![
                    (OracleName::PkixPath, fail("a")),
                    (OracleName::OpenSsl, fail("b")),
                ],
                Some(&fail("expected")),
            ),
            classify(
                "loose".into(),
                vec![
                    (OracleName::PkixPath, pass()),
                    (OracleName::OpenSsl, fail("nope")),
                ],
                Some(&fail("expected")),
            ),
        ]
    }

    #[test]
    fn write_markdown_includes_summary_counts() {
        let mut data = sample_classified();
        sort_by_severity(&mut data);
        let mut buf = Vec::new();
        write_markdown(&mut buf, &data, &MarkdownOptions::default()).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("# pkix-difftest report"));
        assert!(s.contains("## Summary"));
        assert!(s.contains("LooserThanWild"));
        assert!(s.contains("DiagnosticDivergence"));
        assert!(s.contains("**Total**"));
    }

    #[test]
    fn write_markdown_includes_ground_truth_section_when_disagreements_exist() {
        let mut data = sample_classified();
        sort_by_severity(&mut data);
        let mut buf = Vec::new();
        write_markdown(&mut buf, &data, &MarkdownOptions::default()).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("## Ground-truth disagreements"));
        // 'loose' agrees with expected (both Pass for pkix-path? actually pkix is Pass and expected is Fail — DISAGREES).
        // 'bad-diag' agrees with expected (both Fail).
        // So one ground-truth disagreement should appear.
        assert!(s.contains("DISAGREES"));
    }

    #[test]
    fn write_markdown_omits_per_class_section_when_sample_size_zero() {
        let mut data = sample_classified();
        sort_by_severity(&mut data);
        let mut buf = Vec::new();
        write_markdown(
            &mut buf,
            &data,
            &MarkdownOptions {
                sample_size: 0,
                title: None,
            },
        )
        .unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("## Summary"));
        // Per-class headers are H2 with class name + count, NOT the
        // summary table where the class names are inside table cells.
        assert!(!s.contains("## LooserThanWild"));
    }

    #[test]
    fn write_markdown_truncates_per_class_samples() {
        // 12 LooserThanWild items; sample_size=3 should cap the rendered
        // list at 3 with a "9 omitted" footer.
        let mut data: Vec<Classified> = (0..12)
            .map(|i| {
                classify(
                    format!("loose-{i:02}"),
                    vec![
                        (OracleName::PkixPath, pass()),
                        (OracleName::OpenSsl, fail("nope")),
                    ],
                    None,
                )
            })
            .collect();
        sort_by_severity(&mut data);
        let mut buf = Vec::new();
        write_markdown(
            &mut buf,
            &data,
            &MarkdownOptions {
                sample_size: 3,
                title: None,
            },
        )
        .unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("9 additional sample(s) in this class omitted"));
    }

    #[test]
    fn write_json_round_trips() {
        let mut data = sample_classified();
        sort_by_severity(&mut data);
        let mut buf = Vec::new();
        write_json(&mut buf, &data).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert!(parsed.get("summary").is_some());
        assert!(parsed.get("classified").is_some());
        assert!(parsed.get("ground_truth_disagreements").is_some());
        let total = parsed["summary"]["total"].as_u64().unwrap();
        assert_eq!(total, 3);
    }

    #[test]
    fn write_json_classified_entry_shape() {
        let data = sample_classified();
        let mut buf = Vec::new();
        write_json(&mut buf, &data).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        let entries = parsed["classified"].as_array().unwrap();
        let first = &entries[0];
        assert!(first.get("name").is_some());
        assert!(first.get("class").is_some());
        assert!(first.get("verdicts").is_some());
        let verdicts = first["verdicts"].as_array().unwrap();
        let v0 = &verdicts[0];
        assert!(v0.get("oracle").is_some());
        assert!(v0.get("verdict").is_some());
        assert!(v0.get("reason").is_some());
    }

    #[test]
    fn escape_md_escapes_pipes_and_backticks() {
        assert_eq!(escape_md("a|b"), "a\\|b");
        assert_eq!(escape_md("a`b"), "a\\`b");
    }
}
