//! Every PKITS vector, scored against NIST's expected verdict.
//!
//! The manifest ships 249 vectors and each carries its own ground truth
//! (`ShouldValidate`) and its own RFC 5280 §6.1.1 initial inputs. The
//! loader resolves both, and the pkix-path oracle validates under the
//! inputs, so each vector can be scored.
//!
//! # Oracle
//!
//! NIST PKITS (SP 800-89), `vectors.json`'s per-vector `ShouldValidate`
//! flag. PKITS standardises *whether* a path validates, not why, so this
//! asserts the verdict's direction only -- `Verdict::Fail`'s reason is
//! not compared.
//!
//! # What this covers that the per-section tests do not
//!
//! `pkix-path/tests/pkits_*.rs` assert named vectors one function at a
//! time, which leaves whichever vectors nobody wrote a function for
//! unexercised and makes the count of what is covered a grep. This runs
//! the whole manifest, so a vector is either scored or named in the
//! failure list.

use std::collections::BTreeMap;
use std::path::PathBuf;

use pkix_difftest::corpus::pkits::PkitsCorpus;
use pkix_difftest::corpus::Corpus;
use pkix_difftest::{oracles, Verdict};

/// Vectors pkix-path is known not to satisfy, each with its reason.
///
/// Every entry is a tracked decision, not an accepted wrong answer. A
/// vector listed here that starts agreeing with NIST fails this test, so
/// a fix cannot leave a stale exemption behind.
fn known_gaps() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        // DSA verification is intended but not implemented. The stance
        // is settled and recorded in AGENTS.md: verify-only and opt-in,
        // mirroring FIPS 186-5, which retains DSA "only for the purposes
        // of verifying existing signatures". So these two are a backlog
        // item behind a feature flag rather than a permanent refusal,
        // and implementing it means deleting both entries in the same
        // change. Tracked in PKIX-vb4o.
        //
        // pyca refuses these vectors too ("Forbidden public key
        // algorithm"); of the three oracles only OpenSSL accepts them.
        (
            "4.1.4 Valid DSA Signatures Test4",
            "DSA verification not implemented; verify-only/opt-in is the recorded stance (PKIX-vb4o)",
        ),
        (
            "4.1.5 Valid DSA Parameter Inheritance Test5",
            "same, plus RFC 3279 §2.3.2 parameter inheritance (PKIX-vb4o)",
        ),
        // notBefore is 500101120100Z, which RFC 5280 §4.1.2.5.1 reads as
        // 1950 -- below the 1970 floor of the `der` crate's UtcTime. The
        // certificate does not parse, so there is no verdict to score.
        // Supporting it means either forking `der` or pre-processing the
        // time field, and this workspace supports 1970-2049 and does not
        // fork `der`.
        (
            "4.2.3 Valid pre2000 UTC notBefore Date Test3",
            "notBefore 1950 is below der's 1970 floor (PKIX-2kgd)",
        ),
    ])
}

/// What scoring one vector produced.
enum Outcome {
    /// pkix-path and NIST agree on whether the path validates.
    Agreed,
    /// Both produced a verdict and they differ.
    Disagreed(String),
    /// No verdict: the chain did not load.
    HarnessError(String),
}

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("pkix-path/tests/pkits")
}

#[test]
fn every_pkits_vector_matches_nist_ground_truth() {
    let corpus = PkitsCorpus::load(corpus_root()).expect("load PKITS manifest");
    let gaps = known_gaps();

    let mut attempted = 0usize;
    let mut agreed = 0usize;
    let mut problems: Vec<String> = Vec::new();
    let mut stale: Vec<String> = Vec::new();

    for item in corpus.iter() {
        let item = item.expect("PKITS entry resolves");
        let expected = item
            .expected
            .as_ref()
            .expect("every PKITS vector carries ground truth");
        attempted += 1;

        let outcome = match oracles::pkix_path::verify(&item.chain) {
            Err(e) => Outcome::HarnessError(format!("chain did not load: {e}")),
            // PKITS fixes only whether a path validates, not why, so
            // only the direction is compared.
            Ok(v) => match (&v, expected) {
                (Verdict::Pass, Verdict::Pass) | (Verdict::Fail { .. }, Verdict::Fail { .. }) => {
                    Outcome::Agreed
                }
                _ => Outcome::Disagreed(format!(
                    "NIST says {}, pkix-path says {v}",
                    match expected {
                        Verdict::Pass => "valid",
                        Verdict::Fail { .. } => "invalid",
                    }
                )),
            },
        };

        let exempt = gaps.get(item.name.as_str());
        match (&outcome, exempt) {
            (Outcome::Agreed, None) => agreed += 1,
            (Outcome::Agreed, Some(reason)) => {
                agreed += 1;
                stale.push(format!(
                    "{} agrees with NIST now; drop the exemption ({reason})",
                    item.name
                ));
            }
            // A known gap behaving as recorded.
            (_, Some(_)) => {}
            (Outcome::Disagreed(d), None) => problems.push(format!("{}: {d}", item.name)),
            (Outcome::HarnessError(e), None) => problems.push(format!("{}: {e}", item.name)),
        }
    }

    let mut report = String::new();
    if attempted != 249 {
        report.push_str(&format!("\nattempted {attempted} of 249 vectors\n"));
    }
    if !problems.is_empty() {
        report.push_str(&format!(
            "\n{} vector(s) not matching NIST and not a recorded gap:\n",
            problems.len()
        ));
        for p in &problems {
            report.push_str(&format!("  {p}\n"));
        }
    }
    if !stale.is_empty() {
        report.push_str(&format!("\n{} stale exemption(s):\n", stale.len()));
        for s in &stale {
            report.push_str(&format!("  {s}\n"));
        }
    }
    assert!(report.is_empty(), "{report}");

    // The exemptions are the only vectors allowed not to agree, so the
    // count is pinned: a new gap cannot be absorbed silently.
    assert_eq!(
        agreed,
        249 - known_gaps().len(),
        "every vector but the recorded gaps must agree with NIST"
    );
}
