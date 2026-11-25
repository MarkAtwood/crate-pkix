#!/usr/bin/env bash
# ci-diff-baseline.sh — run the pkix-difftest harness on a corpus and assert
# the resulting verdict-class summary matches the committed baseline.
#
# Usage:
#   ci-diff-baseline.sh <corpus-spec> <corpus-arg> <baseline-json> [--oracles=...]
#
# Examples:
#   ci-diff-baseline.sh pkits pkix-path/tests/pkits pkix-difftest/baseline-pkits.json
#   ci-diff-baseline.sh limbo /tmp/limbo.json pkix-difftest/baseline-limbo.json \
#       --oracles=pkix-path,openssl,pyca
#
# What we compare and why:
#
# The diff harness emits a JSON report with three top-level keys:
#   - "summary":                 per-verdict-class counts (e.g. Agreement: 71)
#   - "ground_truth_disagreements": ARRAY of per-chain detail, each entry
#                                  carrying name, class, and every oracle's
#                                  verdict AND reason string
#   - "classified":              per-chain detail with full reason strings
#
# Oracle reason strings are not stable. They vary between OpenSSL versions
# (e.g. "unable to get local issuer certificate" wording tweaks across
# 3.0.x -> 3.2.x) and pyca/cryptography releases, and this job runs against
# whatever those are on ubuntu-latest. A reason-string change must not be able
# to fail this gate, because it says nothing about pkix-path.
#
# Two places leaked reason-string sensitivity in and had to be closed:
#
# 1. The Agreement / DiagnosticDivergence split. DiagnosticDivergence means
#    every oracle agreed on pass/fail and differed only on the reason, so a
#    reason-string change moves a chain between those two buckets with no
#    verdict changing. They are therefore summed into one "VerdictsAgreed"
#    count, and the distinction is no longer gated. (This is what left the job
#    red from 2026-11-16: eight chains drifted Agreement -> DiagnosticDivergence
#    with every verdict identical.)
#
# 2. "ground_truth_disagreements" embeds the reason strings directly. The old
#    filter diffed it whole, which contradicted the stated policy right above
#    it. Reasons are now stripped; oracle + verdict + name + class survive.
#
# What this gate still catches, which is the signal worth having:
#   - LooserThanWild   — pkix-path accepts what an oracle rejects
#   - StricterThanWild — pkix-path rejects what an oracle accepts
#   - OracleDivergence — the oracles disagree with each other
#   - total            — chains appearing or vanishing from the corpus
#   - which chains disagree with corpus ground truth, and how they voted
#
# What it no longer catches, deliberately: a change in how an oracle words a
# failure. Use `pkix-difftest report` locally for that.
#
# Exit codes:
#   0  — summary + gt_disagreements match the committed baseline
#   1  — they do not match (regression or improvement; either way: investigate)
#   2  — harness error (missing tools, missing fixtures, etc.)

set -euo pipefail

if (( $# < 3 )); then
    cat >&2 <<EOF
usage: $0 <corpus-spec> <corpus-arg> <baseline-json> [extra args to harness]

  corpus-spec   pkits | limbo | pem-tree | pem-multi
  corpus-arg    directory or manifest path expected by the corpus-spec
  baseline-json path to the committed baseline JSON to diff against
  extra args    passed through to pkix-difftest, e.g. --oracles=...
EOF
    exit 2
fi

CORPUS_SPEC="$1"
CORPUS_ARG="$2"
BASELINE_JSON="$3"
shift 3

if [[ ! -f "$BASELINE_JSON" ]]; then
    echo "ci-diff-baseline.sh: baseline JSON not found: $BASELINE_JSON" >&2
    exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "ci-diff-baseline.sh: jq is required but not on PATH" >&2
    exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HARNESS="${REPO_ROOT}/target/release/pkix-difftest"

if [[ ! -x "$HARNESS" ]]; then
    echo "ci-diff-baseline.sh: harness binary missing; run 'cargo build -p pkix-difftest --release' first" >&2
    echo "  expected: $HARNESS" >&2
    exit 2
fi

# Default pyca venv path: pkix-difftest/python/.venv created by setup-venv.sh.
# Allow override via PYCA_DIFFTEST_PYTHON for caller-supplied venvs in CI.
if [[ -z "${PYCA_DIFFTEST_PYTHON:-}" ]]; then
    DEFAULT_VENV="${REPO_ROOT}/pkix-difftest/python/.venv/bin/python"
    if [[ -x "$DEFAULT_VENV" ]]; then
        export PYCA_DIFFTEST_PYTHON="$DEFAULT_VENV"
    fi
fi

FRESH_JSON="$(mktemp -t pkix-difftest-fresh.XXXXXX.json)"
trap 'rm -f "$FRESH_JSON"' EXIT

echo "ci-diff-baseline.sh: running '${HARNESS}' run ${CORPUS_SPEC} ${CORPUS_ARG}"
"$HARNESS" run "$CORPUS_SPEC" "$CORPUS_ARG" \
    --output-json "$FRESH_JSON" \
    "$@"

# Extract just the comparison-stable fields from both reports.
BASELINE_FILTERED="$(mktemp -t pkix-difftest-baseline.XXXXXX.json)"
FRESH_FILTERED="$(mktemp -t pkix-difftest-fresh-filtered.XXXXXX.json)"
trap 'rm -f "$FRESH_JSON" "$BASELINE_FILTERED" "$FRESH_FILTERED"' EXIT

# Verdict classes, with the two reason-text-sensitive buckets merged, and
# ground-truth disagreements with reason strings stripped. Arrays are sorted so
# element order cannot fail the gate either.
JQ_FILTER='
{
  verdict_classes: {
    VerdictsAgreed:   ((.summary.Agreement // 0) + (.summary.DiagnosticDivergence // 0)),
    LooserThanWild:   (.summary.LooserThanWild   // 0),
    StricterThanWild: (.summary.StricterThanWild // 0),
    OracleDivergence: (.summary.OracleDivergence // 0),
    total:            (.summary.total            // 0)
  },
  ground_truth_disagreements:
    [ (.ground_truth_disagreements // [])[]
      | {
          name,
          class: (if .class == "DiagnosticDivergence" then "VerdictsAgreed"
                  elif .class == "Agreement"          then "VerdictsAgreed"
                  else .class end),
          verdicts: [ .verdicts[] | {oracle, verdict} ] | sort_by(.oracle)
        }
    ] | sort_by(.name)
}'
jq -S "$JQ_FILTER" "$BASELINE_JSON" > "$BASELINE_FILTERED"
jq -S "$JQ_FILTER" "$FRESH_JSON"    > "$FRESH_FILTERED"

if diff -u "$BASELINE_FILTERED" "$FRESH_FILTERED"; then
    echo "ci-diff-baseline.sh: summary matches committed baseline"
    exit 0
fi

# Mismatch. Print enough context for a CI log reader to triage.
echo
echo "ci-diff-baseline.sh: REGRESSION — summary diverged from committed baseline"
echo
echo "Baseline:                ${BASELINE_JSON}"
echo "Fresh run:               ${FRESH_JSON}  (NOT cleaned up so you can inspect)"
echo
echo "To investigate locally, compare the full reports:"
echo "  diff <(jq -S . ${BASELINE_JSON}) <(jq -S . ${FRESH_JSON}) | less"
echo
echo "If the divergence is intentional (e.g. you fixed a bug in pkix-path),"
echo "regenerate the baseline:"
echo "  cp ${FRESH_JSON} ${BASELINE_JSON}"
echo "  (then re-run any baseline-XXX-analysis.md regenerators and commit)"

# Keep the fresh JSON so a developer can `cp` it; override the cleanup trap.
trap 'rm -f "$BASELINE_FILTERED" "$FRESH_FILTERED"' EXIT
exit 1
