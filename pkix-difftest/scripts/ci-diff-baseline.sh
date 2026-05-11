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
#   - "ground_truth_disagreements": int, # of chains where the worst-classified
#                                  verdict disagrees with the corpus
#                                  expected_result (limbo only; null on PKITS)
#   - "classified":              per-chain detail with full reason strings
#
# We deliberately do NOT diff "classified" verbatim. Oracle reason strings vary
# between OpenSSL versions (e.g. "unable to get local issuer certificate" wording
# tweaks across 3.0.x → 3.2.x) and pyca/cryptography releases. A reason-string
# change flips chains between Agreement and DiagnosticDivergence without any
# pkix-path behaviour change, which is exactly the kind of false positive the
# bead text warns about.
#
# Instead we diff:
#   - "summary"                    — verdict-class count drifts are real signal
#   - "ground_truth_disagreements" — semantic correctness drifts are real signal
#
# Any other report-shape divergence is a tooling concern, not a regression.
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

JQ_FILTER='{summary, ground_truth_disagreements}'
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
