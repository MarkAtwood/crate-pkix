# pkix-difftest

Differential testing harness for `pkix-path` against
[OpenSSL](https://www.openssl.org/) (`openssl verify`) and
[pyca/cryptography](https://cryptography.io/)
(`cryptography.x509.verification.PolicyBuilder`).

This is **dev tooling**, not a published library. The crate is
`publish = false`. It exists to surface verdict divergences between
`pkix-path` and the major real-world implementations so we can ship
`pkix-path` with confidence on chains that PKITS alone does not exercise.

See the parent issue [PKIX-7nsf](../.beads/) for the full design
rationale.

## 30-second pitch

PKITS exercises RFC 5280 §6.1 *as written*. Real-world certs and major
shipping implementations (OpenSSL, NSS, BoringSSL, BouncyCastle, JDK,
pyca/cryptography, Microsoft, Apple) all disagree with each other —
and with the literal spec — on dozens of corner cases (DN comparison,
critical-extension allowlists, clock-skew tolerance, negative serials,
RSA-PSS parameter encoding, …). Without a differential test harness,
`pkix-path` will inevitably ship a verdict on some real cert that
disagrees with what every TLS stack on Earth says, and we will not
know until a downstream user files an issue.

`pkix-difftest` runs each chain through `pkix-path` plus one or more
external oracles, classifies the resulting verdict tuple into one of
five buckets (`LooserThanWild`, `StricterThanWild`, `OracleDivergence`,
`DiagnosticDivergence`, `Agreement`), and emits a markdown + JSON
report.

## Quickstart

```sh
# 1. Bootstrap the pyca/cryptography venv (one-time):
./pkix-difftest/python/setup-venv.sh

# 2. Run on a single chain:
cargo run -p pkix-difftest -- single \
  pkix-difftest/tests/fixtures/good-chain.pem \
  --oracle pkix-path,openssl,pyca

# 3. Run on the NIST PKITS corpus:
cargo run -p pkix-difftest -- run pkits pkix-path/tests/pkits \
  --oracles pkix-path,openssl,pyca \
  --output-md pkix-difftest/baseline-pkits.md \
  --output-json pkix-difftest/baseline-pkits.json
```

The `single` subcommand prints one line per oracle and exits 0 / 1 / 2
for Pass / Fail / harness-error. The `run` subcommand emits a markdown
report (default to stdout when `--output-md` is omitted) and exits 0
when the report is produced (verdict counts inside the report are the
signal; non-zero exit means the harness itself failed).

## Architecture

```
pkix-difftest/
├── src/
│   ├── lib.rs         # Verdict, OracleName, Chain, PEM split
│   ├── main.rs        # CLI: single / run pkits|limbo|pem-tree|pem-multi
│   ├── classify.rs    # 5-class verdict classifier (worst-first)
│   ├── report.rs      # markdown + JSON writers (pure)
│   ├── oracles/
│   │   ├── pkix_path.rs   # in-process, system under test
│   │   ├── openssl.rs     # subprocess + stderr parser
│   │   └── pyca.rs        # Python sidecar + JSON IPC
│   └── corpus/
│       ├── pkits.rs       # NIST PKITS vectors.json loader
│       ├── limbo.rs       # x509-limbo limbo.json loader (PKIX-g9vc.2)
│       ├── pem_tree.rs    # recursive chain.pem tree walker
│       └── pem_multi.rs   # explicit-paths CLI corpus
├── python/
│   ├── pyca_oracle.py     # sidecar (chain JSON in, verdict JSON out)
│   └── setup-venv.sh      # idempotent venv bootstrap
├── tests/
│   ├── smoke.rs              # PKIX-7nsf.1
│   ├── openssl_oracle.rs     # PKIX-7nsf.2
│   ├── pyca_oracle.rs        # PKIX-7nsf.3 (skips if no venv)
│   ├── corpus_*.rs           # PKIX-7nsf.4
│   └── fixtures/             # PKITS 4.1.1 + 4.1.2 chains
├── baseline-pkits.md         # auto-generated PKITS (Tier-1) report
├── baseline-pkits.json       # PKITS machine-readable source of truth
├── baseline-pkits-analysis.md# PKITS curated bucket-by-bucket analysis
├── baseline-limbo.md         # auto-generated x509-limbo (Tier-2) report
├── baseline-limbo.json       # limbo machine-readable source of truth
├── baseline-limbo-analysis.md# limbo curated bucket-by-bucket analysis
└── baseline-pyca.md          # corpus-shape finding (see PKIX-g9vc)
```

## How to add a new oracle

1. Create `src/oracles/<name>.rs` with:
   ```rust
   pub fn verify(chain: &Chain) -> std::io::Result<Verdict> { ... }
   ```
2. Add `pub mod <name>;` to `src/oracles/mod.rs`.
3. Add a variant to `OracleName` in `src/lib.rs`.
4. Wire it into `parse_oracle_name` and `run_oracle` in `src/main.rs`.
5. Add an integration test under `tests/<name>_oracle.rs` using
   independent oracles (PKITS ground truth or the existing fixtures).

The oracle must:

* Return `Verdict::Fail { reason }` for actual verification failures.
* Return `Err(io::Error)` for *harness* failures (missing binary,
  malformed input, parse errors). Do NOT silently classify harness
  failures as `Fail` — the classifier needs to distinguish "we asked
  and got Fail" from "we couldn't even ask".
* Not perform shell interpolation. Use `std::process::Command` with
  explicit `arg(...)`.
* Produce deterministic reason strings (no timestamps).

## How to add a new corpus

1. Create `src/corpus/<name>.rs` with a struct that implements:
   ```rust
   impl Corpus for MyCorpus {
       fn iter(&self) -> Box<dyn Iterator<Item = io::Result<CorpusItem>> + '_> { ... }
   }
   ```
2. Each yielded `CorpusItem` has a `name` (used in reports), an
   optional `expected: Verdict` (corpus ground truth), and a `Chain`
   (leaf-first, with the trust anchor present as the last cert).
3. Per-chain errors must be reported as `io::Result` items, not
   silently skipped — the classifier reports per-chain harness errors
   as a separate category.
4. Wire the new corpus into `CorpusCmd` in `src/main.rs`.

## How to re-run a baseline

```sh
cargo run --release -p pkix-difftest -- run pkits pkix-path/tests/pkits \
  --oracles pkix-path,openssl,pyca \
  --output-md pkix-difftest/baseline-pkits.md \
  --output-json pkix-difftest/baseline-pkits.json \
  --title "PKITS baseline (pkix-path vs openssl vs pyca)" \
  --sample-size 50
```

The committed `baseline-pkits.json` is the source of truth. After a
change that affects any verdict, re-run the harness, then `git diff`
the `.json` to see exactly which chains moved between classes. Update
`baseline-pkits-analysis.md` to reflect the new state.

## CI integration

The PKITS corpus runs on every push and pull request via
[`.github/workflows/diff-harness.yml`](../.github/workflows/diff-harness.yml).
The workflow invokes [`scripts/ci-diff-baseline.sh`](scripts/ci-diff-baseline.sh),
which runs the harness and asserts that the verdict-class `summary` and
`ground_truth_disagreements` fields match the committed
`baseline-pkits.json`.

What the CI script intentionally does *not* diff:

- Per-chain `classified[]` reason strings. OpenSSL minor releases reword
  diagnostics ("unable to get local issuer certificate" tweaks across
  3.0 → 3.2) and pyca/cryptography releases change error formatting. A
  reason-string change flips chains between Agreement and
  DiagnosticDivergence without any pkix-path behaviour change — false
  positives the CI script is built to suppress.

What CI does diff:

- `summary`: per-verdict-class counts (Agreement, LooserThanWild,
  StricterThanWild, OracleDivergence, DiagnosticDivergence, total).
- `ground_truth_disagreements`: number of chains where the worst
  verdict disagrees with the corpus expected_result (limbo only).

If CI fails with a diff, the workflow uploads the fresh JSON as a
build artefact (`pkits-fresh-report`). To accept the new state as
intentional:

```sh
# Download the artefact, then locally:
cp <fresh-pkits.json> pkix-difftest/baseline-pkits.json
# Regenerate the markdown report + analysis:
cargo run --release -p pkix-difftest -- run pkits pkix-path/tests/pkits \
  --oracles pkix-path,openssl,pyca \
  --output-md pkix-difftest/baseline-pkits.md
# Update baseline-pkits-analysis.md to reflect the new bucket counts.
# Commit all three: .json, .md, -analysis.md.
```

The x509-limbo Tier-2 corpus is *not* run in CI today because the
~88MB testdata is out-of-tree (lives in `~/GIT/x509-limbo`) and a full
run is ~14 minutes. A scheduled nightly limbo job is filed as a
follow-up; see PKIX-klku notes.

## Tier-2: x509-limbo corpus

[x509-limbo](https://github.com/C2SP/x509-limbo) is the curated
~9.7k-testcase chain-validation corpus that pyca/cryptography's
verifier tests run against. The harness ships a first-class loader
(`pkix-difftest/src/corpus/limbo.rs`) that filters to the
RFC-5280-shaped subset (drops CLIENT validation, feature-tagged
cases, max-chain-depth outliers, and CRL-bearing cases — 9726
cases remaining of 9773) and threads per-testcase `validation_time`
through every oracle.

```sh
# 1. Clone x509-limbo (~88MB, one-time):
git clone --depth=1 https://github.com/C2SP/x509-limbo.git ~/GIT/x509-limbo

# 2. Run the harness (full corpus ≈14 min on a modern workstation):
cargo run --release -p pkix-difftest -- run limbo \
  ~/GIT/x509-limbo/limbo.json \
  --oracles pkix-path,openssl,pyca \
  --output-md pkix-difftest/baseline-limbo.md \
  --output-json pkix-difftest/baseline-limbo.json \
  --title "pkix-difftest baseline (x509-limbo Tier-2)"
```

Committed baseline files:

* `baseline-limbo.json` — machine-readable, lossless source of truth.
* `baseline-limbo.md` — auto-generated per-bucket detail.
* `baseline-limbo-analysis.md` — curated bucket-by-bucket analysis
  (mirrors `baseline-pkits-analysis.md`).

After a code change that affects any verdict, re-run the harness,
`git diff` the `.json`, and update the analysis MD with any new
buckets or net-count shifts.

## Demo: running the entire x509-limbo corpus (legacy PEM-tree path)

This section predates the proper LimboCorpus loader (see "Tier-2"
above for the supported workflow). It is kept for reference because
the PEM-tree converter is still useful for ad-hoc cherry-picking of
testcases into shareable on-disk corpora.



[x509-limbo](https://github.com/C2SP/x509-limbo) is the curated 9,773-
testcase chain-validation corpus that pyca/cryptography's verifier tests
run against. It is the corpus the parent epic PKIX-7nsf originally
called "Tier 2: pyca corpus" (see `baseline-pyca.md` for the discovery
that pyca's `tests/x509/` is parser-shaped, not chain-shaped).

The structurally-correct integration is `run limbo` (see "Tier-2: x509-limbo
corpus" above). The PEM-tree converter described below is a legacy ad-hoc
path predating the proper loader; prefer `run limbo` for any baseline run.

```sh
# 1. Clone x509-limbo (~88MB, one-time):
git clone --depth=1 https://github.com/C2SP/x509-limbo.git ~/GIT/x509-limbo

# 2. Convert testcases into a chain.pem tree (stdlib-only, ~10s):
python3 pkix-difftest/python/limbo-to-pem-tree.py \
  ~/GIT/x509-limbo/limbo.json /tmp/limbo-pem-tree

# 3. Run the harness (full corpus is ~15 min with all three oracles):
cargo run --release -p pkix-difftest -- run pem-tree /tmp/limbo-pem-tree \
  --oracles pkix-path,openssl,pyca \
  --output-md /tmp/limbo-baseline.md \
  --output-json /tmp/limbo-baseline.json \
  --title "x509-limbo demo (pkix-path vs openssl vs pyca)" \
  --sample-size 30
```

Each converted testcase lives at `<output_dir>/<safe_id>/` with a
`chain.pem` (consumed by the harness) and a sibling `meta.json`
capturing the limbo metadata (`expected_result`, `validation_kind`,
`validation_time`, features) for cross-reference against the harness
report.

### Demo-path limitations

This is a **demo path**, not a substitute for the real LimboCorpus
integration:

* **`validation_time` is ignored** — the harness uses the system
  clock for every chain. Testcases whose chain was valid only at a
  specific past time will appear expired and pile up in
  `Agreement(Fail)`.
* **`expected_result` is not threaded through** — the harness's
  PEM-tree loader yields `expected: None`. Cross-reference manually
  via `<output_dir>/<id>/meta.json` and the JSON report.
* **`has-crl` testcases are filtered** at conversion time (CRL
  revocation is out of harness scope).
* **Non-self-signed trust anchors** (~2.5% of testcases by sample)
  fail the chain auto-detection heuristic and surface as per-chain
  harness errors in the report. Limbo's schema permits them; the
  harness's `Chain::from_pem_bytes` requires a self-signed last
  cert.

These are exactly the gaps PKIX-g9vc closes; until then, this is the
fastest way to see the harness exercise a large real-world corpus.

## Limitations

* The harness requires the trust anchor to be the **last** cert in
  the chain. Real-world TLS chains typically omit the root; you must
  append it from a trust store before running the harness. The
  PKITS and LimboCorpus loaders both handle this from corpus
  metadata; the PEM-tree and PEM-multi loaders require pre-assembled
  full chains.
* Per-chain `validation_time` threading: PKITS uses
  per-testcase times from `vectors.json`, LimboCorpus uses
  per-testcase RFC 3339 times from `limbo.json` (with a 2023-11-14
  fallback when null), pyca demo-mode PEM-tree uses the system
  clock. Mix accordingly.
* CRL revocation is not exercised. The harness compares path
  verdicts only; revocation differential testing is a separate
  problem (OCSP responder semantics, CRL distribution-point
  matching). Out of scope for this harness (tracked as PKIX-emf1).
* No CT-log scrape (Tier 3 corpus). Tracked as
  [PKIX-5bab](../.beads/).
* No CI integration — runs are interactive only. Tracked as
  [PKIX-klku](../.beads/).

## Independent oracle discipline

Per `AGENTS.md` test integrity rules, no test in this crate uses
`pkix-path` as its own oracle. The fixtures under `tests/fixtures/`
were chosen because they have **independent** oracles:

* `good-chain.pem` is PKITS 4.1.1 ("Valid Signatures Test1") with
  PKITS ground truth `ShouldValidate: true`. Cross-checked against
  `openssl verify` (exit 0) and `pyca` (verdict pass).
* `bad-chain.pem` is PKITS 4.1.2 ("Invalid CA Signature Test2") with
  PKITS ground truth `ShouldValidate: false`. Cross-checked against
  `openssl verify` (exit 2, "certificate signature failure") and
  `pyca` (verdict fail, "signature does not match").

The smoke tests assert that `pkix-path`'s verdict matches both
PKITS and OpenSSL on those chains.
