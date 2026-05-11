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
│   ├── main.rs        # CLI: single / run pkits|pem-tree|pem-multi
│   ├── classify.rs    # 5-class verdict classifier (worst-first)
│   ├── report.rs      # markdown + JSON writers (pure)
│   ├── oracles/
│   │   ├── pkix_path.rs   # in-process, system under test
│   │   ├── openssl.rs     # subprocess + stderr parser
│   │   └── pyca.rs        # Python sidecar + JSON IPC
│   └── corpus/
│       ├── pkits.rs       # NIST PKITS vectors.json loader
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
├── baseline-pkits.md         # auto-generated PKITS report
├── baseline-pkits.json       # machine-readable source of truth
├── baseline-pkits-analysis.md# curated bucket-by-bucket analysis
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

## Demo: running the entire x509-limbo corpus

[x509-limbo](https://github.com/C2SP/x509-limbo) is the curated 9,773-
testcase chain-validation corpus that pyca/cryptography's verifier tests
run against. It is the corpus the parent epic PKIX-7nsf originally
called "Tier 2: pyca corpus" (see `baseline-pyca.md` for the discovery
that pyca's `tests/x509/` is parser-shaped, not chain-shaped).

The structurally-correct integration — a `LimboCorpus` loader with
per-testcase `validation_time` threading through every oracle — is
tracked under [PKIX-g9vc](../.beads/). Until that lands, you can
exercise the existing PEM-tree corpus loader over the entire limbo
corpus by running the bundled converter:

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
  append it from a trust store before running the harness. This is
  tracked under [PKIX-g9vc](../.beads/) (x509-limbo integration also
  fixes this — its testcase shape carries trust anchors separately).
* Per-chain `validation_time` is system-clock-only. Some test
  corpora (notably x509-limbo) ship per-testcase validation times
  for chains that are now expired but were valid at issue time.
  Threading this through is part of [PKIX-g9vc](../.beads/).
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
