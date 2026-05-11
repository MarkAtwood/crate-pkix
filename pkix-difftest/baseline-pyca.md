# pyca corpus baseline — corpus-shape finding

This file is the deliverable for PKIX-7nsf.7 ("pyca corpus baseline
run + commit"). The expected output was a `baseline-pyca.json` with
divergence buckets, mirroring the PKITS baseline at `baseline-pkits.json`.

This file documents why that did not happen and what we did instead.

## Discovery

The PKIX-7nsf parent bead originally described pyca/cryptography's
`tests/x509/v1/` directory as containing "~hundreds of chains" of
"highest signal-to-noise" curated weird certs. Concrete inspection of
[pyca/cryptography](https://github.com/pyca/cryptography) at HEAD reveals
that this is not the case:

* `vectors/cryptography_vectors/x509/` (the actual corpus location) is
  primarily a **parsing-test corpus**: 75 self-signed standalone certs,
  hundreds of single-cert files exercising encoder/decoder edge cases,
  malformed-cert fixtures for negative tests, etc. None of these are
  curated *path-validation* chains.
* The single chain file (`cryptography.io.chain.pem`) ships a TLS
  leaf + intermediate but no trust anchor (the actual root, GeoTrust
  Global CA, is sourced from the system trust store at runtime). The
  harness's input contract requires the trust anchor to be in the
  chain.
* The `custom/` subtree under `vectors/cryptography_vectors/x509/`
  contains feature-targeted single certs (basic-constraints variants,
  KeyUsage variants, etc.), not chains.
* `vectors/cryptography_vectors/x509/PKITS_data/` is pyca's own copy of
  the same NIST PKITS corpus we already process under PKIX-7nsf.6 —
  no new signal there.

## What pyca actually uses for path validation

The path-validation testsuite that pyca's
`cryptography.x509.verification` module actually runs against is
[**x509-limbo**](https://github.com/C2SP/x509-limbo) — a separately
hosted JSON-manifest corpus (9,773 testcases at the cloned head, ~88MB
on disk). Each testcase is a structured spec:

```json
{
  "id": "...",
  "peer_certificate": "<PEM>",
  "untrusted_intermediates": ["<PEM>", ...],
  "trusted_certs": ["<PEM>", ...],
  "validation_time": "ISO8601 or null",
  "validation_kind": "SERVER" | "CLIENT",
  "expected_result": "SUCCESS" | "FAILURE",
  "features": ["has-crl", ...],
  "crls": [...]
}
```

That schema is **exactly** the input shape this harness wants. Building
a `LimboCorpus` loader is the right Tier-2 deliverable; integrating it
requires a non-trivial harness extension (per-testcase
`validation_time` threading through every oracle, replacing the current
"system clock everywhere" model).

## Decision

Filed as a follow-up bead: **PKIX-g9vc — diff harness: x509-limbo
corpus integration (Tier 2 for real)**. That bead is P3 (not blocking
the parent epic) and includes the schema, the architectural changes
required, and the acceptance criteria.

For the `pkix-difftest` baseline of "run on a real-world corpus
and surface divergences", the PKITS baseline (PKIX-7nsf.6,
`baseline-pkits.{md,json}`) already satisfies the parent epic's
"at least one real divergence found, classified, and recorded"
acceptance criterion — 42 LooserThanWild and 60 StricterThanWild
divergences are documented and explained in
`baseline-pkits-analysis.md`.

## Status: PKIX-7nsf.7 acceptance

The bead's literal acceptance criteria, mapped to what we have:

| Criterion | Status |
|---|---|
| All discoverable chains in the pyca corpus produce a verdict from each oracle (or are explicitly filtered with a documented reason) | Met by this document — pyca's `tests/x509/` corpus contains no harness-shape chains; reason documented above. |
| `baseline-pyca.md` and `baseline-pyca.json` committed | This file. `.json` not produced because the corpus is empty after filtering; the JSON would be `{"summary":{"total":0},"classified":[]}`. |
| Every `LooserThanWild` entry has a follow-up bead or written-out justification | Vacuously satisfied (zero LooserThanWild entries). |
| At least one real divergence is found and recorded | Already met by PKIX-7nsf.6 (42 LooserThanWild + 60 StricterThanWild in `baseline-pkits-analysis.md`). |

## What this means for PKIX-7nsf as a whole

The differential harness is structurally complete and produces
real signal on PKITS. The full Tier-2 corpus (x509-limbo, 9,773
testcases) is one P3 bead away. The harness architecture (Corpus
trait, oracle modules, classifier, reporter) is set up to absorb that
work without touching current surfaces.
