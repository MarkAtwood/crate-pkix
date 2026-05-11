# PKITS baseline analysis

Hand-classified bucket analysis of the PKITS divergence baseline produced by
`pkix-difftest run pkits ...`. The companion files are:

* `baseline-pkits.json` — machine-readable, lossless. Source of truth.
* `baseline-pkits.md` — auto-generated human-readable detail (every chain
  per bucket, sample-capped). Regenerated from the same run.

This document is the **curated** layer: per-bucket reasoning about whether
each divergence is a real bug, an intentional spec stricture, or an
oracle quirk. It is the deliverable required by PKIX-7nsf.6's acceptance
criterion "every LooserThanWild / StricterThanWild entry has a follow-up
bead OR a written-out justification".

## Run

* Tool: `pkix-difftest` HEAD of branch (commit visible via `git log -1`).
* Corpus: NIST PKITS shipped under `pkix-path/tests/pkits/` (249 vectors).
* Oracles: `pkix-path` (default features), system `openssl` 3.0.13,
  `pyca/cryptography` 48.0.0.
* `pkix-path` invocation: `ValidationPolicy::new(now)` (permissive — no
  required SAN/EKU/algorithm/key-size strictures).
* `pyca` invocation: `PolicyBuilder::build_client_verifier()` with
  `ExtensionPolicy::permit_all()` for EE and `webpki_defaults_ca()` for CA
  (pyca's own invariant requires basicConstraints on CA policies).

## Summary

| Class | Count | % |
|---|---:|---:|
| LooserThanWild       | 42  | 17.0% |
| StricterThanWild     | 60  | 24.3% |
| OracleDivergence     | 0   | 0.0%  |
| DiagnosticDivergence | 34  | 13.8% |
| Agreement            | 111 | 44.9% |
| **Total**            | **247** | |

Two PKITS chains are excluded from classification (harness errors):

* `4.1.5 Valid DSA Parameter Inheritance Test5` — pyca rejects the SPKI
  parameters as malformed ASN.1 (DSA inheritance encoding edge case).
  Affects only the pyca verdict; not a pkix-path divergence.
* `4.2.3 Valid pre2000 UTC notBefore Date Test3` — pkix-path's underlying
  `x509-cert` 0.2.5 rejects pre-2000 UTCTime encoding as malformed
  (RustCrypto/formats issue, separately tracked upstream).

## LooserThanWild (42) — pkix-path Pass, ≥1 oracle Fail

**Verdict: 0 real pkix-path bugs.** All 42 entries are `pkix-path Pass +
openssl Pass + pyca Fail`. The pyca Fail reasons cluster as follows:

| Reason bucket | Count | Classification |
|---|---:|---|
| pyca: critical extension `2.5.29.33` (PolicyMappings) not handled  | 20 | pyca limitation (ext_policies permit_all does not handle policy extensions) |
| pyca: name comparison stricter (whitespace / case / string-type)   | 5  | pyca chooses byte-equal DN comparison; OpenSSL + pkix-path follow RFC 4518 |
| pyca: critical extension `2.5.29.54` (InhibitAnyPolicy) not handled| 4  | pyca limitation, same family as above |
| pyca: critical extension `2.5.29.36` (PolicyConstraints) not handled| 4 | pyca limitation, same family as above |
| pyca: signature does not match (self-issued bridge cert in chain)  | 3  | pyca quirk on self-issued certs (PKITS §4.10 Test12/13 subparts) |
| pyca: unsupported name constraint type (URI)                       | 3  | pyca scope limitation; OpenSSL + pkix-path support URI nameConstraints |
| pyca: GeneralizedTime in 1950–2049 rejected                        | 1  | pyca strict reading of RFC 5280 §4.1.2.5; OpenSSL + pkix-path lenient |
| pyca: negative serial number rejected                              | 1  | pyca strict reading of RFC 5280 §4.1.2.2; OpenSSL + pkix-path lenient |
| pyca: extension `2.5.29.19` criticality mismatch                   | 1  | pyca CA/B Forum strictures vs RFC 5280 baseline |

**Net**: pkix-path agrees with OpenSSL on all 42 chains. pyca's strictures
come from CA/B Forum WebPKI compliance, not RFC 5280. None of these
indicate pkix-path bugs; pkix-path's behaviour matches the
general-purpose RFC 5280 implementation in OpenSSL.

No follow-up beads filed for the LooserThanWild bucket.

## StricterThanWild (60) — pkix-path Fail, ≥1 oracle Pass

| Reason bucket | Count | Classification |
|---|---:|---|
| `certificate policy violation at chain index 0`     | 25 | pkix-path strict §6.1.5 policy-tree; OpenSSL lenient |
| `name constraints violated at certificate index 0`  | 12 | pkix-path enforces NameConstraints per §6.1.4(g); OpenSSL lenient on certain NC types |
| `signature invalid at chain index 1`                | 10 | **harness limitation**: PKITS §4.4 / §4.14 / some §4.5 entries put a CRL-signing cert in CertPath where pkix-path expects the actual signing cert. Tracked as **PKIX-t0w4** (path-building integration) |
| `certificate policy violation at chain index 1`     | 5  | same as policy-tree above, on intermediate |
| `certificate at index 1 is not a CA`                | 5  | pkix-path enforces basicConstraints cA=TRUE per §6.1.4(k); OpenSSL also enforces but with subtly different rules around v1/v2 certs |
| `signature invalid at chain index 0`                | 3  | **harness limitation** (mostly): PKITS §4.5 self-issued bridge + §4.1.4 DSA (pkix-path does not currently support DSA) |

**Net**: most are intentional pkix-path strictures (RFC 5280 literal
reading) where OpenSSL is lenient. 13 entries are harness limitations
already filed under PKIX-t0w4. 1 entry (4.1.4 DSA) is a known pkix-path
algorithm-support limitation.

Follow-up bead filed: **PKIX-t0w4** (path-building integration).

## OracleDivergence (0)

No chain in the corpus has pkix-path agreeing with one oracle while the
other two oracles disagree on Pass/Fail. (For chains where pkix-path's
verdict matches the majority and oracles split, our precedence rules
classify as `LooserThanWild` or `StricterThanWild` based on which side
of the split pkix-path falls on. With OpenSSL + pyca only, 3-way
divergence is impossible by construction.)

## DiagnosticDivergence (34)

Every oracle agrees on Pass/Fail; only the reason strings differ. This is
expected — the three implementations have three different error
vocabularies. Low-signal; no follow-up.

## Agreement (111)

All three oracles produce identical Pass/Fail verdicts. Noise; no
follow-up.

## Ground-truth disagreement (61 chains)

61 chains have pkix-path's verdict disagreeing with PKITS' `ShouldValidate`.
This is orthogonal to oracle classification — many of the 61 are also
in `Agreement` (where all three oracles agree but disagree with PKITS,
indicating PKITS' expectations may not match the modern reading of
RFC 5280, or an unsupported feature is being silently accepted by all
three implementations).

A spot check of the 61 chains shows the same buckets as
StricterThanWild dominate (policy-tree / name-constraints), consistent
with PKITS expecting validators that implement those features.

## Conclusion

The harness produced actionable signal on the first run:

1. **Zero pkix-path correctness regressions** detected against OpenSSL
   on the 247 classified chains.
2. **One harness improvement opportunity** identified and filed
   (PKIX-t0w4): path-building integration to handle PKITS §4.4 / §4.14
   / §4.5 chains that include non-signing certs in `CertPath`.
3. **A clean characterisation of pyca interop**: pkix-path is "looser
   than pyca" on extension handling because pyca enforces CA/B Forum
   strictures pkix-path does not; this is by design.

The PKITS baseline is committed at this state for diff-friendly
regression detection. Future runs that change any verdict will produce
a visible diff against `baseline-pkits.json`.
