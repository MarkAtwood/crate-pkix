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
  required SAN/EKU/algorithm/key-size strictures). **Revocation enabled
  when `Chain.crls` is non-empty (PKIX-emf1.2).**
* `openssl` invocation: `openssl verify -CAfile ROOT -untrusted INTER LEAF`,
  with `-CRLfile CRLS -crl_check_all` added when the chain carries CRLs
  (PKIX-emf1.3).
* `pyca` invocation: `PolicyBuilder::build_client_verifier()` with
  `ExtensionPolicy::permit_all()` for EE and `webpki_defaults_ca()` for CA
  (pyca's own invariant requires basicConstraints on CA policies).
  **RFC 5280 §6.3 baseline CRL handling** (PKIX-emf1.4): the sidecar
  hand-rolls a CRL check on top of PolicyBuilder, since `PolicyBuilder`
  in cryptography 48.0.0 exposes `store / time / extension_policies /
  max_chain_depth` and no revocation hook. The check parses each supplied
  CRL via `x509.load_der_x509_crl`, drops expired CRLs, matches issuer
  DN equality to each cert in the chain (leaf + intermediates), and looks
  up serials in `crl.get_revoked_certificate_by_serial_number`. No
  indirect/delta/scoped CRL handling; no CRL signature verification — the
  baseline is intentionally narrow so any divergence vs pkix-path's full
  RFC 5280 §6.3.3 implementation shows up as a classifier signal (Looser/
  Stricter or DiagnosticDivergence).

## Summary

| Class | Count | % |
|---|---:|---:|
| LooserThanWild       | 81  | 32.8% |
| StricterThanWild     | 46  | 18.6% |
| OracleDivergence     | 0   | 0.0%  |
| DiagnosticDivergence | 49  | 19.8% |
| Agreement            | 71  | 28.7% |
| **Total**            | **247** | |

Two PKITS chains are excluded from classification (harness errors):

* `4.1.5 Valid DSA Parameter Inheritance Test5` — pyca rejects the SPKI
  parameters as malformed ASN.1 (DSA inheritance encoding edge case).
  Affects only the pyca verdict; not a pkix-path divergence.
* `4.2.3 Valid pre2000 UTC notBefore Date Test3` — pkix-path's underlying
  `x509-cert` 0.2.5 rejects pre-2000 UTCTime encoding as malformed
  (RustCrypto/formats issue, separately tracked upstream).

## What changed in this revision (PKIX-t0w4)

The PKITS corpus loader now runs every `CertPath` bundle through
`pkix-path-builder::build_path` before handing the chain to the oracles
(`pkix-difftest/src/corpus/pkits.rs::try_build_chain`). PKITS §4.4 /
§4.14 / some §4.5 vectors advertise a CRL-signing cert inside `CertPath`
that is not part of the signature chain; `build_path` discards it via
AKI/SKI matching and yields the actual signature chain. When `build_path`
fails (parse error, no path found — typically negative-test bundles
deliberately violating cA=TRUE or DN chaining), the loader falls back to
the v1 root-first-reversed ordering so the chain is still classifiable.

Compared to the prior baseline (no path-building integration):

| Class | Pre-t0w4 | Post-t0w4 | Δ |
|---|---:|---:|---:|
| LooserThanWild       | 64  | 81  | +17 |
| StricterThanWild     | 77  | 60  | −17 |
| DiagnosticDivergence | 35  | 35  |  0  |
| Agreement            | 71  | 71  |  0  |

The 17 chains that flipped from `StricterThanWild` to `LooserThanWild`
are PKITS §4.4 / §4.14 / §4.5 bundles where pkix-path previously
reported `signature invalid at chain index N` because the positional
chain walker tried to verify a CRL-signing cert against the EE. Post-
t0w4 the rebuilt chain validates successfully under pkix-path **and**
OpenSSL, while pyca still rejects them due to its own (unrelated)
intermediate-selection heuristic. Net result: 0 remaining
`signature invalid at chain index N` entries in the StricterThanWild
bucket (the one survivor, `4.1.4 Valid DSA Signatures Test4`, is the
known pkix-path-does-not-support-DSA limitation).

## What changed in this revision (PKIX-emf1.4 pyca CRL)

The pyca sidecar gained a hand-rolled RFC 5280 §6.3 baseline CRL check
(`pkix-difftest/python/pyca_oracle.py::_crl_revocation_reason`). Prior
to this change, pyca was *not* a CRL oracle — `PolicyBuilder` does not
integrate CRL revocation, so when a PKITS chain shipped CRLs the pyca
verdict reflected path-validation only.

Compared to the pre-emf1.4 baseline (pyca path-only):

| Class | Pre-emf1.4 | Post-emf1.4 | Δ |
|---|---:|---:|---:|
| LooserThanWild       | 81  | 81  |  0  |
| StricterThanWild     | 60  | 46  | −14 |
| DiagnosticDivergence | 35  | 49  | +14 |
| Agreement            | 71  | 71  |  0  |

The 14 chains that flipped from `StricterThanWild` to
`DiagnosticDivergence` are all in §4.4 (CRL Verification), §4.14
(Distribution Points / onlySomeReasons), and §4.15 (Delta CRLs)
PKITS sections, and all are **Invalid** tests (`ShouldValidate=false`)
where the corpus expects the chain to be rejected because of a CRL
indicator. Pre-emf1.4: pkix-path rejected (revocation), pyca passed
(no CRL awareness), classifier saw 2-of-3 → `StricterThanWild`.
Post-emf1.4: all three oracles reject (each with their own reason
string), classifier sees 3-of-3 Fail → `DiagnosticDivergence`.

The flip is a real improvement in differential signal: fewer false-
positive `StricterThanWild` entries in the §4.4 / §4.14 / §4.15
revocation buckets, and pyca now serves as an independent CRL
oracle alongside OpenSSL. Specific testcases that flipped:

* §4.4: `4.4.2 Invalid Revoked CA Test2`, `4.4.3 Invalid Revoked EE
  Test3`, `4.4.8 Invalid Unknown CRL Entry Extension Test8`,
  `4.4.9 Invalid Unknown CRL Extension Test9`, `4.4.18 Invalid Long
  Serial Number Test18`.
* §4.14: `4.14.2 Invalid distributionPoint Test2`, `4.14.6 Invalid
  distributionPoint Test6`, `4.14.15`, `4.14.16`, `4.14.20`,
  `4.14.21` (`Invalid onlySomeReasons Test15/16/20/21`).
* §4.15: `4.15.4 Invalid delta-CRL Test4`, `4.15.6 Invalid delta-CRL
  Test6`, `4.15.9 Invalid delta-CRL Test9`.

Out of scope for the pyca baseline check (indirect/scoped CRLs,
CRL signature verification, IDP onlySomeReasons honoring) — these
remain pkix-path-only enforcement points. Future divergences in
those areas will surface as `StricterThanWild` per the existing
pattern.

## What changed in PKIX-emf1.7 (CRL revocation wiring)

Compared to the pre-PKIX-emf1.7 baseline (no revocation oracle wiring):

| Class | Pre-emf1 | Post-emf1 | Δ |
|---|---:|---:|---:|
| LooserThanWild       | 42  | 64  | +22 |
| StricterThanWild     | 60  | 77  | +17 |
| DiagnosticDivergence | 34  | 35  | +1  |
| Agreement            | 111 | 71  | −40 |

The shift is dominated by CRL-aware revocation flips:

* **−40 Agreement chains** moved out of "all three oracles agree on
  Pass" because at least one oracle now reports `Fail (revoked)` after
  consulting the CRL.
* **+22 LooserThanWild chains** are cases where pkix-path passes but a
  CRL-aware oracle (mainly OpenSSL) fails on CRL-coverage strictness:
  "unable to get certificate CRL" (10), "different CRL scope" (6),
  "CRL has expired" (2), "key usage does not include CRL signing" (2),
  and similar. pkix-path's per-CRL "soft skip" policy (oracles/pkix-path.rs
  module docs) is intentionally lenient on CRL applicability — when a CRL
  does not apply to a cert (scope, expiry, signer), pkix-path treats that
  as "no determination" and continues, while OpenSSL fails closed. That
  divergence is a documented design choice, not a pkix-path bug.
* **+17 StricterThanWild chains** are cases where pkix-path now flips to
  `Fail (revoked)` post-emf1.2, while at least one oracle still passes —
  almost entirely pyca, which has no CRL support. 8 of those 17 are the
  cleanest case: pkix-path **and** OpenSSL agree on `Fail (revoked)` and
  pyca alone passes (PKITS §4.4 / §4.13 revoked-EE / revoked-CA tests).

## LooserThanWild (81) — pkix-path Pass, ≥1 oracle Fail

Bucketed by the **failing** oracle and reason. pkix-path passing here is
either a deliberate design choice (soft CRL handling) or a permissive
default (no CA/B Forum strictures); both are documented.

| Failing oracle reason | Count | Classification |
|---|---:|---|
| pyca: critical extension `2.5.29.33` / `.36` / `.54` not handled         | 29 | pyca limitation (policy-tree extensions; ext_policies permit_all does not handle them) |
| openssl: `unable to get certificate CRL`                                  | 10 | **CRL coverage divergence** — pkix-path's soft per-cert policy lets a chain pass when no CRL covers a cert; OpenSSL's `-crl_check_all` fails closed. See "CRL coverage policy" below. |
| openssl: `different CRL scope`                                            | 6  | **CRL coverage divergence** — same family. OpenSSL rejects CRLs whose IDP scope flags exclude the cert (RFC 5280 §5.2.5). pkix-path treats as "no determination", continues. |
| pyca: candidates exhausted: all candidates exhausted (no chain found)     | 5  | pyca path-building difference (different intermediate selection heuristic). |
| pyca: candidates exhausted: signature does not match                      | 3  | pyca self-issued bridge cert quirk (PKITS §4.10 Test12/13 subparts). |
| pyca: candidates exhausted: unsupported name constraint (URI)             | 3  | pyca scope limitation; openssl + pkix-path support URI nameConstraints. |
| openssl: `CRL has expired`                                                | 2  | **CRL coverage divergence** — OpenSSL fails closed on expired CRLs; pkix-path's CrlChecker also fails on CrlExpired but the per-CRL soft policy in oracles/pkix-path.rs treats it as "this CRL has no determination, try next", and if no other CRL covers the cert, the cert passes. |
| openssl: `key usage does not include CRL signing`                         | 2  | **CRL coverage divergence** — OpenSSL fails closed when the CRL signer cert lacks cRLSign; pkix-path's CrlChecker returns CrlSignMissing, treated as soft skip. |
| openssl: `unhandled critical CRL extension`                               | 1  | OpenSSL strict on unknown critical CRL extensions; pkix-path's CrlChecker fails on that too, treated as soft skip. |
| openssl: `CRL signature failure`                                          | 1  | Same family — OpenSSL hard-fails; pkix-path soft-skips. |
| openssl: `certificate revoked`                                            | 1  | **Real divergence** — OpenSSL finds a cert in a CRL pkix-path's soft policy skipped (probably due to a CRL parse / signature / scope difference). Worth investigating; see PKIX-cqwt for CRL signer discovery work that may close this. |
| pyca: `GeneralizedTime in 1950–2049 rejected`                             | 1  | pyca strict reading of RFC 5280 §4.1.2.5; OpenSSL + pkix-path lenient. |

### CRL coverage policy

The biggest new bucket family is "openssl/pkix-path differ on CRL coverage
strictness", contributing 22 of the 64 LooserThanWild chains. The
divergence is by design:

* OpenSSL with `-crl_check_all` requires every cert in the chain to be
  covered by a CRL that parses, has a valid signature against the issuer,
  is within its validity window, and whose scope applies. If any cert
  lacks such a CRL, OpenSSL fails the chain.
* pkix-path's oracle wraps `pkix-revocation::CrlChecker` in a soft
  per-CRL loop (see `pkix-difftest/src/oracles/pkix_path.rs` module
  docs): each (cert, CRL) pair is checked, but a CRL that fails to apply
  is silently ignored and the chain continues. Only an actual
  `Err(Revoked)` flips the verdict.

The two are different policies, both defensible. pkix-path's choice is
documented; OpenSSL's choice is the historical default. The harness
exists to surface this divergence — not to declare one wrong.

No follow-up beads filed for this bucket beyond PKIX-cqwt (CRL signer
discovery, which addresses the 1 "certificate revoked" entry where
OpenSSL finds a CRL pkix-path could not match to a signer).

## StricterThanWild (60) — pkix-path Fail, ≥1 oracle Pass

| Reason bucket | Count | Classification |
|---|---:|---|
| `certificate policy violation at chain index 0`     | 25 | pkix-path strict §6.1.5 policy-tree; OpenSSL lenient |
| `pkix-path revocation: ... revoked by CRL` (various serials) | 17 | **Real revocation finding** — pkix-path agrees with OpenSSL on revocation outcome. The Stricter classification comes from pyca's no-CRL-support pass-through. 8 of these are clean "pkix-path + openssl Fail(revoked), pyca Pass" (PKITS §4.4 / §4.13). |
| `name constraints violated at certificate index 0`  | 12 | pkix-path enforces NameConstraints per §6.1.4(g); OpenSSL lenient on certain NC types |
| `certificate policy violation at chain index 1`     | 5  | same as policy-tree above, on intermediate |
| `certificate at index 1 is not a CA`                | 5  | pkix-path enforces basicConstraints cA=TRUE per §6.1.4(k); OpenSSL also enforces but with subtly different rules around v1/v2 certs |
| `signature invalid at chain index 0`                | 1  | PKITS §4.1.4 DSA (pkix-path does not currently support DSA — unrelated to path building) |

**Net**: 17 entries are real revocation findings (pkix-path and OpenSSL
agree, pyca lags due to no CRL support — PKIX-emf1.4). The remaining 43
follow the same pattern as before: pkix-path strict §6.1 enforcement vs
OpenSSL leniency. The previous baseline's 13 `signature invalid at chain
index N` entries (harness limitation tracked under PKIX-t0w4) are now
gone — the PKITS loader runs `CertPath` through `pkix-path-builder`
before classification, so the CRL-signing cert no longer poisons the
positional walk.

Follow-up beads: **PKIX-emf1.4** (pyca CRL strategy, surfaces the
no-revocation divergence visibly here).

## OracleDivergence (0)

No chain in the corpus has pkix-path agreeing with one oracle while the
other two oracles disagree on Pass/Fail. (For chains where pkix-path's
verdict matches the majority and oracles split, our precedence rules
classify as `LooserThanWild` or `StricterThanWild` based on which side
of the split pkix-path falls on. With OpenSSL + pyca only, 3-way
divergence is impossible by construction.)

## DiagnosticDivergence (35)

Every oracle agrees on Pass/Fail; only the reason strings differ. This is
expected — the three implementations have three different error
vocabularies. Low-signal; no follow-up.

## Agreement (71)

All three oracles produce identical Pass/Fail verdicts. The 40-chain
drop versus the prior baseline reflects the CRL revocation findings
that previously did not exist as divergences (all three oracles passed
silently when no CRL was consulted). Now CRL-aware oracles surface the
revoked status, breaking the prior "Agreement(Pass)" alignment on
revoked chains.

## Ground-truth disagreement

PKITS ground truth (`ShouldValidate` per vector) versus pkix-path's
verdict. The harness reports per-class agreement; spot-check the JSON
for the per-chain detail. Many of the 17 newly-Failed (revoked)
chains move from "Agreement(Pass) disagreeing with PKITS expected
Fail" to "Agreement(Fail) matching PKITS expected Fail", which is the
desired direction. Net ground-truth agreement should improve under
this baseline; the exact delta is left to a future analysis pass once
PKIX-emf1.4 resolves the pyca side.

## Conclusion

The PKIX-emf1 revocation wiring + PKIX-t0w4 path-building integration
produced clear new signal:

1. **17 PKITS revocation chains** correctly flip to `Fail (revoked)`
   under both pkix-path and openssl, matching PKITS' expected
   ShouldValidate=false.
2. **CRL coverage policy divergence between pkix-path and openssl** is
   visible as a documented design difference (22 LooserThanWild
   chains).
3. **Pyca's lack of CRL support** is visible as 8+ Stricter chains
   where the two CRL-aware oracles agree on revoked and pyca lags;
   PKIX-emf1.4 documents the maintainer-bound strategy decision.
4. **PKITS §4.4 / §4.14 / §4.5 path-building harness limitation
   eliminated** — 13 `signature invalid at chain index N` Stricter
   chains are gone; pkix-path now validates the rebuilt chains
   alongside OpenSSL.

No new pkix-path correctness regressions detected. The harness output is
committed as the canonical baseline for diff-friendly regression
detection on future runs.
