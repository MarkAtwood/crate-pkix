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
  `pyca/cryptography` 50.0.2.

  **pyca moved 48.0.0 → 50.0.2 at this regeneration and that is most of the
  drift below.** 50.x rejects 20 chains that 48.x passed, chiefly on
  unaccounted-for critical extensions. The job installs whatever
  `setup-venv.sh` resolves rather than a pinned version, so this will happen
  again; pinning it is tracked separately.
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

| Class | Count | % | previous |
|---|---:|---:|---:|
| LooserThanWild       | 63  | 25.5% | 62 |
| StricterThanWild     | 56  | 22.7% | 57 |
| OracleDivergence     | 0   | 0.0%  | 0  |
| DiagnosticDivergence | 67  | 27.1% | 67 |
| Agreement            | 61  | 24.7% | 61 |
| **Total**            | **247** | | 247 |

Ground-truth disagreements: **46 → 35 → 17 → 15 → 2 → 1** across five
regenerations. The last step was the delta-CRL fix: PKITS §4.15.5 was
reported as revoked because `pkix-difftest`'s oracle consulted a base CRL
its delta superseded, which made `removeFromCRL` unreachable. The
disagreement was the harness's, not `pkix-revocation`'s.

The last step closed the `onlySomeReasons` gap: `pkix-revocation` now
combines reason-partitioned CRLs per RFC 5280 §6.3.3, so 4.14.18 and 4.14.19
agree with NIST while 4.14.17 — whose two partitions cover only four of eight
reasons — still correctly fails.

### Second regeneration: CRL selection and signer discovery

Eighteen further ground-truth fixes, no regressions. Three changes, and the
order matters:

1. **Distribution-point filtering.** The oracle considers only CRLs the
   certificate points at, via `pkix_revocation::crl_applies_to`
   (RFC 5280 §6.3.3(b)). Measured alone this is a perfect no-op — every CRL
   that previously produced a verdict was already applicable — so it removes
   nothing and constrains what follows.

2. **Signer discovery, gated by that filter.** Among applicable CRLs,
   `new_with_signer_discovery` finds which certificate actually signed each
   one: the key-rollover and separate-CRL-key case, where a CA signs its CRL
   with one certificate while having issued the subject from another.

   Three earlier attempts added discovery or `cRLIssuer` candidates *without*
   the filter and all three were worse — 35 (an 18-for-18 trade), 44, and 46
   disagreements. Discovery answers "who signed this CRL", never "is this the
   right CRL", so unfiltered it authenticates CRLs a certificate never
   pointed at.

3. **Dropped signers restored, revoked ones excluded.** Path building drops
   certificates that are not links in the chain, including the CA's dedicated
   CRL-signing certificate in several §4.4, §4.5 and §4.14 vectors.
   `Chain::aux_certs_der` carries them to discovery.

   That broke one negative test, 4.4.21, and the reason is worth keeping:
   it is structurally identical to 4.4.19 beside it, and NIST fails it only
   because the CRL signer's certificate (serial 68) is revoked by
   `TrustAnchorRootCRL`, where 4.4.19's (serial 66) is not.
   `new_with_signer_discovery` enforces `cRLSign` and requires the signer to
   chain to a self-signed certificate, but cannot ask whether the signer is
   still valid. `drop_revoked` removes revoked candidates before discovery
   sees them.

`LooserThanWild` rises 43 → 60 as a *consequence* of the fixes: a chain the
oracle stopped wrongly rejecting, which pyca still rejects, moves
`StricterThanWild` → `LooserThanWild`. Verified that no chain entered
`LooserThanWild` without being a ground-truth fix.

### What moved, and why

Changes to the `pkix-path` oracle adapter, plus one oracle upgrade:

1. **The adapter no longer fails open on undetermined revocation.** It used to
   treat every outcome except `Revoked` as "no negative determination", which
   reported a clean bill of health when *no* CRL applied to a certificate at
   all. It now fails when nothing could be applied, matching
   `pkix_chain::verify_chain`, which propagates every revocation error and has
   no soft-fail mode.

   This surfaced after `pkix-revocation` began correctly refusing CRLs with
   unrecognized critical extensions (RFC 5280 §5.2/§5.3). Those CRLs had been
   applied and reported `Revoked`; once refused, the fail-open let three
   chains NIST classes **invalid** pass — 4.4.8, 4.4.9 and 4.15.4.

2. **Delta CRLs are paired with their bases.** The adapter built one checker
   per CRL and never called `CrlChecker::with_delta`, so a delta was always
   refused as `DeltaCrlAsComplete` and a certificate revoked *only* in a delta
   was never seen as revoked. That is 4.15.4 exactly: serial 3,
   `KeyCompromise`, listed only in `deltaCRLCA1deltaCRL`.

   Worth recording: the **previous baseline had 4.15.4 failing for the wrong
   reason.** Before the standalone-delta check existed, the delta was accepted
   as a complete CRL and found the revocation — the precise behaviour that
   commit closed as a vulnerability. A baseline can encode a vulnerability as
   an expectation.

3. **pyca 48.0.0 → 50.0.2**.

### What still disagrees

Two chains, both predating this work and catalogued per bucket below.

### Reading this baseline

The LooserThanWild and StricterThanWild breakdowns are derived from
`baseline-pkits.json`, so their counts match the baseline by
construction. Sections headed "What changed in revision X" are history:
their numbers are the comparison that was true at that revision and are
deliberately not updated. The authoritative current totals are the
summary table above and the JSON, which the CI gate compares.

`ground_truth_disagreements` is compared by **chain name**, not just by count,
so a newly-disagreeing chain shows up as a diff even if the totals happen to
match. The 1 recorded here (4.1.4 Valid DSA Signatures Test4)
is expected; a 2nd is a regression.

Two PKITS chains are excluded from classification (harness errors):

* `4.1.5 Valid DSA Parameter Inheritance Test5` — pyca rejects the SPKI
  parameters as malformed ASN.1 (DSA inheritance encoding edge case).
  Affects only the pyca verdict; not a pkix-path divergence.
* `4.2.3 Valid pre2000 UTC notBefore Date Test3` — the certificate's
  `notBefore` is 1950, and `der` 0.8 supports `UTCTime` only for
  1970-2049 ("due to common operations working on `UNIX_EPOCH`"), where
  RFC 5280 §4.1.2.5.1 allows 1950-2049. So it fails in the DER layer and
  never reaches validation. Fail-closed, deliberate upstream, and not
  fixable without forking the dependency; see `pkix-path`'s Limitations
  section. Earlier revisions of this file blamed "x509-cert 0.2.5" and
  "pre-2000 UTCTime", both wrong: the floor is the epoch, not the
  millennium, and the restriction is `der`'s.

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
remain pkix-path-only enforcement points.

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
  and similar — pkix-path's per-CRL "soft skip" policy
  (oracles/pkix-path.rs module docs) against OpenSSL failing closed.
* **+17 StricterThanWild chains** are cases where pkix-path now flips to
  `Fail (revoked)` post-emf1.2, while at least one oracle still passes —
  almost entirely pyca, which has no CRL support. 8 of those 17 are the
  cleanest case: pkix-path **and** OpenSSL agree on `Fail (revoked)` and
  pyca alone passes (PKITS §4.4 / §4.13 revoked-EE / revoked-CA tests).

## LooserThanWild — pkix-path Pass, ≥1 oracle Fail

Bucketed by the **failing** oracle and reason. pkix-path passing here is
either a deliberate design choice (soft CRL handling) or a permissive
default (no CA/B Forum strictures); both are documented.

| Reason | Count | Classification |
|---|---:|---|
| pyca: `invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions` | 20 | pyca limitation — policyMappings; its `permit_all` ext_policies does not handle the policy-tree extensions. |
| pyca: `fatal error: critical nameConstraints extension contains an unsupported directoryName co…` | 9 | pyca limitation — refuses a critical nameConstraints it cannot fully process; OpenSSL and pkix-path process these. |
| openssl: `unable to get certificate CRL` | 8 | **CRL coverage divergence** — pkix-path's soft per-cert policy passes a chain when no CRL covers a cert; OpenSSL's `-crl_check_all` fails closed. See "CRL coverage policy" below. |
| pyca: `all candidates exhausted with no interior errors` | 5 | pyca path-building difference — a different intermediate-selection heuristic. |
| pyca: `invalid extension: 2.5.29.54: certificate contains unaccounted-for critical extensions` | 4 | pyca limitation — inhibitAnyPolicy, same family. |
| openssl: `different CRL scope` | 4 | **CRL coverage divergence** — OpenSSL rejects a CRL whose IDP scope excludes the cert (§5.2.5); pkix-path treats that as no determination. |
| pyca: `invalid extension: 2.5.29.36: certificate contains unaccounted-for critical extensions` | 4 | pyca limitation — policyConstraints, same family. |
| pyca: `signature does not match` | 3 | pyca self-issued bridge-cert quirk (PKITS §4.10 Test12/13 subparts). |
| pyca: `unsupported name constraint` | 2 | pyca scope limitation; OpenSSL and pkix-path support URI nameConstraints. |
| pyca: `certificate <serial> revoked by CRL` (0x4, 0x6) | 2 | **pyca finds a revocation pkix-path does not.** pyca gained its own CRL check in PKIX-emf1.4, so these deserve a look rather than an assumption. |
| pyca: `validity dates between 1950 and 2049 must be UtcTime (encountered processing <Certificat…` | 1 | pyca strict reading of §4.1.2.5; OpenSSL and pkix-path lenient. |
| pyca: `invalid extension: 2.5.29.19: Certificate extension has incorrect criticality` | 1 | pyca limitation — a basicConstraints encoding it refuses. |

Derived from `baseline-pkits.json` rather than hand-classified, so the
counts cannot drift from the baseline they describe. Reasons are
normalised — serial numbers and checker counts collapsed — so rows
group by cause rather than by string.

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

## StricterThanWild — pkix-path Fail, ≥1 oracle Pass

| Reason | Count | Classification |
|---|---:|---|
| pkix-path: `certificate policy violation at chain index 0` | 25 | pkix-path strict §6.1.5 policy-tree enforcement; OpenSSL lenient. |
| pkix-path: `revocation status of cert at chain index 0 is undetermined — no checker covered it` | 22 | **CRL coverage, the other direction** — pkix-path will not vouch for a cert no CRL covered, where an oracle passes it. The mirror of the `unable to get certificate CRL` bucket in LooserThanWild. |
| pkix-path: `certificate policy violation at chain index 1` | 5 | Same, on the intermediate. |
| pkix-path: `cert at chain index 0 revoked by CRL: certificate <serial> is revoked (reason keyComprom…` | 3 | **Real revocation finding** — pkix-path agrees with OpenSSL; the Stricter label comes from the third oracle passing the chain. |
| pkix-path: `signature not verified at chain index 0: unsupported signature algorithm` | 1 | PKITS §4.1.4 DSA. pkix-path ships no DSA backend, and this is the corpus's one remaining ground-truth disagreement. |

Derived from `baseline-pkits.json` rather than hand-classified, so the
counts cannot drift from the baseline they describe. Reasons are
normalised — serial numbers and checker counts collapsed — so rows
group by cause rather than by string.

**Net**: 30 of the 56 are pkix-path's strict §6.1.5 policy-tree
enforcement against OpenSSL's leniency, which is the deliberate stance.
22 are the CRL-coverage question in its fail-closed direction, the mirror
of the LooserThanWild bucket above — the same policy produces entries on
both sides depending on which oracle holds a CRL. 3 are real revocation
findings where pkix-path and OpenSSL agree. The last is DSA, and it is
the corpus's one remaining ground-truth disagreement.

Earlier revisions of this paragraph counted 17 revocation findings and 43
strict-enforcement entries, from a baseline two regenerations back.

Follow-up beads: **PKIX-emf1.4** (pyca CRL strategy, surfaces the
no-revocation divergence visibly here).

## OracleDivergence (0)

No chain in the corpus has pkix-path agreeing with one oracle while the
other two oracles disagree on Pass/Fail. (For chains where pkix-path's
verdict matches the majority and oracles split, our precedence rules
classify as `LooserThanWild` or `StricterThanWild` based on which side
of the split pkix-path falls on. With OpenSSL + pyca only, 3-way
divergence is impossible by construction.)

## DiagnosticDivergence

Every oracle agrees on Pass/Fail; only the reason strings differ. This is
expected — the three implementations have three different error
vocabularies. Low-signal; no follow-up.

## Agreement

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

## Net pkix-path correctness regressions

None. The PKIX-emf1 revocation wiring and the PKIX-t0w4 path-building
integration added signal, not regressions — every divergence they
surfaced is accounted for per bucket above. The harness output is
committed as the canonical baseline for diff-friendly regression
detection on future runs.
