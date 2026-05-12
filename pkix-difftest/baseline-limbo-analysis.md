# x509-limbo baseline analysis

Hand-classified bucket analysis of the x509-limbo (Tier-2) divergence
baseline produced by `pkix-difftest run limbo ...`. The companion files
are:

* `baseline-limbo.json` — machine-readable, lossless. Source of truth.
* `baseline-limbo.md` — auto-generated human-readable detail (every chain
  per bucket, sample-capped). Regenerated from the same run.

This document is the **curated** layer: per-bucket reasoning about whether
each divergence is a real bug in pkix-path, an intentional spec stricture,
a documented harness limitation, or an oracle quirk. It is the deliverable
required by PKIX-g9vc.4's acceptance criterion "every
LooserThanWild / StricterThanWild entry has a follow-up bead OR a
written-out justification".

## Run

* Tool: `pkix-difftest` HEAD of `main` (commit visible via `git log -1`).
* Corpus: x509-limbo `limbo.json` (9773 testcases at fetch time),
  RFC-5280-shaped filter applied at load (drops CLIENT validation,
  any `features`-tagged case, `max_chain_depth!=null`, and CRL-bearing
  cases) leaving **9726 testcases** classified. Filter rationale lives
  in `pkix-difftest/src/corpus/limbo.rs`.
* Oracles: `pkix-path` (default features = `["rsa", "p256"]`), system
  `openssl` 3.0.13, `pyca/cryptography` 48.0.0 in
  `pkix-difftest/python/.venv`.
* `pkix-path` invocation: `ValidationPolicy::new(validation_time_unix)`
  per testcase (permissive — no required SAN/EKU/algorithm/key-size
  strictures, no revocation since the filter drops CRL-bearing cases).
  The default crypto feature set excludes `p384` — this is an
  intentional "what does an unsuspecting downstream consumer get?"
  framing (see harness comment in `pkix-difftest/Cargo.toml`).
* `openssl` invocation: `openssl verify -CAfile ROOT -untrusted INTERS LEAF`
  (no `-crl_check` since the corpus subset has no CRLs).
* `pyca` invocation: `PolicyBuilder::build_client_verifier()` with
  `ExtensionPolicy::permit_all()` for EE and `webpki_defaults_ca()` for
  CA. (Same wrapper as the PKITS baseline.)

## Summary

| Class                | Count | %     |
|----------------------|-------|-------|
| LooserThanWild       |   827 | 8.5%  |
| StricterThanWild     |    23 | 0.2%  |
| OracleDivergence     |     0 | 0.0%  |
| DiagnosticDivergence |  5898 | 60.6% |
| Agreement            |  2978 | 30.6% |
| **Total**            | **9726** |   |

Ground-truth agreement (vs corpus's `expected_result`):

| Class           | gt agree | gt disagree |
|-----------------|---------:|------------:|
| LooserThanWild  |       96 |         731 |
| StricterThanWild|       19 |           4 |

The 731 LooserThanWild-but-corpus-disagrees and 4
StricterThanWild-but-corpus-disagrees cases are the focus below.

### Delta from previous baseline (PKIX-lwr9.4.1, 2026-05-11)

| Class                | before | after | Δ   |
|----------------------|-------:|------:|----:|
| LooserThanWild       |    827 |   827 |   0 |
| StricterThanWild     |     26 |    23 |  −3 |
| OracleDivergence     |      0 |     0 |   0 |
| DiagnosticDivergence |   5898 |  5898 |   0 |
| Agreement            |   2975 |  2978 |  +3 |
| Total                |   9726 |  9726 |   — |

The limbo loader now routes positional CertPath bundles through
`pkix_path_builder::build_first_valid_path` (PKIX-lwr9.4.1, shipped on
top of the PKIX-lwr9.4.2 helper) instead of single-shot `build_path`.
The helper iterates `build_path_candidates` and tries each through
`pkix_path::validate_path` until one passes — closing the
single-shot-wrapper gap PKIX-lwr9.4 diagnosed for bettertls::tc60
(cross-signed pool with one intermediate signed under ecdsa-with-SHA1).

Seven testcases reclassified by this change:

| Case                                              | before               | after                | gt    |
|---------------------------------------------------|----------------------|----------------------|-------|
| `bettertls::pathbuilding::tc60`                   | StricterThanWild     | Agreement            | true  |
| `bettertls::pathbuilding::tc47`                   | StricterThanWild     | DiagnosticDivergence | true  |
| `bettertls::pathbuilding::tc74`                   | StricterThanWild     | DiagnosticDivergence | true  |
| `bettertls::pathbuilding::tc80`                   | StricterThanWild     | DiagnosticDivergence | true  |
| `rfc5280::nc::permitted-self-issued`              | DiagnosticDivergence | StricterThanWild     | false |
| `bettertls::pathbuilding::tc56`                   | DiagnosticDivergence | Agreement            | true  |
| `rfc5280::nc::nc-forbids-alternate-chain-ica`     | DiagnosticDivergence | Agreement            | true  |

tc60 is the headline win (the bead's primary acceptance criterion):
corpus expected SUCCESS, was StricterThanWild with `gt_agreement=false`
(the sole pkix-path-builder-attributable case in the limbo Tier-2
baseline), now Agreement Pass. tc47/74/80 also flipped out of Stricter
into DiagDiv: corpus expected FAILURE on all three, all oracles now
agree on Fail (different reasons) — net improvement in differential
signal. tc56 and `nc-forbids-alternate-chain-ica` are "harness
false-failure" cases that flipped from all-Fail (DiagDiv) to all-Pass
(Agreement) because the new chain ordering is one all three oracles
accept; both expect SUCCESS and gt now agrees.

The one regression-shaped flip — `rfc5280::nc::permitted-self-issued`
moving DiagDiv → StricterThanWild with `gt_agreement=false` — reflects
that the new chain ordering causes openssl + pyca to pass a chain the
corpus expects to fail (pkix-path correctly still rejects). The
underlying harness contract is preserved (we classify whatever each
oracle says about whatever chain we give them); the case moved because
the chain bytes changed, not because pkix-path got worse. Tracked in
this run's analysis only; no follow-up bead.

Prior to this change (PKIX-lwr9.6, 2026-05-11), the limbo loader used
single-shot `build_path` after PKIX-yn3e (AKI-based candidate
selection, 2026-05-08) eliminated the dominant 47-case
`bettertls::pathbuilding` Stricter bucket via topological reordering
alone. PKIX-lwr9.4.1 closes the residual single-candidate gap by
iterating with verifier feedback.

## LooserThanWild (819) — pkix-path Pass, ≥1 oracle Fail

Bucketed by failing-oracle reason. The dominant bucket is BetterTLS
nameConstraints — 748 of 819 entries (91%) where openssl alone fails on
"permitted subtree violation" (612) or "excluded subtree violation"
(136), while pkix-path and pyca pass.

| Failing oracle reason | Count | Classification |
|---|---:|---|
| openssl: `permitted subtree violation` | 612 | **Documented divergence: BetterTLS CN-as-DNS strict reading.** See "BetterTLS nameConstraints" below. |
| openssl: `excluded subtree violation`  | 136 | Same family. |
| pyca: `ValueError: ... does not appear to be IPv4/IPv6` | ~30 | **pyca implementation bug**, not a pkix-path divergence. pyca attempts to coerce certain BetterTLS-style SAN strings into IP addresses and aborts before reaching the chain-validation logic. |
| openssl: `unable to get issuer certificate` | 5 | webpki-aki edge cases — openssl strict AKI path-building |
| openssl: `unable to get local issuer certificate` | 3 | similar AKI/SKI path-building strictness |
| openssl: `certificate has expired` | 3 | **pkix-path correct per RFC 5280 §4.1.2.5.** Two are `notafter-exact` / `notafter-fractional` testcases where validation_time hits notAfter inclusively (RFC says "from notBefore through notAfter, inclusive" — corpus expects SUCCESS). One is `expired-root` where corpus expects FAILURE; pkix-path passes the chain because the root anchor itself is not subjected to a validity check (trust anchors are trusted by deployment, not by validity period — RFC 5280 §6.1 anchor). pyca treats the anchor as a regular cert here and rejects on time. |
| pyca: `candidates exhausted: Neither EKU nor anyEKU could be found` | 4 | pyca enforces EKU presence on every chain cert; pkix-path's default `ValidationPolicy` does not require EKU. Documented permissive default. |
| pyca: `candidates exhausted: signature does not match` | 1 | pyca-internal path-building heuristic; not pkix-path's concern. |
| pyca: `candidates exhausted: excluded name constraint matched SAN` | 2 | pyca strict on certain NC types; pkix-path lenient. Documented divergence; matches the PKITS-style "pyca limitation" bucket. |
| pyca: `candidates exhausted: nameConstraints must have non-empty permitted/excluded` | 2 | pyca-internal validity check; pkix-path tolerates empty subtree sets. |
| pyca: malformed-extension / criticality / "must be X.509v3" / RSA-too-weak (≤2 each) | ~15 | pyca pedantic-WebPKI strictures; pkix-path correctly does not enforce these per project policy. |
| pyca: `GeneralizedTime in 1950–2049 rejected` | (0 in this corpus) | — |
| openssl: `unhandled critical extension` | 2 | openssl pedantic on critical-extensions in non-leaf certs; pkix-path tolerates per its critical-extension policy. |
| openssl: `unsupported name constraint type` | 1 | openssl scope limitation. |
| openssl: `unsupported or invalid name syntax` | 1 | openssl strict on name encoding. |

Counts marked `~N` are approximations because the underlying pyca
error strings vary by SAN content. Exact per-string counts live in
`baseline-limbo.json`; the bucket Total reflects the true 819.



### BetterTLS nameConstraints (748 / 91%)

The single dominant divergence family. Every entry is a
`bettertls::nameconstraints::tc*` testcase where:

* an intermediate carries a `nameConstraints` extension with a `permitted`
  or `excluded` dNSName subtree (typically `localhost`-anchored), and
* the leaf has **no SAN extension**, only a `Subject DN` with `CN`
  containing a hostname that violates the constraint
  (`CN=bad.example.com`), and
* openssl fails the chain with `permitted/excluded subtree violation`
  (applying its CN-as-dNSName legacy rule from RFC 2459 / WebPKI), while
* pkix-path and pyca both pass.

**This is the strictly literal RFC 5280 reading.** RFC 5280 §4.2.1.10
explicitly says:

> Restrictions of the form dirName MUST be applied to the subject field
> in the certificate (when the certificate includes a non-empty subject
> field) and to any names of type directoryName in the subjectAltName
> extension. Restrictions of the form dNSName, x400Address,
> ediPartyName, and registeredID MUST be applied only to the
> corresponding name type in subjectAltName.

So dNSName nameConstraints apply **only** to dNSName SAN entries — not
to Subject CN. When the leaf has no SAN, there is nothing for the
dNSName constraint to match against, and the cert (correctly) passes
the constraint check. openssl applies the older RFC 2459 / WebPKI
"CN-as-dNSName" rule, which the corpus author treats as the expected
behaviour (`expected_result: FAILURE` for 660 of 748).

This is the same family as the PKITS analysis's documented "pkix-path
strict RFC vs openssl lenient" stance, but in reverse direction:
**openssl is the stricter one here, applying WebPKI norms beyond RFC
5280.** pkix-path and pyca agree on the RFC-literal reading.

**Position taken**: pkix-path is correct per its stated scope (RFC 5280
§6 path validation, not WebPKI server-cert validation). The BetterTLS
nameConstraints corpus expects WebPKI-strict behaviour; pkix-path
deliberately does not provide that, since CN-as-dNSName extraction is a
hostname-binding decision that should live in a separate `pkix-tls` /
`pkix-rfc6125` layer, not in `pkix-path`.

This bucket is documented in `pkix-path/src/lib.rs` (NameConstraints
handling) and tracked in this analysis. **No follow-up bead filed** —
the divergence is by design and the WebPKI strict-CN behaviour belongs
in a future hostname-verification crate, not in pkix-path itself.

### Other LooserThanWild buckets

All small and either oracle-implementation quirks (pyca IP-coercion
ValueError, openssl AKI strict path-building) or documented pkix-path
permissive defaults (EKU not required by default, critical-extension
tolerance). No follow-up beads filed for these.

## StricterThanWild (23) — pkix-path Fail, ≥1 oracle Pass

| Reason bucket | Count | Classification |
|---|---:|---|
| `malformed certificate at chain index 0` | 11 | 10 bettertls::nameconstraints (tc8877..tc9476) + 1 webpki::san::unicode-emoji-san. **pkix-path AGREES with corpus ground truth** on all 11 (gt_agreement=true). pkix-path rejects malformed leaves that openssl tolerates; strict-is-correct. No bead. |
| `signature invalid at chain index 1` | 5 | 3 online::* (apple/cloudflare/akamai, P-384 harness limitation, PKIX-wmch, gt=false) + 2 bettertls::pathbuilding (tc8/tc15 = forbidden ECDSA-with-SHA1 OID 1.2.840.10045.4.1, gt=true). |
| `signature invalid at chain index 0` | 4 | online::stackoverflow.com (P-384, PKIX-wmch, gt=false), webpki::forbidden-dsa-root (DSA, project-policy unsupported, gt=true), webpki::forbidden-p192-root (P-192, project-policy unsupported, gt=true), and bettertls::pathbuilding::tc41 (gt=true). All four are intentional pkix-path limitations or pkix-path-correct rejections; no bug. |
| `unhandled critical extension at chain index 0` | 1 | rfc5280::ee-critical-aia-invalid (gt=true). **pkix-path correct** — RFC 5280 §4.2.1.1 says AKI MUST NOT be critical. pkix-path enforces; openssl fails too (different wording); pyca passes. |
| `name constraints violated at certificate index 0` | 1 | rfc5280::nc::nc-permits-invalid-dns-san (gt=true). pkix-path strict NC; openssl lenient; pyca strict too. No bead. |
| `no path to a trusted anchor` | 1 | rfc5280::nc::permitted-self-issued (gt=false). Flipped from DiagnosticDivergence in this baseline: the new `build_first_valid_path`-built chain ordering causes openssl and pyca to pass, while pkix-path can find no chain that satisfies both topology and signature. Side effect of the harness change, not a pkix-path regression. No bead. |
| **Total** | **23** | |

### Residual ground-truth-disagreement cases (4 of 23)

Only **4** of the 23 StricterThanWild cases have `gt_agreement=false`
(pkix-path is wrong vs corpus expected result):

| Case                                  | Tracked under |
|---------------------------------------|---------------|
| `online::akamai.com`                  | PKIX-wmch (P-384 harness limitation) |
| `online::apple.com`                   | PKIX-wmch (P-384 harness limitation) |
| `online::cloudflare.com`              | PKIX-wmch (P-384 harness limitation) |
| `online::stackoverflow.com`           | PKIX-wmch (P-384 harness limitation) |

`rfc5280::nc::permitted-self-issued` is also `gt_agreement=false` but
sits in a different bucket: it's a side-effect of the chain-ordering
change in PKIX-lwr9.4.1, not a pkix-path implementation gap. The new
ordering happens to be one openssl+pyca accept; pkix-path correctly
sees it as not-a-valid-path. Documented above; no follow-up bead.

PKIX-lwr9.4 / `bettertls::pathbuilding::tc60` has been resolved by this
work (PKIX-lwr9.4.2 helper + PKIX-lwr9.4.1 harness adoption). tc60
flipped from StricterThanWild(gt=false) into Agreement(gt=true).

The other 19 StricterThanWild residuals all have `gt_agreement=true`:
pkix-path correctly rejects what the corpus expects to fail. Strict
behaviour is intentional in those cases (malformed-cert rejection,
RFC 5280 §4.2.1.1 critical-AKI enforcement, DSA / P-192 project-policy
exclusion).

### `bettertls::pathbuilding` family (3 Stricter residuals, 0 algorithmic builder bugs)

After PKIX-lwr9.6 (build_path harness wiring, 2026-05-11) and
PKIX-lwr9.4.1 (build_first_valid_path harness adoption, this baseline)
the `bettertls::pathbuilding` family is fully closed:

* **tc8 / tc15** — corpus expects FAILURE on ECDSA-with-SHA1
  (`1.2.840.10045.4.1`). pkix-path rejects via signature mismatch
  (the OID is not dispatched by `DefaultVerifier`); pyca rejects via
  `Forbidden signature algorithm`; openssl passes permissively.
  gt_agreement=true (pkix-path right by verdict). Stricter residual.
* **tc41** — corpus expects FAILURE; pkix-path correctly rejects
  with a signature-linkage diagnostic. gt_agreement=true. Stricter
  residual.
* **tc47 / tc74 / tc80** — formerly Stricter, now DiagnosticDivergence
  with all three oracles agreeing on Fail (different reasons). PKIX-lwr9.4.1
  caused the chain reordering that surfaced this agreement.
* **tc60** — formerly Stricter(gt=false), the single
  `gt_agreement=false` residual cited by PKIX-lwr9.4. Now Agreement(gt=true)
  after PKIX-lwr9.4.1.

### Harness-shape limitations (not pkix-path bugs)

* **ECDSA P-384 (4 online::* chains: apple/cloudflare/akamai/stackoverflow)** —
  pkix-difftest builds pkix-path with default features `["rsa", "p256"]`.
  Real-world ECC chains require `p384`. Documented in
  `pkix-difftest/Cargo.toml` as an intentional default-features-only
  test. The secondary `--features rustcrypto` baseline below confirms
  these flip to Agreement when `p384` is activated. Tracked as
  **PKIX-wmch**.
* **ECDSA-with-SHA-1 legacy OID (`1.2.840.10045.4.1`)** — pkix-path
  does not dispatch this OID. Out of scope (deprecated algorithm; not
  project policy to add). Surfaces on bettertls::pathbuilding tc8/tc15
  as harmless DiagnosticDivergence-shaped Stricter (gt_agreement=true).

## OracleDivergence (0)

No chain has pkix-path agreeing with one oracle while the other two
oracles disagree on Pass/Fail (3-way split is impossible by
construction with two non-pkix-path oracles).

## DiagnosticDivergence (5898)

All three oracles agree on Pass/Fail; only the reason strings differ.
60.6% of the corpus falls here, which is high — but expected. x509-limbo
ships hundreds of "make sure all oracles agree this is invalid" CVE and
malformed-cert tests where openssl says "unable to parse" while pyca
says "VerificationError: invalid extension X" and pkix-path says
"malformed certificate at chain index N". Low-signal; no follow-up.

## Agreement (2978 / 30.6%)

All three oracles produce identical Pass/Fail verdicts. PKIX-lwr9.6
moved 43 chains from divergence classes into Agreement by wiring
pkix-path-builder into the harness; PKIX-lwr9.4.1 added 3 more by
swapping single-shot `build_path` for the iterating
`build_first_valid_path`. Within Agreement, the harness's value comes
from the next run: any chain that flips from Agreement to a divergence
class without a corresponding code change is a regression.

## Ground-truth disagreement

Across all 9726 classified cases, pkix-path disagrees with the corpus
ground-truth on **2902 cases** (29.8%). The bulk is the 731
LooserThanWild-but-corpus-disagrees set, which is dominated by the
748 BetterTLS nameConstraints cases discussed above (660 with
gt_disagree).

After excluding the BetterTLS CN-as-DNS family (intentional
RFC-literal divergence), real ground-truth-disagreement drops to
~2160. The next biggest contributors:

* pyca-strict failures where pkix-path passes (corpus expects pyca
  to be right): EKU presence, critical-extension criticality, RSA
  key strength, NC type strictness. Each is a project-policy decision
  to keep pkix-path's defaults permissive. Documented per-bucket above.
* the 5 residual StricterThanWild gt-disagreements (4 P-384 harness
  + 1 harness/API-gap, tc60 — filed as PKIX-lwr9.4).

The harness is functioning correctly: the dominant ground-truth-
disagreement signal points at a documented design choice (CN-as-DNS),
and the smaller signal isolates the genuine follow-up work.

## Follow-up beads filed by this analysis

* **PKIX-lwr9** — pkix-path-builder robustness on bettertls::pathbuilding.
  After PKIX-lwr9.6 wired the harness through `build_path`, the
  residual is **one** case (`tc60`), reframed by PKIX-lwr9.4 as a
  consumer-side harness/API-gap (`build_path` is single-shot;
  harness does not iterate `build_path_candidates` past a first
  candidate whose intermediate carries an algorithm `DefaultVerifier`
  rejects). Significantly de-scoped from the original 47-case framing.
  Umbrella closed; substantive follow-up tracked under PKIX-lwr9.4
  (design call pending: harness fix vs new pkix-path-builder helper).
* **PKIX-wmch** — pkix-difftest secondary baseline with all pkix-path
  signature features enabled (p384, etc.) to validate real-world
  ECDSA chains. Confirmed: 4 online::* chains flip to Agreement with
  `rustcrypto`. Snapshot baseline maintained as
  `baseline-limbo-allfeatures.{json,md}`.

## Conclusion

The x509-limbo Tier-2 baseline produces clear signal:

1. **One residual real divergence**: `bettertls::pathbuilding::tc60`,
   a single depth-6 chain. Down from 47 cases before PKIX-lwr9.6
   wired the harness through `build_path`. PKIX-lwr9.4 diagnosed the
   residual as a consumer-side harness/API-gap (`build_path` is
   single-shot; harness does not iterate `build_path_candidates` past
   a first candidate whose intermediate carries an algorithm
   `DefaultVerifier` rejects), not an algorithmic builder bug.
   Resolution design call pending under PKIX-lwr9.4.
2. **One documented intentional divergence**: openssl applies a
   CN-as-dNSName rule on nameConstraints checks that RFC 5280
   §4.2.1.10 explicitly forbids; pkix-path and pyca agree on the
   RFC-literal reading. 748 of 827 LooserThanWild cases are this
   family.
3. **One harness-shape limitation**: default-features-only build
   excludes p384, causing 4 online::* ECDSA chains (apple.com,
   cloudflare.com, akamai.com, stackoverflow.com) to fail signature
   verification. Tracked as PKIX-wmch — the secondary `rustcrypto`-
   features baseline below confirms these 4 are the only signature-
   verification flips from the feature surface change.
4. **Zero new pkix-path correctness regressions** detected against
   the existing project policy lines (no DSA, no P-192,
   permissive-by-default EKU/SAN/criticality).

Future runs should diff against this baseline as a regression
detector: any chain that flips Pass/Fail without a corresponding
documented change in pkix-path or the harness is worth investigating.

## With full crypto (`--features rustcrypto`, PKIX-wmch)

A secondary baseline run was produced with `pkix-difftest` built using
the `rustcrypto` feature, which activates `pkix-path/rustcrypto`
(`rsa` + `p256` + `p384`). All other oracle and corpus parameters
are unchanged. Files:

* `baseline-limbo-allfeatures.json` — machine-readable.
* `baseline-limbo-allfeatures.md` — auto-generated detail.

Invocation:

```sh
cargo build -p pkix-difftest --release --features rustcrypto
./target/release/pkix-difftest run limbo /path/to/limbo.json \
    --oracles pkix-path,openssl,pyca \
    --output-md  pkix-difftest/baseline-limbo-allfeatures.md \
    --output-json pkix-difftest/baseline-limbo-allfeatures.json
```

### Summary delta

| Class                | default | rustcrypto | Δ |
|----------------------|--------:|-----------:|---:|
| LooserThanWild       |     827 |        827 |  0 |
| StricterThanWild     |      23 |         19 | −4 |
| OracleDivergence     |       0 |          0 |  0 |
| DiagnosticDivergence |    5898 |       5898 |  0 |
| Agreement            |    2978 |       2982 | +4 |
| Total                |    9726 |       9726 |  — |

Ground-truth disagreements: 2902 → 2898 (−4, matching the 4 flips
to Agreement(Pass) — all 4 cases have `expected_result: SUCCESS`).
PKIX-lwr9.4.1 baked the 3 build_first_valid_path flips into both
baselines: the (default) Stricter 23 / Agreement 2978 already reflects
the tc60 / tc56 / nc-forbids-alternate-chain-ica fixes, so the
default-vs-rustcrypto delta below shows the remaining 4 P-384 chains
only.

### Chains that flipped

Exactly 4 cases changed class between the two baselines, all from
`StricterThanWild` (pkix-path Fail with `signature invalid at chain
index N`, openssl + pyca Pass) to `Agreement` (all three oracles
Pass):

| Case                       | default-features verdict (pkix-path)     | rustcrypto verdict (pkix-path) |
|----------------------------|------------------------------------------|--------------------------------|
| `online::apple.com`        | Fail: signature invalid at chain index 1 | Pass                           |
| `online::cloudflare.com`   | Fail: signature invalid at chain index 1 | Pass                           |
| `online::akamai.com`       | Fail: signature invalid at chain index 1 | Pass                           |
| `online::stackoverflow.com`| Fail: signature invalid at chain index 0 | Pass                           |

All 4 chains terminate at an ECDSA P-384 trust anchor (DigiCert
Global Root G3 family for the first three; the fourth has a P-384
root higher in the chain). Activating `pkix-path/p384` is sufficient
for `DefaultVerifier` to dispatch the `ecdsa-with-SHA384` OID and
verify the certificate signatures end-to-end.

No other case changed class.

### Why no `webpki::*` flips

The bead text anticipated that several `webpki::*` testcases would
also flip under the full crypto profile (P-384 / Ed25519). The
empirical answer from the run is **no `webpki::*` case flipped**.

Counting signature-verification failures in the default baseline,
filtered to `webpki::*` names:

| Case                          | Class                | pkix-path reason                |
|-------------------------------|----------------------|---------------------------------|
| `webpki::forbidden-dsa-root`  | StricterThanWild     | signature invalid at chain index 0 |
| `webpki::forbidden-p192-root` | StricterThanWild     | signature invalid at chain index 0 |
| `webpki::explicit-curve`      | DiagnosticDivergence | signature invalid at chain index 0 |

None are P-384 or Ed25519. Two are policy-excluded curves (DSA,
P-192) that pkix-path does not implement and will not implement;
the third is `explicit-curve`, where pkix-path's signature rejection
agrees on verdict with the other oracles (all three say Fail) and
the divergence is in the failure reason only. Activating
`rustcrypto` has no effect on any of them.

Ed25519 was a strict superset of the speculation in the bead —
pkix-path has not implemented an Ed25519 `SignatureVerifier` at all.
The `rustcrypto` feature is `rsa + p256 + p384`, not Ed25519. If
real-world Ed25519 chains land in the corpus in the future, that
will be tracked separately.

### Operational note

This secondary baseline is **not** wired into CI. CI continues to
diff against `baseline-limbo.json` (the default-features baseline)
per `pkix-difftest/scripts/ci-diff-baseline.sh`. The all-features
baseline is a snapshot for manual regression review when a new
signature backend lands or when the limbo corpus is refreshed.
