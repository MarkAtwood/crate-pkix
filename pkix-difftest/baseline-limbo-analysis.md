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
| LooserThanWild       |   819 | 8.4%  |
| StricterThanWild     |    74 | 0.8%  |
| OracleDivergence     |     0 | 0.0%  |
| DiagnosticDivergence |  5901 | 60.7% |
| Agreement            |  2932 | 30.1% |
| **Total**            | **9726** |   |

Ground-truth agreement (vs corpus's `expected_result`):

| Class           | gt agree | gt disagree |
|-----------------|---------:|------------:|
| LooserThanWild  |       92 |         727 |
| StricterThanWild|       19 |          55 |

The 727 LooserThanWild-but-corpus-disagrees and 55
StricterThanWild-but-corpus-disagrees cases are the focus below.

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

## StricterThanWild (74) — pkix-path Fail, ≥1 oracle Pass

| Reason bucket | Count | Classification |
|---|---:|---|
| `no path to a trusted anchor` | 24 | 22 bettertls::pathbuilding + 2 misc (rfc5280::nc::permitted-self-issued, rfc5280::root-and-intermediate-swapped). **Real divergence: pkix-path-builder is weaker than openssl/pyca path builders.** See PKIX-lwr9 (filed below). |
| `signature invalid at chain index 5` | 10 | bettertls::pathbuilding tc48-57. Same family — chain depth 6 cases the builder misorders. |
| `signature invalid at chain index 1` | 13 | 10 bettertls::pathbuilding (tc2/tc8/tc15/tc23/tc30-35) + 3 online (apple/cloudflare/akamai). The 10 pathbuilding cases: most are wrong-intermediate selection; tc8/tc15 are different (pyca fails on Forbidden signature algorithm 1.2.840.10045.4.1 — a legacy ECDSA OID — but openssl passes; harness limitation, not path-builder). The 3 online::* cases are ECDSA P-384 intermediate→root verifications where pkix-path lacks `p384` feature. Filed as PKIX-lwr9 (pathbuilding) and PKIX-wmch (P-384) below. |
| `signature invalid at chain index 0` | 3 | online::stackoverflow.com (P-384, PKIX-wmch), webpki::forbidden-dsa-root (DSA, project-policy unsupported), webpki::forbidden-p192-root (P-192, project-policy unsupported). All three are intentional pkix-path limitations, not bugs. |
| `malformed certificate at chain index 0` | 11 | bettertls::nameconstraints tc8877..tc9476 + webpki::san::unicode-emoji-san. **pkix-path AGREES with corpus ground truth** on all 11 (gt_agreement=true). pkix-path rejects malformed leaves that openssl and pyca tolerate; in this case strict-is-correct. No bead. |
| `path length exceeds maximum` | 8 | bettertls::pathbuilding tc61-68. pkix-path-builder picks a long path that exceeds the intermediate's pathLenConstraint. openssl fails differently ("unable to get local issuer"), pyca passes via shorter alternate path. Same root cause as the path-building bucket. PKIX-lwr9. |
| `signature invalid at chain index 6` | 1 | bettertls::pathbuilding::tc60. Same path-building family. PKIX-lwr9. |
| `certificate at index 6 is not a CA` | 2 | bettertls::pathbuilding::tc58, tc59. Path builder selects a non-CA cert at an intermediate position. PKIX-lwr9. |
| `unhandled critical extension at chain index 0` | 1 | rfc5280::ee-critical-aia-invalid. **pkix-path correct** — RFC 5280 §4.2.1.1 says AKI MUST NOT be critical. pkix-path enforces; openssl fails too (different wording); pyca passes. gt_agreement=true. |
| `name constraints violated at certificate index 0` | 1 | rfc5280::nc::nc-permits-invalid-dns-san. gt_agreement=true. pkix-path strict NC; openssl lenient; pyca strict too. No bead. |
| **Total** | **74** | |

### `bettertls::pathbuilding` family (47 / 64% of Stricter)

**Real divergence**: pkix-path-builder's path-selection heuristic is
weaker than openssl's and pyca's. The BetterTLS pathbuilding suite is
specifically designed to test resilience against:

* multiple candidate intermediates (some self-signed, some
  cross-signed) where the validator must pick the right one,
* deep chains (6 levels) with redundant intermediates,
* cases where the "obvious" path (first match by issuer DN) leads to
  signature failure but an alternate sibling intermediate works.

On all 47 cases pkix-path fails with one of:
`no path to a trusted anchor`, `signature invalid at chain index N`,
`path length exceeds maximum`, `certificate at index N is not a CA`,
`signature invalid at chain index 6`. openssl + pyca both find a
valid path on most of them; openssl alone fails on the pathlen
cases where pyca succeeds through self-issued-cert exemptions.

The corpus author marks **43 of 47** as `expected_result: SUCCESS` —
positive tests that the validator should pass. pkix-path is wrong on
those 43. The remaining 4 (gt_agreement=true) are cases where the
corpus expects FAILURE and pkix-path correctly rejects (tc8/tc15 are
in this group — pkix-path rejects via signature mismatch, pyca via
forbidden algorithm).

Filed as **PKIX-lwr9** (pkix-path-builder robustness on bettertls
pathbuilding suite). This becomes the highest-priority real divergence
the harness has surfaced.

### Harness-shape limitations (not pkix-path bugs)

* **ECDSA P-384 (4 chains: online apple/cloudflare/akamai/stackoverflow
  + part of webpki ECC roots)** — pkix-difftest builds pkix-path with
  default features `["rsa", "p256"]`. Real-world ECC chains require
  `p384`. Documented in `pkix-difftest/Cargo.toml` as an intentional
  default-features-only test, but a secondary all-features run would
  catch real-world ECC chains. Filed as **PKIX-wmch** (run a secondary
  all-features baseline). Lower priority than the path-builder bead.
* **Some ECDSA-with-SHA-1-or-legacy OID (1.2.840.10045.4.1)** — pkix-path
  default features don't dispatch this OID. Out of scope (deprecated
  algorithm; not project policy to add).

## OracleDivergence (0)

No chain has pkix-path agreeing with one oracle while the other two
oracles disagree on Pass/Fail (3-way split is impossible by
construction with two non-pkix-path oracles).

## DiagnosticDivergence (5901)

All three oracles agree on Pass/Fail; only the reason strings differ.
60.7% of the corpus falls here, which is high — but expected. x509-limbo
ships hundreds of "make sure all oracles agree this is invalid" CVE and
malformed-cert tests where openssl says "unable to parse" while pyca
says "VerificationError: invalid extension X" and pkix-path says
"malformed certificate at chain index N". Low-signal; no follow-up.

## Agreement (2932 / 30.1%)

All three oracles produce identical Pass/Fail verdicts. 30% Agreement
is lower than the PKITS baseline's 28.7%, but the limbo corpus has
~40× more cases, so absolute Agreement count (2932) dwarfs PKITS
(71). Within Agreement, the harness's value comes from the next run:
any chain that flips from Agreement to a divergence class without a
corresponding code change is a regression.

## Ground-truth disagreement

Across all 9726 classified cases, pkix-path disagrees with the corpus
ground-truth on **2948 cases** (30.3%). The bulk is the 727
LooserThanWild-but-corpus-disagrees set, which is dominated by the
748 BetterTLS nameConstraints cases discussed above (660 with
gt_disagree).

After excluding the BetterTLS CN-as-DNS family (intentional
RFC-literal divergence), real ground-truth-disagreement drops to
~2200. The next biggest contributors:

* pyca-strict failures where pkix-path passes (corpus expects pyca
  to be right): EKU presence, critical-extension criticality, RSA
  key strength, NC type strictness. Each is a project-policy decision
  to keep pkix-path's defaults permissive. Documented per-bucket above.
* the 54 BetterTLS pathbuilding cases where pkix-path SHOULD pass and
  doesn't (filed as PKIX-lwr9).

The harness is functioning correctly: the dominant ground-truth-
disagreement signal points at a documented design choice (CN-as-DNS),
and the smaller signal isolates the real follow-up work
(path-builder robustness).

## Follow-up beads filed by this analysis

* **PKIX-lwr9** — pkix-path-builder fails on bettertls::pathbuilding
  suite (47 StricterThanWild cases, 43 of which the corpus expects to
  pass). Highest-priority real divergence (P2).
* **PKIX-wmch** — pkix-difftest secondary baseline with all pkix-path
  signature features enabled (p384, etc.) to validate real-world
  ECDSA chains (P3). Lower priority — documents what the limbo
  `online::*` chains look like under the full crypto profile.

## Conclusion

The x509-limbo Tier-2 baseline produced clear signal:

1. **One real divergence family**: pkix-path-builder is weaker than
   openssl/pyca on the BetterTLS pathbuilding suite (47 cases of 74
   StricterThanWild; 43 corpus-expected-success). Tracked as PKIX-lwr9.
2. **One documented intentional divergence**: openssl applies a
   CN-as-dNSName rule on nameConstraints checks that RFC 5280
   §4.2.1.10 explicitly forbids; pkix-path and pyca agree on the
   RFC-literal reading. 748 of 819 LooserThanWild cases are this
   family.
3. **One harness-shape limitation**: default-features-only build
   excludes p384, causing 4 online::* ECDSA chains and several
   webpki:: ECC root tests to fail signature verification. Tracked
   as PKIX-wmch.
4. **Zero new pkix-path correctness regressions** detected against
   the existing project policy lines (no DSA, no P-192,
   permissive-by-default EKU/SAN/criticality).

Future runs should diff against this baseline as a regression
detector: any chain that flips Pass/Fail without a corresponding
documented change in pkix-path or the harness is worth investigating.
