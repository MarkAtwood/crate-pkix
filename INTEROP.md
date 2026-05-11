# Real-world interoperability divergences

This document captures **concrete cases** where `pkix-path` produces a
verdict that disagrees with one or more other shipping X.509 path
validators (OpenSSL, pyca/cryptography, …), along with our reasoning
for which behaviour `pkix-path` follows.

The findings here are sourced from `pkix-difftest`
([`pkix-difftest/`](pkix-difftest/)), the differential testing harness
that runs every chain through `pkix-path` plus one or more external
oracles and classifies the verdict tuple. The PKITS baseline in
`pkix-difftest/baseline-pkits-analysis.md` is the canonical artefact
this document distils.

## Reading this document

Each section names a concrete divergence class, with:

* A characteristic chain (PKITS test name, which is stable across
  PKITS releases).
* The verdict each oracle produces on that chain.
* Our reasoning ("we side with X because Y").
* The status: **intentional** (we will not change), **bug**
  (`pkix-path` is wrong, follow-up bead filed), or **harness limitation**
  (the chain shape exposes a `pkix-difftest` gap, not a real
  divergence).

This is a living document. PRs that change `pkix-path` verdict
behaviour and affect any divergence here MUST update this file in the
same commit.

## Current status

* **Zero correctness regressions detected** against OpenSSL across the
  247 PKITS chains the harness can classify. Every chain where
  `pkix-path` and OpenSSL disagree is documented below as either
  intentional (we follow the literal RFC 5280 reading) or harness
  limitation (chain shape exposes a `pkix-difftest` gap).

## 1. pyca rejects critical PolicyMappings, InhibitAnyPolicy, PolicyConstraints

* **Characteristic chain**: `4.10.1.1 Valid Policy Mapping Test1
  (Subpart 1)` (and 27 similar)
* **Verdicts**:
  * `pkix-path`: Pass
  * `openssl`: Pass
  * `pyca`: `Fail (VerificationError: ... invalid extension: 2.5.29.33:
    certificate contains unaccounted-for critical extensions)`
* **Reasoning**: pyca's `PolicyBuilder.build_client_verifier()` uses
  the CA/B Forum-flavoured extension policies and explicitly does not
  handle PolicyMappings (OID 2.5.29.33), InhibitAnyPolicy (2.5.29.54),
  or PolicyConstraints (2.5.29.36). When these extensions appear
  marked critical, pyca rejects the cert because *any* unhandled
  critical extension is rejected per its policy. RFC 5280 §6.1.4
  *requires* a path validator to process these extensions; OpenSSL
  and `pkix-path` do, so they accept. **`pkix-path` sides with the
  RFC.** `pyca`'s behaviour is a deliberate design choice for WebPKI
  conformance, not an interpretation we should match.
* **Status**: intentional. No action.

## 2. pyca DN comparison stricter than RFC 4518

* **Characteristic chain**: `4.3.3 Valid Name Chaining Whitespace
  Test3` (and 4 similar)
* **Verdicts**:
  * `pkix-path`: Pass
  * `openssl`: Pass
  * `pyca`: `Fail (VerificationError: ... candidates exhausted: all
    candidates exhausted with no interior errors)`
* **Reasoning**: PKITS 4.3.3 / 4.3.4 / 4.3.5 / 4.3.10 / 4.3.11 chain
  certs whose Subject and Issuer DNs differ in whitespace,
  capitalisation, or PrintableString-vs-UTF8String encoding. RFC 4518
  defines string preparation that normalises away these differences;
  RFC 5280 §6.1 requires DN comparison to follow that normalisation.
  `pkix-path` and OpenSSL implement the normalisation; pyca uses
  byte-equal comparison, which rejects these chains. **`pkix-path`
  sides with the RFC.**
* **Status**: intentional. (Note: `pkix-path`'s RFC 4518 implementation
  is partial — see PKIX-l63j for the planned RFC 4518 work.)

## 3. pyca rejects negative serial numbers and pre-1950 GeneralizedTime

* **Characteristic chains**:
  * `4.4.15 Invalid Negative Serial Number Test15` (negative serial)
  * `4.2.4 Valid GeneralizedTime notBefore Date Test4` (date in 1950–2049 range)
* **Verdicts**:
  * `pkix-path`: Pass
  * `openssl`: Pass
  * `pyca`: `Fail` with reasons "certificate serial number cannot be
    negative" or "validity dates between 1950 and 2049 must be UtcTime"
* **Reasoning**: RFC 5280 §4.1.2.2 says "the serial number MUST be a
  positive integer", and §4.1.2.5 says dates ≤ 2049 MUST use UTCTime
  rather than GeneralizedTime. pyca enforces both literally; OpenSSL
  and `pkix-path` are lenient because real-world certs in the wild
  violate these MUSTs and the validators that ship with browsers and
  TLS stacks accept them. **`pkix-path` sides with the wild here**:
  rejecting these chains breaks more real-world traffic than it
  protects against.
* **Status**: intentional, but worth flagging if you operate in a
  regulated environment that wants strict RFC 5280. If so, file an
  issue requesting a `ValidationPolicy` flag.

## 4. pkix-path enforces NameConstraints; OpenSSL is lenient on some types

* **Characteristic chain**: 12 PKITS §4.13 NameConstraint tests
* **Verdicts**:
  * `pkix-path`: `Fail (name constraints violated at certificate index 0)`
  * `openssl`: Pass
  * `pyca`: Pass (when supported), `Fail (unsupported name constraint
    type)` for URI nameConstraints
* **Reasoning**: OpenSSL ships a partial NameConstraint implementation
  with documented gaps on some general-name types (particularly URI
  and DirName). `pkix-path` implements the full §4.2.1.10 set per RFC
  5280. **`pkix-path` sides with the RFC.** This is the kind of
  divergence where being stricter than OpenSSL is the right call —
  NameConstraints exist to bound CA authority and OpenSSL's leniency
  has been the subject of real-world CVEs.
* **Status**: intentional.

## 5. pkix-path enforces RFC 5280 §6.1.5 policy state machine

* **Characteristic chain**: 30 PKITS chains around `4.8.* Certificate
  Policies` and `4.9.* RequireExplicitPolicy`
* **Verdicts**:
  * `pkix-path`: `Fail (certificate policy violation at chain index N)`
  * `openssl`: Pass
* **Reasoning**: RFC 5280 §6.1.5 specifies a complex policy
  intersection state machine (`valid_policy_tree`, `explicit_policy`,
  `policy_mapping_inhibit`, `inhibit_any_policy`). The spec is
  famously underspecified at the edges and OpenSSL implements a
  lenient version that accepts more chains than the literal RFC
  reading. `pkix-path` implements the literal reading. **`pkix-path`
  sides with the RFC.** This is exactly the kind of feature that
  exists for a reason — policy constraints let CAs scope their
  delegations to specific OIDs.
* **Status**: intentional. If a downstream consumer needs the lenient
  OpenSSL behaviour, file an issue requesting a permissive
  `ValidationPolicy` flag.

## 6. PKITS chains where pkix-path appears to fail signature validation

* **Characteristic chains**: 13 PKITS §4.4 (Separate Cert/CRL Keys)
  and §4.14 (Indirect CRL / cRLIssuer) plus some §4.5 self-issued
  rollover chains
* **Verdicts**:
  * `pkix-path`: `Fail (signature invalid at chain index N)`
  * `openssl`: Pass
* **Reasoning**: PKITS' `vectors.json` `CertPath` field is intended as
  a *bundle* for path-builders, not a pre-ordered signature chain. For
  these specific tests, `CertPath` includes a CRL-signing cert in a
  position that does not match the actual signature linkage.
  `pkix-path` is positional — it expects `chain[i+1]` to be the
  issuer of `chain[i]` — so it correctly rejects the chain on
  signature. OpenSSL does its own path-building from the bundle and
  finds the actual signature path.
* **Status**: **harness limitation**, not a real divergence. The
  harness's PKITS loader passes `CertPath` through verbatim; the
  proper fix is path-building integration, tracked as
  [PKIX-t0w4](.beads/).

## 7. PKITS §4.7.4 / §4.7.5 (cRLSign on intermediate) — opt-in via policy flag

* **Characteristic chains**:
  * `4.7.4 Invalid keyUsage Critical cRLSign False Test4`
  * `4.7.5 Invalid keyUsage Not Critical cRLSign False Test5`
* **Verdicts (default policy)**:
  * `pkix-path`: Pass
  * `openssl`: Pass (RFC-literal reading)
  * PKITS metadata: must-fail
* **Reasoning**: RFC 5280 §6.1.4(n) only requires the `keyCertSign` bit
  on intermediates; the literal §6.1 state machine does not check
  `cRLSign`. PKITS conflates path validation with revocation
  infrastructure: a CA cert without `cRLSign` cannot revoke certs it
  issued, so PKITS treats such chains as invalid even at path-validation
  time. `pkix-path` defaults to the RFC-literal reading.
* **Configurable strictness**: set
  `ValidationPolicy::require_crl_sign_on_cas = true` to opt into PKITS
  conformance. With the flag on, any intermediate whose `KeyUsage`
  extension is present but lacks `cRLSign` is rejected with
  `Error::CrlSignMissing { index }`. Default remains `false`; existing
  callers see no behavioural change.
* **Status**: intentional default; opt-in flag exposed. Tracked as
  PKIX-0x9z.

## Reproducing these findings

```sh
# 1. Bootstrap pyca venv (one-time):
./pkix-difftest/python/setup-venv.sh

# 2. Re-run the baseline:
cargo run --release -p pkix-difftest -- run pkits pkix-path/tests/pkits \
  --oracles pkix-path,openssl,pyca \
  --output-md pkix-difftest/baseline-pkits.md \
  --output-json pkix-difftest/baseline-pkits.json

# 3. Compare against the committed baseline:
git diff pkix-difftest/baseline-pkits.json
```

The `baseline-pkits.json` is the source of truth. Any verdict-affecting
change to `pkix-path` should produce a clean `git diff` of this file
naming exactly the chains that moved between classes.
