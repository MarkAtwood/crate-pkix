# `verify_*` wrapper differential — pyca/cryptography baseline

This is the deliverable for **PKIX-fmtv.19**: per-purpose pass-rate
baseline for `pkix_chain::verify_*` against the pyca/cryptography
`PolicyBuilder` family.

The companion OpenSSL baseline is **PKIX-fmtv.18 →
`baseline-verify-openssl.md`** (open).

## Scope by canonical purpose

pyca's `x509.verification.PolicyBuilder` is **intentionally
TLS-focused** — it ships `build_server_verifier(subject)` and
`build_client_verifier()` and no others. Coverage by `verify_*`
wrapper:

| Wrapper | pyca oracle | Baseline coverage |
|---|---|---|
| `verify_tls_server` | `build_server_verifier(DNSName/IPAddress)` | full, 23 cases |
| `verify_tls_client_dns` | `build_client_verifier()` | path-only; pyca cannot bind subject |
| `verify_tls_client_mailbox` | (same as above; no rfc822Name binding in pyca) | path-only |
| `verify_smime_signer` / `verify_smime_recipient` | none | falls to OpenSSL (PKIX-fmtv.18) |
| `verify_code_signer` | none | falls to OpenSSL |
| `verify_time_stamper` | none | falls to OpenSSL |
| `verify_ocsp_responder` | none | falls to OpenSSL (also pending design clarification, PKIX-fmtv.13.3) |

The S/MIME / code-signing / timestamp / OCSP gap is **not a defect**
— it reflects pyca's API surface. Differential coverage for those
wrappers is entirely on `openssl verify -purpose ...` (PKIX-fmtv.18).

## Oracle configuration

`pkix-difftest/python/pyca_verify_oracle.py` is the sidecar this
baseline uses; companion of the existing chain-level
`pyca_oracle.py` but with purpose-specific verifiers instead of the
chain-only `ClientVerifier` + `permit_all` shape.

### Server mode

```
builder = PolicyBuilder()
    .store(Store([root]))
    .time(t)
    .extension_policies(
        ee_policy=ExtensionPolicy
            .permit_all()
            .require_present(SubjectAlternativeName, Criticality.AGNOSTIC, None),
        ca_policy=ExtensionPolicy.webpki_defaults_ca(),
    )
verifier = builder.build_server_verifier(DNSName("...") | IPAddress(...))
```

Why the custom EE policy: pyca's `webpki_defaults_ee` is CA/B Forum
TLS-BR–flavored and requires `authorityKeyIdentifier`,
`subjectKeyIdentifier`, `cRLDistributionPoints`, etc. on the leaf.
That set is orthogonal to the RFC 6125 binding `verify_tls_server`
implements, and rejecting every minimal-extension test fixture would
collapse the comparison surface to zero. The custom EE policy
preserves the two semantics that matter:

1. **SAN must be present.** Pyca refuses to construct a
   `ServerVerifier` whose EE policy doesn't include
   `require_present(SubjectAlternativeName, ...)` — that gate is
   enforced at `build_server_verifier()` time, not at `verify()` time.

2. **SAN must match the subject.** `ServerVerifier.verify(...)`
   applies the binding regardless of EE-policy permissiveness — it's
   the verifier's purpose-driving check, not an extension-policy
   check.

### Client mode

```
builder = PolicyBuilder()
    .store(Store([root]))
    .time(t)
    .extension_policies(
        ee_policy=ExtensionPolicy.permit_all(),
        ca_policy=ExtensionPolicy.webpki_defaults_ca(),
    )
verifier = builder.build_client_verifier()
```

`build_client_verifier()` does not accept a subject — pyca's client
path doesn't bind hostname or mailbox at the verifier level. Under
`permit_all` EE policy, EKU is also not enforced. Both of those make
pyca a **strictly weaker oracle** for `verify_tls_client_dns`. Cases
where the Rust verifier enforces SAN binding or clientAuth EKU
are surfaced as `Rust-stricter` in the matrix below — they are
not bugs.

## Corpus

The cert corpus consumed is `pkix-chain/tests/fixtures/` — the
curated RFC 6125 fixture set authored under **PKIX-fmtv.22** for the
`hostname_corpus.rs` smoke surface. The wrapper diff test reuses
those fixtures so the per-case agreement matrix is directly auditable
against the in-crate baseline at
`pkix-chain/tests/hostname_corpus_baseline.md`.

No new fixtures are created for this baseline; if PKIX-fmtv.22's
corpus grows, this baseline grows with it automatically (the row
table in `tests/verify_wrapper_pyca.rs` is updated in lockstep).

## Per-purpose pass-rate

Captured by running `pkix-difftest/tests/verify_wrapper_pyca.rs` against
`pkix-chain 0.4.0` + `pkix-identity 0.1.0` + `pkix-path 0.3.0` + pyca
`cryptography 48.0.0`.

### Server (`verify_tls_server` vs `ServerVerifier(DNSName/IPAddress)`)

**23 / 23 cases produced a verdict on both sides.**
**22 / 23 in agreement** (95.7%). **0 Rust-looser, 1 Rust-stricter.**

| # | Case | Rust | pyca | Agreement |
|---|---|---|---|---|
| 1 | `exact_match` | Ok | pass | Agree |
| 2 | `exact_mismatch` | NoMatchingSan | fail | Agree |
| 3 | `exact_parent_does_not_match` | NoMatchingSan | fail | Agree |
| 4 | `wildcard_matches_single_label` | Ok | pass | Agree |
| 5 | `wildcard_parent_rejected` | NoMatchingSan | fail | Agree |
| 6 | `wildcard_deeper_rejected` | NoMatchingSan | fail | Agree |
| 7 | `wildcard_partial_label_rejected` | NoMatchingSan | fail | Agree |
| 8 | `wildcard_internal_rejected` | NoMatchingSan | fail | Agree |
| 9 | `wildcard_public_suffix_rejected` | NoMatchingSan | pass | **StricterThanPyca** |
| 10 | `case_san_upper_target_lower` | Ok | pass | Agree |
| 11 | `case_san_lower_target_upper` | Ok | pass | Agree |
| 12 | `idn_alabel_san_alabel_target` | Ok | pass | Agree |
| 13 | `ipv4_san_matches_ipv4_target` | Ok | pass | Agree |
| 14 | `ipv4_san_mismatch` | NoMatchingSan | fail | Agree |
| 15 | `ipv6_san_matches_ipv6_target` | Ok | pass | Agree |
| 16 | `ipv6_san_mismatch` | NoMatchingSan | fail | Agree |
| 17 | `ipv4_san_v6_target_rejected` | NoMatchingSan | fail | Agree |
| 18 | `dns_san_ip_target_rejected` | NoMatchingSan | fail | Agree |
| 19 | `multi_san_first_matches` | Ok | pass | Agree |
| 20 | `multi_san_middle_matches` | Ok | pass | Agree |
| 21 | `multi_san_wildcard_matches` | Ok | pass | Agree |
| 22 | `multi_san_none_match` | NoMatchingSan | fail | Agree |
| 23 | `missing_san_rejected` | MissingSan | fail | Agree |

#### Recorded divergence: case 9 — `wildcard_public_suffix_rejected`

- **Fixture**: `host-wildcard-tld.der`, SAN = `*.com`
- **Target**: `foo.com`
- **Rust** (`verify_tls_server` + `pkix-identity` matcher): rejects.
  Conservative public-suffix-shape refusal — a wildcard SAN whose
  remainder (`com`) has no internal `.` separator is universally
  unsafe. Documented in `pkix-chain/tests/hostname_corpus_baseline.md`
  and `pkix-identity` rustdoc as the structural check we ship instead
  of full Public Suffix List enforcement.
- **pyca**: accepts. Pyca does not implement public-suffix-shape
  refusal at the matcher level; its conservatism comes from
  webpki_defaults_ee's EKU/AKI requirements at a higher layer (the
  EE policy we relax for this comparison). The pyca team's stance
  has historically been "PSL enforcement is the caller's
  responsibility" — same posture as ours, but with a different
  default behavior on the structural fallback.
- **Verdict**: legitimate semantic divergence, documented under
  `pkix-identity`'s rustdoc. Not a bug on either side.

### Client (`verify_tls_client_dns` vs `ClientVerifier`)

**5 / 5 cases produced a verdict on both sides.**
**3 / 5 in agreement** (60%). **0 Rust-looser, 2 Rust-stricter.**

| # | Case | Rust | pyca | Agreement |
|---|---|---|---|---|
| 1 | `client_dns_match_rfc5280` | Ok | pass | Agree |
| 2 | `client_dns_match_basic_client` | Ok | pass | Agree |
| 3 | `client_dns_san_mismatch` | NoMatchingSan | pass | **StricterThanPyca** |
| 4 | `client_dns_eku_mismatch` | Path | pass | **StricterThanPyca** |
| 5 | `client_dns_none_no_san_ok` | Ok | pass | Agree |

Both `StricterThanPyca` cases are **expected pyca-weaker
outcomes**:

- Case 3: Rust enforces SAN binding via the wrapper's `Some(identity)`
  branch. Pyca's `ClientVerifier` accepts no subject argument and
  therefore can not bind. Documented as a scope limitation, not a
  bug.

- Case 4: Rust enforces `id-kp-clientAuth` EKU under
  `BasicTlsClientProfile`. Pyca's `ClientVerifier` under
  `permit_all` EE policy does not enforce EKU. To make pyca enforce
  EKU we would have to use `webpki_defaults_ee`, which would
  re-introduce the AKI/SKI/AIA strictures the corpus does not
  satisfy. Documented as a scope limitation.

These are surfaced in the diff matrix but the test does NOT fail on
them — the assert is `server.looser == 0`, not anything about the
client matrix.

## Hard invariants enforced by the test

The integration test (`tests/verify_wrapper_pyca.rs`) asserts:

1. Every Rust outcome matches the row table's `expected_rust` — the
   table is the in-test ground truth and prevents regressions when
   the matcher, parser, or wrapper changes upstream.

2. **Zero `Rust-looser` cases in server mode.** A Rust-looser
   divergence is "pyca refused while `verify_tls_server` passed"
   — a strong signal of a Rust bug. The assertion will fire if we
   ever regress.

The test does NOT assert on:

- Client-mode divergences, since both expected divergences are
  pyca-weaker by design.

- Rust-stricter server-mode divergences, since case 9 is a
  documented intentional difference. If a NEW Rust-stricter case
  appears, the matrix output (visible in CI on
  `--nocapture`) surfaces it and a human re-decides whether to
  document or fix; we don't fail-closed because that would block
  legitimate semantic differences from being recorded.

## Out of scope

- **PKITS / x509-limbo through the wrappers.** These corpora have
  EE certs with no SAN and no EKU, so they cannot exercise wrapper-
  level binding. The chain-level baselines (`baseline-pkits.md`,
  `baseline-limbo.md`) handle them at the `validate_path` layer.

- **CRL / OCSP revocation.** PKIX-fmtv.19 is a path+identity
  baseline. Revocation-side diff is PKIX-emf1.4 (CRL) + PKIX-emf1.5
  (OCSP).

- **Mailbox / rfc822Name binding through the wrappers.** Pyca has
  no equivalent verifier; the OpenSSL baseline (PKIX-fmtv.18 +
  `openssl verify -verify_email`) is the deliverable for that
  surface.

- **CT / SCT.** PKIX-baac.

## Reproducing

```sh
# One-time venv bootstrap (idempotent):
pkix-difftest/python/setup-venv.sh

# Run the diff:
cargo test -p pkix-difftest --test verify_wrapper_pyca -- --nocapture
```

The matrix is emitted to stderr (visible with `--nocapture`). If the
matrix layout in the test file is updated, this document is updated
to match in the same commit.
