# `pkix-profiles-cabf` — divergences from current CA/B Forum BR

This crate is a hand-authored snapshot of a small curated subset of CA/B
Forum Baseline Requirements predicates, exposed as idiomatic Rust
[`Profile`] types per AGENTS.md non-negotiable #5's "unprincipled
exception" clause. It is **reference, not authoritative.** The BR text
is the only canonical source.

This file records:

1. Which CA/B Forum specs and which version of each this crate was last
   refreshed against.
2. Known divergences between this crate's shipped Rust and the upstream
   BR text — both intentional and unintentional.
3. The policy under which this crate is refreshed.

For **comprehensive** CA/B Forum predicate coverage, see the sibling
crate `pkix-policy-zlint`, which wraps zlint's ~400 BR-conformance
checks via subprocess at runtime (PKIX-jy95.10).

## Last refresh

| Spec | Version | Refresh date |
|---|---|---|
| CA/B Forum TLS BR | 2.2.6 | 2026-05-13 |
| CA/B Forum S/MIME BR | 1.0.14 | 2026-05-13 |
| CA/B Forum Code Signing BR | 3.10.0 | 2026-05-13 |

Sources: `specs/cabforum-BR.md`, `specs/cabforum-smime-BR.md`,
`specs/cabforum-code-signing-BR.md` in the workspace root.

## Intentional divergences

### No numeric chain-depth cap on the `Profile`

`WebPkiProfile`, `SmimeProfile`, and `CodeSigningProfile` do **not** set
`ValidationPolicy::max_path_len`. Audit against the listed BR versions
confirmed that no current BR imposes a numeric chain-depth cap; each
spec only constrains the `pathLenConstraint` extension on individual CA
certificates in their `basicConstraints` tables (e.g. TLS BR
§7.1.2.10.4). RFC 5280 §4.2.1.9 `pathLenConstraint` enforcement in
`pkix-path` covers the per-cert case.

Earlier versions of this crate (pre-PKIX-d5rh) set `max_path_len = 2`
on `WebPkiProfile` and `max_path_len = 1` on the S/MIME and CS
profiles. That was workspace-added defense, not a BR requirement, and
it was removed when the citations were audited. Callers who want
defensive caps can opt in by setting `policy.max_path_len = N` on the
returned `ValidationPolicy`.

### SC-081 validity cap enforcement delegated to `pkix-lint`

`WebPkiProfile` does not set `ValidationPolicy::max_validity_secs`.
SC-081's phased cap is issuance-time-dependent (the cap in force when
the cert was issued governs that cert for its lifetime); a single
`max_validity_secs` value on `ValidationPolicy` would apply the same
cap to all certs regardless of issuance date.

The phased cap is exposed as `sc081_validity_cap(not_before_unix)` for
use by `pkix-lint::ValidityMaxLint` (and any caller building a
custom lint). See `WebPkiProfile`'s struct-level rustdoc.

### S/MIME and CS `max_validity_secs` apply to the whole chain

`SmimeProfile::policy().max_validity_secs = 825 days` (Strict
generation per §6.3.2) and `CodeSigningProfile::policy().max_validity_secs
= 460 days` apply to **every** certificate in the chain, not just the
leaf. Typical CA certificates have validity periods well above these
caps and will fail validation. This matches `pkix-path`'s
`ValidationPolicy` shape (the field is per-cert, not leaf-only) and is
called out in each profile's rustdoc `# Limitations` section. Callers
chaining these profiles against real-world CA hierarchies should
override `max_validity_secs` or use a custom policy.

### Sub-profile families partially split — Strict generation only

All S/MIME `Profile` types in this crate target the **Strict
generation** (`.3` OID suffix). Per S/MIME BR §7.1.6.1 line 2600,
Legacy generation (`.1`) was banned for new issuance effective
2025-07-15; the `-cabf` crate intentionally does not ship Legacy-tier
profile types. Multipurpose generation (`.2`) is a transitional bridge
profile and is tracked separately as PKIX-jbvb.8 (open architectural
question on whether to add Multipurpose Profile types). The
spec-taxonomy principle in AGENTS.md (PKIX-mzsk) ships one canonical
Profile per validation type, targeting the modern tier (Strict).

- `SmimeProfile` — Mailbox-validated baseline, Strict generation.
  825-day validity cap; rfc822Name SAN; emailProtection EKU.
- `SmimeSponsorValidated` — Sponsor-validated tier (§7.5),
  Strict generation. Reserved policy OID `2.23.140.1.5.3.3`. Subject
  DN rule per §7.1.4.2.5: `organizationName AND organizationIdentifier
  AND ((givenName AND surname) OR pseudonym)`.
- `SmimeIndividualValidated` — Individual-validated tier (§7.6),
  Strict generation. Reserved policy OID `2.23.140.1.5.4.3`. Subject
  DN rule per §7.1.4.2.6 Note 2: `(givenName AND surname) OR pseudonym`.
- Organization-validated (§7.4) Profile type remains tracked under
  PKIX-jbvb.1.

### Subscriber-cert taxonomy only

Per AGENTS.md's spec-taxonomy principle (PKIX-mzsk), this crate ships
`Profile` types only for subscriber certificates. CA-cert / Root-cert
profile machinery is not duplicated here — RFC 5280 §6.1 in `pkix-path`
handles CA-cert validation. Per-predicate lint enforcement is out of
scope as well; `pkix-policy-zlint` covers that.

## Out of scope by design

- `pkix-profiles-mozilla`, `pkix-profiles-fedramp`, `pkix-profiles-dod`,
  `pkix-profiles-etsi` — barred by the AGENTS.md non-negotiable #5
  "not a template" clause. Other industry-forum / vendor policies must
  come in via policy-adapter crates that defer to upstream tools, not
  via workspace-internal transcription.
- CAA DNS record checks (network operation, out of scope for the
  `pkix-path` `Profile` shape).
- CT log SCT verification (separate verification step; tracked under
  `pkix-ct`).
- OCSP / CRL revocation (handled by `pkix-revocation`).

## Refresh policy

This crate is refreshed on a wholesale audit cadence, not per-ballot.
When the workspace maintainer pulls in updated BR markdown sources
under `specs/`, a follow-up audit refreshes the citations, version
stamps, and any behavior that materially diverges. Between refreshes,
the citations may drift behind the upstream specs.

If you depend on bit-exact CA/B Forum conformance, **fork and review**.
The crate-level rustdoc says so explicitly.

PRs that point out a divergence (citation, behavior, or coverage gap)
are welcome. File the divergence here first, then either propose the
fix in the same PR or split it into a follow-up.

## Cross-references

- AGENTS.md non-negotiable #5 — three-mode policy-class architecture
  and the unprincipled-exception clause that admits this crate.
- AGENTS.md spec-taxonomy principle (PKIX-mzsk) — what subscriber-cert
  shapes are in scope for `-cabf` crates.
- `pkix-policy-zlint` — principled predicate-comprehensive CA/B Forum
  coverage (PKIX-jy95.10).
- `pkix-lint-cabf/divergences.md` — sibling divergence record for the
  lint side of the unprincipled exception.

[`Profile`]: https://docs.rs/pkix-path/latest/pkix_path/trait.Profile.html
