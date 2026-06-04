# pkix-profiles-cabf

**Reference implementation of CA/Browser Forum certificate profile requirements (TLS BR, S/MIME BR, Code Signing BR). Not authoritative.**

CA/B Forum Baseline Requirements change on a ballot cycle. The implementations in this crate are a small, curated snapshot of marquee BR requirements. They are intended as a starting point: fork and adapt to your deployment's current interpretation of the BR text, which is the only canonical source.

For the current Baseline Requirements:
- <https://cabforum.org/baseline-requirements/> (TLS)
- <https://cabforum.org/smime-br/> (S/MIME)
- <https://cabforum.org/code-signing-baseline-requirements/> (Code Signing)

Maintained on a best-effort basis. If your deployment depends on bit-exact CA/B Forum conformance, you SHOULD vendor and review the relevant rule definitions yourself.

## Profiles

Each profile's `version()` accessor returns the dotted spec version it was last refreshed against (e.g. `"2.2.6"`, `"1.0.14"`, `"3.10.0"`). The BR text is the canonical source; version strings are informational only.

**Subscriber-cert taxonomy only.** Per the spec-taxonomy principle (PKIX-mzsk), this crate ships `Profile` types for each subscriber-certificate profile explicitly named in the BR. CA-cert and Root-cert profile machinery is not duplicated here — that is the path validator's job (RFC 5280 §6.1, in `pkix-path`).

S/MIME profiles target either the **Strict generation** (`.3` OID suffix) or the **Multipurpose generation** (`.2` OID suffix). Legacy generation (`.1`) is BR-banned for new issuance effective 2025-07-15 per S/MIME BR §7.1.6.1 and is not represented here.

| Struct | Free-function alias | Document | Key constraints |
|--------|---------------------|----------|-----------------|
| `WebPkiProfile` | `web_pki_policy` | TLS BR 2.2.6 | SAN required, SHA-1 prohibited, RSA ≥ 2048, `serverAuth` EKU |
| `SmimeProfile` | `smime_policy` | S/MIME BR 1.0.14 | Mailbox-validated Strict: `rfc822Name` SAN, `emailProtection` EKU, max validity 825 days |
| `SmimeSponsorValidated` | `smime_sponsor_policy` | S/MIME BR 1.0.14 §7.5 | Mailbox baseline + policy OID `2.23.140.1.5.3.3` + Subject DN `organizationName` and `organizationIdentifier` and (`givenName`+`surname` or `pseudonym`) |
| `SmimeSponsorValidatedMultipurpose` | `smime_sponsor_multipurpose_policy` | S/MIME BR 1.0.14 §7.5 (Multipurpose) | Mailbox baseline + policy OID `2.23.140.1.5.3.2` + same Subject DN rules + additional EKUs permitted |
| `SmimeIndividualValidated` | `smime_individual_policy` | S/MIME BR 1.0.14 §7.6 | Mailbox baseline + policy OID `2.23.140.1.5.4.3` + Subject DN (`givenName`+`surname` or `pseudonym`) |
| `SmimeIndividualValidatedMultipurpose` | `smime_individual_multipurpose_policy` | S/MIME BR 1.0.14 §7.6 (Multipurpose) | Mailbox baseline + policy OID `2.23.140.1.5.4.2` + same Subject DN rules + additional EKUs permitted |
| `CodeSigningProfile` | `code_signing_policy` | CS BR 3.10.0 | `codeSigning` EKU, SHA-1 prohibited, RSA ≥ 3072, max validity 460 days |

The Organization-validated tier (Strict and Multipurpose) remains tracked under PKIX-jbvb.

For RFC 5280 baseline and `BasicTlsProfile` / `BasicSmimeProfile` (RFC 8551 §3 baseline), see the upstream [`pkix-profiles`] crate.

## SC-081 validity cap

CA/B Forum Ballot SC-081 introduced a phased reduction in TLS certificate maximum validity:

| Issuance date | Maximum validity |
|---------------|------------------|
| Before 2026-03-15 | 398 days |
| 2026-03-15 – 2027-03-15 | 200 days |
| 2027-03-15 – 2029-03-15 | 100 days |
| From 2029-03-15 | 47 days |

Because the applicable cap depends on the certificate's `notBefore` date rather than the current clock, SC-081 enforcement is not set in `ValidationPolicy` directly. It is handled by `ValidityMaxLint` in `pkix-lint-cabf`, which evaluates each certificate at issuance time. Use `sc081_validity_cap(not_before_unix)` to look up the correct cap for a given issuance date.

## Status

Houses the CA/B Forum-specific profile content that was previously embedded in `pkix-profiles`. The split is part of the framework-not-policy stance: `pkix-profiles` keeps the IETF/RFC-baseline mechanisms, and this crate keeps the CA/B Forum reference snapshots clearly marked "not authoritative."

## License

Apache-2.0 OR MIT

[`pkix-profiles`]: https://docs.rs/pkix-profiles
