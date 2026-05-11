# pkix-profiles-cabf

**Reference implementation of CA/Browser Forum certificate profile requirements (TLS BR, S/MIME BR, Code Signing BR). Not authoritative.**

CA/B Forum Baseline Requirements change on a ballot cycle. The implementations in this crate are a snapshot of those requirements at the time of the most recent revision. They are intended as a starting point: fork and adapt to your deployment's current interpretation of the BR text, which is the only canonical source.

For the current Baseline Requirements:
- <https://cabforum.org/baseline-requirements/> (TLS)
- <https://cabforum.org/smime-br/> (S/MIME)
- <https://cabforum.org/code-signing-baseline-requirements/> (Code Signing)

Maintained on a best-effort basis. If your deployment depends on bit-exact CA/B Forum conformance, you SHOULD vendor and review the relevant rule definitions yourself.

## Profiles

| Struct | Free-function alias | Document | Key constraints |
|--------|---------------------|----------|-----------------|
| [`WebPkiProfile`] | [`web_pki_policy`] | CA/B Forum TLS BR | SHA-1 prohibited, RSA ≥ 2048, non-empty SAN, `serverAuth` EKU, path len ≤ 2 |
| [`SmimeProfile`] | [`smime_policy`] | CA/B Forum S/MIME BR v1.0 | SHA-1 prohibited, RSA ≥ 2048, `rfc822Name` SAN, `emailProtection` EKU, max validity 1185 days, path len ≤ 1 |
| [`CodeSigningProfile`] | [`code_signing_policy`] | CA/B Forum CS BR v3.0 | SHA-1 prohibited, RSA ≥ 3072, `codeSigning` EKU, max validity 460 days, path len ≤ 1 |

For RFC-baseline profiles (`Rfc5280Profile`, `BasicTlsProfile`, `BasicSmimeProfile`), see the upstream [`pkix-profiles`] crate.

## SC-081 validity cap

CA/B Forum Ballot SC-081 introduced a phased reduction in TLS certificate maximum validity:

| Issuance date | Maximum validity |
|---------------|------------------|
| Before 2026-03-15 | 398 days |
| 2026-03-15 – 2027-03-15 | 200 days |
| 2027-03-15 – 2029-03-15 | 100 days |
| From 2029-03-15 | 47 days |

Because the applicable cap depends on the certificate's `notBefore` date rather than the current clock, SC-081 enforcement is not set in `ValidationPolicy` directly. It is handled by `ValidityMaxLint` in `pkix-lint-cabf`, which evaluates each certificate at issuance time. Use [`sc081_validity_cap(not_before_unix)`] to look up the correct cap for a given issuance date.

## Status

First substantive content release (`0.2.0`). Houses the CA/B Forum-specific profile content that was previously embedded in `pkix-profiles 0.2.x`. The split is part of the framework-not-policy stance: `pkix-profiles` keeps the IETF/RFC-baseline mechanisms, and this crate keeps the CA/B Forum reference snapshots clearly marked "not authoritative."

The S/MIME BR Organization-validated, Sponsor-validated, and Individual-validated sub-profiles are planned but not yet implemented (tracked as PKIX-jbvb).

## License

Apache-2.0 OR MIT

[`pkix-profiles`]: https://docs.rs/pkix-profiles
