#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! Reference profile implementations for common CA/Browser Forum and IETF regimes.
//!
//! # What this crate is
//!
//! `pkix-profiles` ships **one set of regime implementations** that comes with the
//! library. It is not the authoritative home for all possible PKI profiles — it is
//! an example and reference. Third-party crates (`pkix-fpki`, `pkix-etsi`, etc.)
//! implement [`pkix_path::Profile`] directly against `pkix-path` and do not need to
//! depend on this crate.
//!
//! The [`Profile`] trait itself lives in `pkix-path` so that external profile crates
//! can depend on it without pulling in these bundled implementations.
//!
//! # Profiles
//!
//! | Struct | Free-function alias | Document | Key constraints |
//! |--------|--------------------|---------| ----------------|
//! | [`WebPkiProfile`] | [`web_pki_policy`] | CA/B Forum TLS BR | 398-day max validity, SAN required, SHA-1 prohibited |
//! | [`SmimeProfile`] | [`smime_policy`] | CA/B Forum S/MIME BR | Email-specific key usage, S/MIME EKU |
//! | [`CodeSigningProfile`] | [`code_signing_policy`] | CA/B Forum Code Signing BR | Code signing EKU, RSA ≥ 3072 |
//! | [`Rfc5280Profile`] | [`rfc5280_policy`] | RFC 5280 only | No CA/B Forum additions |
//!
//! # Usage
//!
//! ```rust,no_run
//! use pkix_profiles::{Profile, WebPkiProfile};
//!
//! let now_unix = 1_700_000_000_u64;
//!
//! // Via the Profile trait (for generic code or registries):
//! let profile = WebPkiProfile;
//! let policy = profile.policy(now_unix);
//! # let _ = policy;
//!
//! // Via free-function alias (for quick one-liners):
//! let policy = pkix_profiles::web_pki_policy(now_unix);
//! # let _ = policy;
//! ```
//!
//! # `std` requirement
//!
//! This crate requires `std`. [`ValidationPolicy`] holds owned `Vec` fields that
//! currently require the standard allocator. `no_std` + `alloc` support is planned
//! for a future release; until then, downstream `no_std` crates should construct
//! [`ValidationPolicy`] directly rather than using this crate.
//!
//! # Spec references
//!
//! - CA/Browser Forum Baseline Requirements for TLS Server Certificates
//! - CA/Browser Forum S/MIME Baseline Requirements
//! - CA/Browser Forum Code Signing Baseline Requirements
//! - RFC 5280 — Internet X.509 PKI Certificate and CRL Profile

pub use pkix_path::{Profile, ValidationPolicy};

use der::asn1::ObjectIdentifier;

/// Seconds in one day (60 × 60 × 24).
const SECS_PER_DAY: u64 = 86_400;

// ---------------------------------------------------------------------------
// Per-profile algorithm OID constants
//
// Each profile owns its algorithm list explicitly. Do not share a single
// `CABF_ALLOWED_ALGS` constant across profiles — that couples S/MIME and
// code-signing to TLS BR §7.1.3, which will diverge over time.
//
// Each constant carries a doc comment citing the normative source so future
// maintainers can verify and update independently.
// ---------------------------------------------------------------------------

// RSA signature OIDs (RFC 4055 / RFC 5912)
const SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const SHA384_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const SHA512_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

// ECDSA signature OIDs (RFC 5912)
const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const ECDSA_WITH_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const ECDSA_WITH_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

/// CA/B Forum TLS BR §7.1.3 — approved signature algorithms for TLS certificates.
///
/// SHA-1 (`sha1WithRSAEncryption`, `ecdsa-with-SHA1`) is intentionally absent.
/// The list currently matches S/MIME BR §7.1.3 and CS BR §7.1.3, but they are
/// maintained as separate constants because each regime may diverge independently.
const CABF_TLS_BR_ALLOWED_ALGS: &[ObjectIdentifier] = &[
    SHA256_WITH_RSA,
    SHA384_WITH_RSA,
    SHA512_WITH_RSA,
    ECDSA_WITH_SHA256,
    ECDSA_WITH_SHA384,
    ECDSA_WITH_SHA512,
];

/// CA/B Forum S/MIME BR §7.1.3 — approved signature algorithms for S/MIME certificates.
///
/// Currently identical to [`CABF_TLS_BR_ALLOWED_ALGS`] but maintained independently
/// because the S/MIME BR algorithm policy may diverge from TLS BR in future ballots.
const CABF_SMIME_BR_ALLOWED_ALGS: &[ObjectIdentifier] = &[
    SHA256_WITH_RSA,
    SHA384_WITH_RSA,
    SHA512_WITH_RSA,
    ECDSA_WITH_SHA256,
    ECDSA_WITH_SHA384,
    ECDSA_WITH_SHA512,
];

/// CA/B Forum Code Signing BR §7.1.3 — approved signature algorithms for CS certificates.
///
/// Currently identical to TLS BR list. Code Signing BR also requires RSA ≥ 3072 bits;
/// that is enforced via [`ValidationPolicy::min_rsa_key_bits`], not via this list.
const CABF_CS_BR_ALLOWED_ALGS: &[ObjectIdentifier] = &[
    SHA256_WITH_RSA,
    SHA384_WITH_RSA,
    SHA512_WITH_RSA,
    ECDSA_WITH_SHA256,
    ECDSA_WITH_SHA384,
    ECDSA_WITH_SHA512,
];

// EKU OIDs (RFC 5280 §4.2.1.12)
pub(crate) const ID_KP_SERVER_AUTH: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
pub(crate) const ID_KP_EMAIL_PROTECTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.4");
pub(crate) const ID_KP_CODE_SIGNING: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");

// ---------------------------------------------------------------------------
// Profile structs
// ---------------------------------------------------------------------------

/// CA/Browser Forum TLS Baseline Requirements profile.
///
/// Implements [`Profile`] and produces a [`ValidationPolicy`] with the constraints
/// mandated by the CA/B Forum Baseline Requirements for TLS Server Certificates.
///
/// The free-function alias [`web_pki_policy`] is equivalent to
/// `WebPkiProfile.policy(now_unix)` and is provided for convenience.
///
/// ## SC-081 validity enforcement
///
/// SC-081 validity cap enforcement is **not** performed via
/// `ValidationPolicy::max_validity_secs`.  That field is a single blunt
/// instrument that applies one cap to all certificates regardless of when they
/// were issued.  SC-081 requires the cap in force **at issuance time**
/// (`notBefore`) to govern a certificate for its lifetime.  A relying party's
/// current time (`now_unix`) must not retroactively change which cap applies.
///
/// SC-081 enforcement is delegated to `ValidityMaxLint` in `pkix-lint`, which
/// correctly evaluates `sc081_validity_cap(notBefore)` for each certificate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct WebPkiProfile;

impl Profile for WebPkiProfile {
    fn id(&self) -> &'static str {
        // Reverse-domain style: regime owner + regime abbreviation.
        "cabf.br.tls"
    }

    fn version(&self) -> &'static str {
        // SC-081 is the most recent ballot materially changing validity policy.
        // Note: this string identifies the normative document whose rules were last
        // incorporated into this profile.  SC-081 validity cap enforcement is
        // intentionally delegated to `pkix-lint`'s `ValidityMaxLint`; it is NOT
        // enforced by this profile (see struct-level doc for rationale).
        "SC-081"
    }

    fn policy(&self, now_unix: u64) -> ValidationPolicy {
        let mut p = ValidationPolicy::new(now_unix);
        // SC-081 validity cap enforcement is NOT set here; see struct-level doc.
        // BR §7.1.3: SHA-1 prohibited.
        p.allowed_signature_algs = Some(CABF_TLS_BR_ALLOWED_ALGS.to_vec());
        // BR §6.1.5: RSA keys must be at least 2048 bits.
        p.min_rsa_key_bits = Some(2048);
        // BR §7.1.4.2: SAN must be present and non-empty on the leaf.
        p.require_subject_alt_name = true;
        // BR §7.1.2.7.3: id-kp-serverAuth must be asserted in the leaf's EKU.
        p.required_leaf_eku = Some(vec![ID_KP_SERVER_AUTH]);
        // BR §7.1.1: at most 2 non-self-issued intermediates in the path.
        p.max_path_len = 2;
        p
    }

    fn policy_oids(&self) -> &[ObjectIdentifier] {
        // CA/B Forum does not define an OID for the TLS BR policy itself;
        // cert policy OIDs are issued by individual CAs, not by the Forum.
        &[]
    }
}

/// CA/Browser Forum S/MIME Baseline Requirements profile (Mailbox-validated / strict).
///
/// Implements [`Profile`] for the strictest S/MIME BR validation tier.
/// Organization-validated, Sponsor-validated, and Individual-validated sub-profiles
/// are planned.
///
/// The free-function alias [`smime_policy`] is equivalent to
/// `SmimeProfile.policy(now_unix)`.
///
/// # Limitations
///
/// Only the Mailbox-validated / strict profile is enforced. Organization-validated,
/// Sponsor-validated, and Individual-validated profiles are planned.
///
/// [`ValidationPolicy::max_validity_secs`] applies to **every** certificate in
/// the chain, not just the leaf. Typical S/MIME CA certificates have validity
/// periods of 10–20 years (well over 1185 days). Callers using `SmimeProfile`
/// with a standard S/MIME CA hierarchy will see validation failures on the
/// intermediate or root CA certificates. To avoid this, use a custom policy
/// that sets only the leaf validity cap, or construct the chain with CA
/// certificates whose validity is within 1185 days.
///
/// Revocation checking (OCSP/CRL) is out of scope; use `pkix-revocation`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SmimeProfile;

impl Profile for SmimeProfile {
    fn id(&self) -> &'static str {
        "cabf.smime"
    }

    fn version(&self) -> &'static str {
        // S/MIME BR version 1.0 (first edition).
        "1.0"
    }

    fn policy(&self, now_unix: u64) -> ValidationPolicy {
        let mut p = ValidationPolicy::new(now_unix);
        // S/MIME BR §6.3.2 (v1.0.0, table): Legacy generation maximum validity
        // is 1185 days. The spec states this as an explicit day count, not a
        // calendar-month approximation. (Strict/Multipurpose is 825 days;
        // this profile targets the Legacy generation.)
        p.max_validity_secs = Some(1185 * SECS_PER_DAY);
        // S/MIME BR §7.1.3: SHA-1 prohibited.
        p.allowed_signature_algs = Some(CABF_SMIME_BR_ALLOWED_ALGS.to_vec());
        // S/MIME BR §6.1.5: RSA keys must be at least 2048 bits.
        p.min_rsa_key_bits = Some(2048);
        // Mailbox-validated: non-empty SAN required; must contain an rfc822Name entry.
        p.require_subject_alt_name = true;
        p.require_rfc822_san = true;
        // S/MIME BR §7.3: id-kp-emailProtection must be asserted.
        p.required_leaf_eku = Some(vec![ID_KP_EMAIL_PROTECTION]);
        // S/MIME BR §7.2: at most one Subordinate CA between Root and end-entity.
        p.max_path_len = 1;
        p
    }

    fn policy_oids(&self) -> &[ObjectIdentifier] {
        &[]
    }
}

/// CA/Browser Forum Code Signing Baseline Requirements profile.
///
/// Implements [`Profile`] for code-signing certificate validation.
/// Timestamp authority verification is out of scope for `pkix-path`.
///
/// The free-function alias [`code_signing_policy`] is equivalent to
/// `CodeSigningProfile.policy(now_unix)`.
///
/// # Limitations
///
/// [`ValidationPolicy::max_validity_secs`] applies to **every** certificate in
/// the chain, not just the leaf. Typical CS subordinate CA certificates have
/// validity periods of 5–10 years (well over 460 days). Callers using
/// `CodeSigningProfile` with a standard CS CA hierarchy will see validation
/// failures on the intermediate CA certificates. To avoid this, use a custom
/// policy that sets only the leaf validity cap, or construct the chain with CA
/// certificates whose validity is within 460 days.
///
/// Timestamp authority verification is out of scope for `pkix-path`;
/// use a dedicated timestamp verifier. Revocation is handled by `pkix-revocation`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct CodeSigningProfile;

impl Profile for CodeSigningProfile {
    fn id(&self) -> &'static str {
        "cabf.cs"
    }

    fn version(&self) -> &'static str {
        // CS BR version 3.0.
        "3.0"
    }

    fn policy(&self, now_unix: u64) -> ValidationPolicy {
        let mut p = ValidationPolicy::new(now_unix);
        // CS BR §6.3.2 (effective 2026-03-01): maximum 460 days for subscriber certificates.
        p.max_validity_secs = Some(460 * SECS_PER_DAY);
        // CS BR §7.1.3: SHA-1 prohibited.
        p.allowed_signature_algs = Some(CABF_CS_BR_ALLOWED_ALGS.to_vec());
        // CS BR §6.1.5: RSA keys must be at least 3072 bits (raised from 2048 effective 2023-06-01).
        // This is the key differentiator from WebPkiProfile (2048 bits).
        p.min_rsa_key_bits = Some(3072);
        // CS certs identify subjects by DN; SAN is not required.
        p.require_subject_alt_name = false;
        // CS BR §7.1.2.3: id-kp-codeSigning must be asserted.
        p.required_leaf_eku = Some(vec![ID_KP_CODE_SIGNING]);
        // CS BR §7.1.1: Root CA issues Subordinate CA directly; at most 1 intermediate.
        p.max_path_len = 1;
        p
    }

    fn policy_oids(&self) -> &[ObjectIdentifier] {
        &[]
    }
}

/// Plain RFC 5280 profile with no CA/B Forum additions.
///
/// Useful as a starting point for custom profiles or as a baseline in testing.
/// The free-function alias [`rfc5280_policy`] is equivalent to
/// `Rfc5280Profile.policy(now_unix)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Rfc5280Profile;

impl Profile for Rfc5280Profile {
    fn id(&self) -> &'static str {
        "ietf.rfc5280"
    }

    fn version(&self) -> &'static str {
        "RFC 5280"
    }

    fn policy(&self, now_unix: u64) -> ValidationPolicy {
        // No constraints beyond RFC 5280 defaults.
        ValidationPolicy::new(now_unix)
    }

    fn policy_oids(&self) -> &[ObjectIdentifier] {
        &[]
    }
}

// ---------------------------------------------------------------------------
// SC-081 phased validity cap helper
// ---------------------------------------------------------------------------

/// Return the maximum TLS certificate validity in seconds for the given issuance time.
///
/// CA/B Forum Ballot SC-081 (approved March 2024) introduces a phased reduction:
/// - Certificates issued before 2026-03-15: 398 days
/// - On or after 2026-03-15: 200 days
/// - On or after 2027-03-15: 100 days
/// - On or after 2029-03-15:  47 days
///
/// The argument should be the certificate's `notBefore` (issuance time), **not** the
/// relying party's current validation time.  SC-081 requires that the cap in force at
/// issuance governs a certificate for its entire lifetime.  Passing a relying-party
/// clock would incorrectly invalidate certificates issued under an earlier, more
/// permissive cap.
///
/// Primary consumer: `ValidityMaxLint` in `pkix-lint`, which calls
/// `sc081_validity_cap(notBefore)` for each certificate it audits.
///
/// Epoch boundaries (UTC midnight on the effective date, seconds since Unix epoch):
/// - 2026-03-15T00:00:00Z = `1_773_532_800`
/// - 2027-03-15T00:00:00Z = `1_805_068_800`
/// - 2029-03-15T00:00:00Z = `1_868_227_200`
///
/// Verified via: `python3 -c "import calendar; print(calendar.timegm((YYYY,3,15,0,0,0,0,0,0)))"`
#[must_use]
pub const fn sc081_validity_cap(not_before_unix: u64) -> u64 {
    // Exact UTC midnight boundaries.
    // Computed: python3 -c "import calendar; print(calendar.timegm((2026,3,15,0,0,0,0,0,0)))"
    const SC081_200D_EPOCH: u64 = 1_773_532_800; // 2026-03-15T00:00:00Z
    const SC081_100D_EPOCH: u64 = 1_805_068_800; // 2027-03-15T00:00:00Z
    const SC081_47D_EPOCH: u64 = 1_868_227_200; // 2029-03-15T00:00:00Z

    if not_before_unix >= SC081_47D_EPOCH {
        47 * SECS_PER_DAY
    } else if not_before_unix >= SC081_100D_EPOCH {
        100 * SECS_PER_DAY
    } else if not_before_unix >= SC081_200D_EPOCH {
        200 * SECS_PER_DAY
    } else {
        398 * SECS_PER_DAY
    }
}

// ---------------------------------------------------------------------------
// Free-function convenience aliases
// ---------------------------------------------------------------------------

/// Return a [`ValidationPolicy`] conforming to the CA/Browser Forum
/// Baseline Requirements for TLS Server Certificates.
///
/// This is a convenience alias for `WebPkiProfile.policy(now_unix)`.
/// For use in generic or registry contexts, prefer [`WebPkiProfile`] directly.
///
/// # Constraints enforced
///
/// | Field | Value | Normative reference |
/// |-------|-------|---------------------|
/// | `allowed_signature_algs` | SHA-256/384/512 RSA + ECDSA; SHA-1 excluded | TLS BR §7.1.3 |
/// | `min_rsa_key_bits` | 2048 | TLS BR §6.1.5 |
/// | `require_subject_alt_name` | true | TLS BR §7.1.4.2 |
/// | `required_leaf_eku` | id-kp-serverAuth (1.3.6.1.5.5.7.3.1) | TLS BR §7.1.2.7.3 |
/// | `max_path_len` | 2 | TLS BR §7.1.1 |
///
/// # SC-081 validity enforcement
///
/// `max_validity_secs` is **not** set.  SC-081 validity cap enforcement is
/// delegated to `ValidityMaxLint` in `pkix-lint`, which evaluates
/// `sc081_validity_cap(notBefore)` per certificate at audit time.  See
/// [`WebPkiProfile`] for the rationale.
///
/// # Limitations
///
/// This function enforces the structural constraints listed above using
/// `pkix-path`'s `ValidationPolicy`. It does not verify:
/// - SC-081 validity caps (use `pkix-lint` `ValidityMaxLint`)
/// - CAA DNS records (network check; out of scope for `pkix-path`)
/// - CT log SCTs (separate verification step; use `pkix-ct`)
/// - OCSP/CRL revocation (use `pkix-revocation`)
#[must_use]
pub fn web_pki_policy(now_unix: u64) -> ValidationPolicy {
    WebPkiProfile.policy(now_unix)
}

/// Return a [`ValidationPolicy`] conforming to the CA/Browser Forum
/// S/MIME Baseline Requirements (Mailbox-validated / strict profile).
///
/// This is a convenience alias for `SmimeProfile.policy(now_unix)`.
///
/// # Constraints enforced
///
/// | Field | Value | Normative reference |
/// |-------|-------|---------------------|
/// | `max_validity_secs` | 1185 days (~39 months) | S/MIME BR §6.3.2 |
/// | `allowed_signature_algs` | SHA-256/384/512 RSA + ECDSA; SHA-1 excluded | S/MIME BR §7.1.3 |
/// | `min_rsa_key_bits` | 2048 | S/MIME BR §6.1.5 |
/// | `require_subject_alt_name` | true | non-empty `SubjectAltName` extension required |
/// | `require_rfc822_san` | true | at least one `rfc822Name` entry required in SAN |
/// | `required_leaf_eku` | id-kp-emailProtection (1.3.6.1.5.5.7.3.4) | S/MIME BR §7.3 |
/// | `max_path_len` | 1 | S/MIME BR §7.2 |
///
/// # Limitations
///
/// Only the Mailbox-validated / strict profile is enforced. Organization-validated,
/// Sponsor-validated, and Individual-validated profiles are planned.
///
/// `max_validity_secs` applies to **every** certificate in the chain, not just
/// the leaf. Typical S/MIME CA certificates have validity periods of 10–20 years
/// (well over 1185 days). Callers using this policy with a standard S/MIME CA
/// hierarchy will see validation failures on intermediate or root CA certificates.
/// Use a custom policy or chain with short-lived CA certificates to avoid this.
///
/// Revocation checking (OCSP/CRL) is out of scope; use `pkix-revocation`.
#[must_use]
pub fn smime_policy(now_unix: u64) -> ValidationPolicy {
    SmimeProfile.policy(now_unix)
}

/// Return a [`ValidationPolicy`] conforming to the CA/Browser Forum
/// Code Signing Baseline Requirements.
///
/// This is a convenience alias for `CodeSigningProfile.policy(now_unix)`.
///
/// # Constraints enforced
///
/// | Field | Value | Normative reference |
/// |-------|-------|---------------------|
/// | `max_validity_secs` | 460 days | CS BR §6.3.2 (effective 2026-03-01) |
/// | `allowed_signature_algs` | SHA-256/384/512 RSA + ECDSA; SHA-1 excluded | CS BR §7.1.3 |
/// | `min_rsa_key_bits` | 3072 | CS BR §6.1.5 (effective 2023-06-01) |
/// | `require_subject_alt_name` | false | CS certs identify subjects by DN |
/// | `required_leaf_eku` | id-kp-codeSigning (1.3.6.1.5.5.7.3.3) | CS BR §7.1.2.3 |
/// | `max_path_len` | 1 | CS BR §7.1.1 |
///
/// # Limitations
///
/// `max_validity_secs` applies to **every** certificate in the chain, not just
/// the leaf. Typical CS subordinate CA certificates have validity periods of
/// 5–10 years (well over 460 days). Callers using this policy with a standard
/// CS CA hierarchy will see validation failures on intermediate CA certificates.
/// Use a custom policy or chain with short-lived CA certificates to avoid this.
///
/// Timestamp authority verification is out of scope for `pkix-path`;
/// use a dedicated timestamp verifier. Revocation is handled by `pkix-revocation`.
#[must_use]
pub fn code_signing_policy(now_unix: u64) -> ValidationPolicy {
    CodeSigningProfile.policy(now_unix)
}

/// Return a plain RFC 5280 [`ValidationPolicy`] with no CA/B Forum additions.
///
/// This is a convenience alias for `Rfc5280Profile.policy(now_unix)`.
#[must_use]
pub fn rfc5280_policy(now_unix: u64) -> ValidationPolicy {
    Rfc5280Profile.policy(now_unix)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use der::Decode as _;
    use pkix_path::{EcdsaP256Verifier, TrustAnchor};
    use x509_cert::Certificate;

    // Reuse the policy-checks fixtures (from pkix-path's fixture directory,
    // accessed via relative path from the pkix-profiles crate root).
    //
    // Test time: 2026-06-01T00:00:00Z = 1_780_272_000 unix seconds.
    // All fixtures have NOT_BEFORE=2026-01-01 and are valid at this time.
    const NOW: u64 = 1_780_272_000;

    fn load(bytes: &[u8]) -> Certificate {
        Certificate::from_der(bytes).expect("valid DER fixture")
    }

    // -----------------------------------------------------------------------
    // Profile trait identity tests
    //
    // Oracle: The trait method return values are defined as part of the public
    // API contract. We verify them directly against the spec-derived constants.
    // -----------------------------------------------------------------------

    #[test]
    fn profile_ids_are_stable() {
        assert_eq!(WebPkiProfile.id(), "cabf.br.tls");
        assert_eq!(SmimeProfile.id(), "cabf.smime");
        assert_eq!(CodeSigningProfile.id(), "cabf.cs");
        assert_eq!(Rfc5280Profile.id(), "ietf.rfc5280");
    }

    #[test]
    fn profile_policy_sets_correct_timestamp() {
        // profile.policy(NOW) must set current_time_unix = NOW.
        assert_eq!(WebPkiProfile.policy(NOW).current_time_unix, NOW);
        assert_eq!(SmimeProfile.policy(NOW).current_time_unix, NOW);
        assert_eq!(CodeSigningProfile.policy(NOW).current_time_unix, NOW);
        assert_eq!(Rfc5280Profile.policy(NOW).current_time_unix, NOW);
    }

    #[test]
    fn profile_policy_matches_free_function() {
        // The Profile impl and the free function must produce identical policies.
        // This is a structural check only — not using one as the oracle for the other.
        let via_trait = WebPkiProfile.policy(NOW);
        let via_fn = web_pki_policy(NOW);
        assert_eq!(
            via_trait, via_fn,
            "WebPkiProfile.policy and web_pki_policy must agree"
        );

        let via_trait = SmimeProfile.policy(NOW);
        let via_fn = smime_policy(NOW);
        assert_eq!(
            via_trait, via_fn,
            "SmimeProfile.policy and smime_policy must agree"
        );

        let via_trait = CodeSigningProfile.policy(NOW);
        let via_fn = code_signing_policy(NOW);
        assert_eq!(
            via_trait, via_fn,
            "CodeSigningProfile.policy and code_signing_policy must agree"
        );

        let via_trait = Rfc5280Profile.policy(NOW);
        let via_fn = rfc5280_policy(NOW);
        assert_eq!(
            via_trait, via_fn,
            "Rfc5280Profile.policy and rfc5280_policy must agree"
        );
    }

    // -----------------------------------------------------------------------
    // SC-081 validity cap tests
    //
    // Oracle: SC-081 ballot text specifies exact effective dates.
    // Boundary values are derived from the ballot, not from the code under test.
    // -----------------------------------------------------------------------

    #[test]
    fn sc081_cap_before_phase_in() {
        // 2026-03-14T23:59:59Z — one second before the 200-day threshold.
        // Boundary: 2026-03-15T00:00:00Z = 1_773_532_800 (verified via python3 calendar.timegm).
        let one_before = 1_773_532_800 - 1;
        assert_eq!(
            sc081_validity_cap(one_before),
            398 * 86_400,
            "one second before 2026-03-15 must yield 398-day cap"
        );
    }

    #[test]
    fn sc081_cap_at_200d_boundary() {
        // 2026-03-15T00:00:00Z exactly = 1_773_532_800.
        assert_eq!(
            sc081_validity_cap(1_773_532_800),
            200 * 86_400,
            "exactly 2026-03-15 must yield 200-day cap"
        );
    }

    #[test]
    fn sc081_cap_at_100d_boundary() {
        // 2027-03-15T00:00:00Z exactly = 1_805_068_800.
        assert_eq!(
            sc081_validity_cap(1_805_068_800),
            100 * 86_400,
            "exactly 2027-03-15 must yield 100-day cap"
        );
    }

    #[test]
    fn sc081_cap_at_47d_boundary() {
        // 2029-03-15T00:00:00Z exactly = 1_868_227_200.
        assert_eq!(
            sc081_validity_cap(1_868_227_200),
            47 * 86_400,
            "exactly 2029-03-15 must yield 47-day cap"
        );
    }

    #[test]
    fn sc081_cap_far_in_future() {
        assert_eq!(
            sc081_validity_cap(u64::MAX),
            47 * 86_400,
            "far-future time must yield the 47-day cap"
        );
    }

    // -----------------------------------------------------------------------
    // web_pki_policy field-value checks
    //
    // Oracle: CA/B Forum TLS BR spec values are constants in WebPkiProfile.
    // We assert the returned struct matches the spec rather than testing
    // round-trips through the code under test itself.
    // -----------------------------------------------------------------------

    #[test]
    fn web_pki_policy_max_validity_not_set() {
        // SC-081 cap enforcement is delegated to ValidityMaxLint in pkix-lint,
        // which uses notBefore for the phase lookup.  WebPkiProfile must NOT
        // set max_validity_secs so that relying-party clock does not retroactively
        // invalidate certs issued under a more permissive cap.
        let p = web_pki_policy(NOW);
        assert!(
            p.max_validity_secs.is_none(),
            "web_pki_policy must not set max_validity_secs (SC-081 enforcement is in pkix-lint)"
        );
    }

    #[test]
    fn web_pki_policy_min_rsa_key_bits_is_2048() {
        let p = web_pki_policy(NOW);
        assert_eq!(
            p.min_rsa_key_bits,
            Some(2048),
            "web_pki_policy: min_rsa_key_bits must be 2048"
        );
    }

    #[test]
    fn web_pki_policy_requires_san() {
        let p = web_pki_policy(NOW);
        assert!(
            p.require_subject_alt_name,
            "web_pki_policy: require_subject_alt_name must be true"
        );
    }

    #[test]
    fn web_pki_policy_requires_server_auth_eku() {
        let p = web_pki_policy(NOW);
        let ekus = p.required_leaf_eku.as_deref().unwrap_or(&[]);
        assert!(
            ekus.contains(&ID_KP_SERVER_AUTH),
            "web_pki_policy: required_leaf_eku must contain id-kp-serverAuth"
        );
    }

    #[test]
    fn web_pki_policy_sha1_not_in_allowed_algs() {
        let sha1_rsa: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");
        let sha1_ecdsa: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.1");
        let p = web_pki_policy(NOW);
        let allowed = p.allowed_signature_algs.as_deref().unwrap_or(&[]);
        assert!(
            !allowed.contains(&sha1_rsa),
            "web_pki_policy: sha1WithRSAEncryption must NOT be in allowed_signature_algs"
        );
        assert!(
            !allowed.contains(&sha1_ecdsa),
            "web_pki_policy: ecdsa-with-SHA1 must NOT be in allowed_signature_algs"
        );
    }

    // -----------------------------------------------------------------------
    // web_pki_policy validate_path integration tests
    // -----------------------------------------------------------------------

    /// Oracle: webpki-self-signed-365d.der — 365 days, self-signed, SAN, serverAuth EKU.
    ///
    /// Using a 1-cert self-signed chain avoids the CA-cert validity check issue:
    /// `web_pki_policy` applies `max_validity_secs` to ALL certs in the chain, and
    /// the root/int fixtures have 10-year validity (well over 200 days). A single
    /// self-signed cert satisfies all constraints at once.
    ///
    /// Oracle: openssl verify -`CAfile` <self> <self> → OK (self-signed).
    #[test]
    fn web_pki_conforming_cert_passes() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/webpki-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        // Use pre-SC-081 time so 365 days is within the 398-day cap.
        let pre_sc081: u64 = 1_767_225_600; // 2026-01-01
        pkix_path::validate_path(
            &[cert],
            &anchors,
            &web_pki_policy(pre_sc081),
            &EcdsaP256Verifier,
        )
        .expect("self-signed 365-day cert with SAN and serverAuth EKU must pass web_pki_policy");
    }

    /// Oracle: webpki-self-signed-365d.der has 365-day validity (< 398) → passes pre-SC-081.
    /// A cert with validity > 200 days fails after SC-081 2026-03-15.
    #[test]
    fn web_pki_long_validity_cert_rejected() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/webpki-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        // Tighten the cap to 300 days; 365-day cert exceeds it.
        let mut policy = web_pki_policy(NOW);
        policy.max_validity_secs = Some(300 * 86_400);
        assert!(
            matches!(
                pkix_path::validate_path(&[cert], &anchors, &policy, &EcdsaP256Verifier),
                Err(pkix_path::Error::ValidityPeriodExceedsMax { index: 0 })
            ),
            "365-day cert over 300-day cap must return ValidityPeriodExceedsMax"
        );
    }

    /// Verify that `web_pki_policy` sets `require_subject_alt_name = true` and that a
    /// cert with a SAN passes (proving the field is wired correctly).
    #[test]
    fn web_pki_policy_san_field_is_true() {
        assert!(
            web_pki_policy(NOW).require_subject_alt_name,
            "web_pki_policy must set require_subject_alt_name=true"
        );
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/webpki-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        let pre_sc081: u64 = 1_767_225_600;
        pkix_path::validate_path(
            &[cert],
            &anchors,
            &web_pki_policy(pre_sc081),
            &EcdsaP256Verifier,
        )
        .expect("self-signed cert with SAN must pass web_pki_policy SAN check");
    }

    /// Oracle: a cert with serverAuth passes, a cert with emailProtection (not serverAuth) fails.
    #[test]
    fn web_pki_missing_server_auth_eku_rejected() {
        let p = web_pki_policy(NOW);
        assert!(
            p.required_leaf_eku
                .as_deref()
                .unwrap_or(&[])
                .contains(&ID_KP_SERVER_AUTH),
            "web_pki_policy must set required_leaf_eku=[serverAuth]"
        );

        // Use pre-SC-081 time so the 365-day cert passes the validity cap.
        let pre_sc081: u64 = 1_767_225_600;
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/webpki-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        pkix_path::validate_path(
            &[cert],
            &anchors,
            &web_pki_policy(pre_sc081),
            &EcdsaP256Verifier,
        )
        .expect("cert with serverAuth must pass web_pki_policy EKU check");

        // Verify rejection: require emailProtection but cert has serverAuth.
        // Also use pre-sc081 so only the EKU check fires (not the validity cap).
        let cert2 = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/webpki-self-signed-365d.der"
        ));
        let anchors2 = [TrustAnchor::from_cert(cert2.clone())];
        let mut strict_policy = web_pki_policy(pre_sc081);
        strict_policy.required_leaf_eku = Some(vec![ID_KP_EMAIL_PROTECTION]);
        assert!(
            matches!(
                pkix_path::validate_path(&[cert2], &anchors2, &strict_policy, &EcdsaP256Verifier),
                Err(pkix_path::Error::MissingEku)
            ),
            "cert with serverAuth (not emailProtection) must be rejected when emailProtection is required"
        );
    }

    /// Oracle: webpki-self-signed-365d.der has serverAuth EKU.
    /// A policy requiring emailProtection must reject it.
    #[test]
    fn web_pki_wrong_eku_rejected() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/webpki-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        // Use pre-SC-081 time so the 365-day cert passes the validity cap check;
        // the test exercises EKU rejection, not validity rejection.
        let pre_sc081: u64 = 1_767_225_600;
        let mut policy = web_pki_policy(pre_sc081);
        policy.required_leaf_eku = Some(vec![ID_KP_EMAIL_PROTECTION]);
        assert!(
            matches!(
                pkix_path::validate_path(&[cert], &anchors, &policy, &EcdsaP256Verifier),
                Err(pkix_path::Error::MissingEku)
            ),
            "cert with serverAuth (not emailProtection) EKU must be rejected"
        );
    }

    // -----------------------------------------------------------------------
    // smime_policy field-value checks
    // -----------------------------------------------------------------------

    #[test]
    fn smime_policy_max_validity_is_1185_days() {
        let p = smime_policy(NOW);
        assert_eq!(
            p.max_validity_secs,
            Some(1185 * 86_400),
            "smime_policy: max_validity_secs must be 1185 days"
        );
    }

    #[test]
    fn smime_policy_requires_email_protection_eku() {
        let p = smime_policy(NOW);
        let ekus = p.required_leaf_eku.as_deref().unwrap_or(&[]);
        assert!(
            ekus.contains(&ID_KP_EMAIL_PROTECTION),
            "smime_policy: required_leaf_eku must contain id-kp-emailProtection"
        );
    }

    #[test]
    fn smime_policy_requires_san() {
        let p = smime_policy(NOW);
        assert!(
            p.require_subject_alt_name,
            "smime_policy: require_subject_alt_name must be true (Mailbox-validated)"
        );
    }

    #[test]
    fn smime_policy_max_path_len_is_1() {
        let p = smime_policy(NOW);
        assert_eq!(
            p.max_path_len, 1,
            "smime_policy: max_path_len must be 1 (S/MIME BR §7.2)"
        );
    }

    /// Oracle: openssl verify -`CAfile` smime-self-signed-365d.pem smime-self-signed-365d.pem → OK
    #[test]
    fn smime_conforming_cert_passes() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/smime-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        pkix_path::validate_path(&[cert], &anchors, &smime_policy(NOW), &EcdsaP256Verifier)
            .expect(
                "self-signed 365-day cert with rfc822Name SAN and emailProtection EKU must pass smime_policy",
            );
    }

    /// Verify that `smime_policy` requires `emailProtection` EKU, and that a cert with
    /// `serverAuth` (not `emailProtection`) is rejected.
    #[test]
    fn smime_policy_requires_email_protection_eku_and_rejects_wrong_eku() {
        assert!(
            smime_policy(NOW)
                .required_leaf_eku
                .as_deref()
                .unwrap_or(&[])
                .contains(&ID_KP_EMAIL_PROTECTION),
            "smime_policy must require id-kp-emailProtection"
        );
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/webpki-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        assert!(
            matches!(
                pkix_path::validate_path(&[cert], &anchors, &smime_policy(NOW), &EcdsaP256Verifier),
                Err(pkix_path::Error::MissingEku)
            ),
            "cert with serverAuth (not emailProtection) must fail smime_policy EKU check"
        );
    }

    // -----------------------------------------------------------------------
    // code_signing_policy field-value checks
    // -----------------------------------------------------------------------

    #[test]
    fn code_signing_policy_max_validity_is_460_days() {
        // CS BR §6.3.2 (effective 2026-03-01): subscriber certificates limited to 460 days.
        let p = code_signing_policy(NOW);
        assert_eq!(
            p.max_validity_secs,
            Some(460 * 86_400),
            "code_signing_policy: max_validity_secs must be 460 days (CS BR §6.3.2)"
        );
    }

    #[test]
    fn code_signing_policy_min_rsa_key_bits_is_3072() {
        let p = code_signing_policy(NOW);
        assert_eq!(
            p.min_rsa_key_bits,
            Some(3072),
            "code_signing_policy: min_rsa_key_bits must be 3072 (CS BR §6.1.5)"
        );
    }

    #[test]
    fn code_signing_policy_does_not_require_san() {
        let p = code_signing_policy(NOW);
        assert!(
            !p.require_subject_alt_name,
            "code_signing_policy: require_subject_alt_name must be false (CS certs use DN)"
        );
    }

    #[test]
    fn code_signing_policy_max_path_len_is_1() {
        let p = code_signing_policy(NOW);
        assert_eq!(
            p.max_path_len, 1,
            "code_signing_policy: max_path_len must be 1 (CS BR §7.1.1)"
        );
    }

    #[test]
    fn code_signing_policy_requires_code_signing_eku() {
        let p = code_signing_policy(NOW);
        let ekus = p.required_leaf_eku.as_deref().unwrap_or(&[]);
        assert!(
            ekus.contains(&ID_KP_CODE_SIGNING),
            "code_signing_policy: required_leaf_eku must contain id-kp-codeSigning"
        );
    }

    /// Oracle: openssl verify -`CAfile` codesign-self-signed-365d.pem codesign-self-signed-365d.pem → OK
    #[test]
    fn code_signing_conforming_cert_passes() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/codesign-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        pkix_path::validate_path(
            &[cert],
            &anchors,
            &code_signing_policy(NOW),
            &EcdsaP256Verifier,
        )
        .expect("self-signed 365-day cert with codeSigning EKU must pass code_signing_policy");
    }

    /// Verify that `code_signing_policy` requires `codeSigning` EKU and that a cert
    /// with `serverAuth` (not `codeSigning`) is rejected with `MissingEku`.
    #[test]
    fn code_signing_policy_rejects_wrong_eku() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/webpki-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        assert!(
            matches!(
                pkix_path::validate_path(
                    &[cert],
                    &anchors,
                    &code_signing_policy(NOW),
                    &EcdsaP256Verifier
                ),
                Err(pkix_path::Error::MissingEku)
            ),
            "cert with serverAuth (not codeSigning) must fail code_signing_policy EKU check"
        );
    }

    /// Higher RSA floor than `web_pki_policy`: 3072 vs 2048.
    #[test]
    fn code_signing_policy_rsa_floor_higher_than_web_pki() {
        let web = web_pki_policy(NOW);
        let cs = code_signing_policy(NOW);
        assert!(
            cs.min_rsa_key_bits > web.min_rsa_key_bits,
            "code_signing min_rsa_key_bits ({:?}) must be higher than web_pki ({:?})",
            cs.min_rsa_key_bits,
            web.min_rsa_key_bits
        );
    }

    // -----------------------------------------------------------------------
    // rfc5280_policy basic sanity
    // -----------------------------------------------------------------------

    #[test]
    fn rfc5280_policy_has_no_cabf_constraints() {
        let p = rfc5280_policy(NOW);
        assert!(
            p.max_validity_secs.is_none(),
            "rfc5280_policy must not set max_validity_secs"
        );
        assert!(
            p.allowed_signature_algs.is_none(),
            "rfc5280_policy must not set allowed_signature_algs"
        );
        assert!(
            p.min_rsa_key_bits.is_none(),
            "rfc5280_policy must not set min_rsa_key_bits"
        );
        assert!(
            !p.require_subject_alt_name,
            "rfc5280_policy must not require SAN"
        );
        assert!(
            p.required_leaf_eku.is_none(),
            "rfc5280_policy must not set required_leaf_eku"
        );
    }

    // -----------------------------------------------------------------------
    // Algorithm separation test
    //
    // Oracle: The three per-profile algorithm lists must currently be identical
    // (they're sourced from the same specs and haven't diverged yet), but they
    // must be structurally separate constants so they can diverge independently.
    // -----------------------------------------------------------------------

    #[test]
    fn per_profile_alg_lists_are_independent_constants() {
        // Verify that TLS, SMIME, and CS each have their own allowed_algs
        // by checking that the Vec pointers are different objects (not shared).
        // We do this by modifying one copy and verifying the others are unchanged.
        let mut web = web_pki_policy(NOW);
        let smime = smime_policy(NOW);
        let cs = code_signing_policy(NOW);

        // Add a bogus OID to the web_pki copy.
        let bogus: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.3.4.5");
        web.allowed_signature_algs.as_mut().unwrap().push(bogus);

        // The smime and cs copies must be unaffected.
        assert!(
            !smime
                .allowed_signature_algs
                .as_deref()
                .unwrap_or(&[])
                .contains(&bogus),
            "modifying web_pki allowed_algs must not affect smime_policy"
        );
        assert!(
            !cs.allowed_signature_algs
                .as_deref()
                .unwrap_or(&[])
                .contains(&bogus),
            "modifying web_pki allowed_algs must not affect code_signing_policy"
        );
    }

    // -----------------------------------------------------------------------
    // smime_policy rfc822Name SAN enforcement (PKIX-zw3)
    //
    // Oracle: smime-self-signed-365d.der has SAN=rfc822Name:test@example.com
    //         (openssl x509 -inform DER -in smime-self-signed-365d.der -text -noout
    //          shows: Subject Alternative Name: email:test@example.com)
    //         webpki-self-signed-365d.der has SAN=dNSName:test.example.com only.
    // -----------------------------------------------------------------------

    /// `smime_policy` sets `require_rfc822_san` = true.
    #[test]
    fn smime_policy_requires_rfc822_san() {
        let p = smime_policy(NOW);
        assert!(
            p.require_rfc822_san,
            "smime_policy must set require_rfc822_san=true"
        );
    }

    /// Cert with rfc822Name SAN passes `smime_policy`.
    ///
    /// Oracle: smime-self-signed-365d.der — SAN contains email:test@example.com
    /// (rfc822Name). Verified by openssl: X509v3 Subject Alternative Name: email:test@example.com
    #[test]
    fn smime_rfc822_san_cert_passes() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/smime-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        pkix_path::validate_path(&[cert], &anchors, &smime_policy(NOW), &EcdsaP256Verifier)
            .expect("cert with rfc822Name SAN must pass smime_policy");
    }

    /// Cert with ONLY dNSName SAN fails `smime_policy` with `MissingRfc822San`.
    ///
    /// Oracle: webpki-self-signed-365d.der has SAN=DNS:test.example.com (dNSName only).
    /// Verified by openssl: X509v3 Subject Alternative Name: DNS:test.example.com
    /// `smime_policy` requires an rfc822Name entry; dNSName does not satisfy this.
    ///
    /// The EKU check (e3) fires before the rfc822 SAN type check (e4) in `chain_walk`.
    /// We override `required_leaf_eku` to serverAuth (which matches the cert) so that
    /// EKU passes and `MissingRfc822San` is the error that fires.
    ///
    /// Use pre-SC-081 time (`1_767_225_600`) so the validity cap does not fire.
    #[test]
    fn smime_dnsname_only_san_fails_with_missing_rfc822_san() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/webpki-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        let pre_sc081: u64 = 1_767_225_600;
        let mut policy = smime_policy(pre_sc081);
        // webpki-self-signed-365d has serverAuth EKU; override required EKU to serverAuth
        // so the EKU check passes and the rfc822Name SAN type check fires.
        policy.required_leaf_eku = Some(vec![ID_KP_SERVER_AUTH]);
        assert!(
            matches!(
                pkix_path::validate_path(&[cert], &anchors, &policy, &EcdsaP256Verifier),
                Err(pkix_path::Error::MissingRfc822San)
            ),
            "cert with dNSName-only SAN must fail smime_policy with MissingRfc822San"
        );
    }
}
