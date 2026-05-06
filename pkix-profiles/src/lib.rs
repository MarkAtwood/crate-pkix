#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! CA/Browser Forum and RFC certificate profile policies for `pkix-chain`.
//!
//! # `std` requirement
//!
//! This crate requires `std`. It does not support `no_std` in v0.1 because
//! [`ValidationPolicy`] holds owned `Vec` fields that currently require the
//! standard allocator. `no_std` + `alloc` support is planned for a future
//! release; until then, downstream `no_std` crates should construct
//! [`ValidationPolicy`] directly rather than using this crate.
//!
//! Provides pre-configured [`ValidationPolicy`] values for common
//! certificate use cases, encoding the additional constraints imposed by
//! the CA/Browser Forum Baseline Requirements beyond RFC 5280.
//!
//! # Profiles
//!
//! | Function | Document | Key constraints |
//! |----------|----------|-----------------|
//! | [`web_pki_policy`] | CA/B Forum TLS BR | 398-day max validity, SAN required, SHA-1 prohibited |
//! | [`smime_policy`] | CA/B Forum S/MIME BR | Email-specific key usage, S/MIME EKU |
//! | [`code_signing_policy`] | CA/B Forum Code Signing BR | Code signing EKU, timestamping |
//! | [`rfc5280_policy`] | RFC 5280 only | No CA/B Forum additions |
//!
//! # Dependencies
//!
//! This crate depends on `pkix-path` with its default features (`rsa`, `p256`)
//! enabled. Users who want a narrower feature set should depend on `pkix-path`
//! directly with only the needed features and use [`pkix_path::ValidationPolicy`]
//! without this crate.
//!
//! # Spec references
//!
//! - CA/Browser Forum Baseline Requirements for TLS Server Certificates
//! - CA/Browser Forum S/MIME Baseline Requirements
//! - CA/Browser Forum Code Signing Baseline Requirements
//! - RFC 5280 — Internet X.509 PKI Certificate and CRL Profile

pub use pkix_path::ValidationPolicy;

use der::asn1::ObjectIdentifier;

// ---------------------------------------------------------------------------
// Shared OID constants
// ---------------------------------------------------------------------------

// RSA signature OIDs (RFC 4055 / RFC 5912)
const SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const SHA384_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const SHA512_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

// ECDSA signature OIDs (RFC 5912)
const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const ECDSA_WITH_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const ECDSA_WITH_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

// The set of algorithms that CA/B Forum profiles consider acceptable.
// Excludes SHA-1 based algorithms per CA/B Forum BR §6.1.5.
//
// sha1WithRSAEncryption (1.2.840.113549.1.1.5) and ecdsa-with-SHA1
// (1.2.840.10045.4.1) are intentionally absent from this list.
const CABF_ALLOWED_ALGS: &[ObjectIdentifier] = &[
    SHA256_WITH_RSA,
    SHA384_WITH_RSA,
    SHA512_WITH_RSA,
    ECDSA_WITH_SHA256,
    ECDSA_WITH_SHA384,
    ECDSA_WITH_SHA512,
];

// EKU OIDs (RFC 5280 §4.2.1.12)
const ID_KP_SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
const ID_KP_EMAIL_PROTECTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.4");
const ID_KP_CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");

// ---------------------------------------------------------------------------
// Profile functions
// ---------------------------------------------------------------------------

/// Return a [`ValidationPolicy`] conforming to the CA/Browser Forum
/// Baseline Requirements for TLS Server Certificates.
///
/// # Constraints enforced
///
/// | Field | Value | Normative reference |
/// |-------|-------|---------------------|
/// | `max_validity_secs` | 398 days | CA/B Forum TLS BR §6.3.2 |
/// | `allowed_signature_algs` | SHA-256/384/512 RSA + ECDSA; SHA-1 excluded | TLS BR §6.1.5 |
/// | `min_rsa_key_bits` | 2048 | TLS BR §6.1.5 |
/// | `require_subject_alt_name` | true | TLS BR §7.1.4.2 |
/// | `required_leaf_eku` | id-kp-serverAuth (1.3.6.1.5.5.7.3.1) | TLS BR §7.1.2.7.3 |
/// | `max_path_len` | 2 | TLS BR §7.1.1 |
///
/// # Limitations
///
/// This function enforces the structural constraints listed above using
/// `pkix-path`'s `ValidationPolicy`. It does not verify:
/// - CAA DNS records (network check; out of scope for `pkix-path`)
/// - CT log SCTs (separate verification step)
/// - OCSP/CRL revocation (use `pkix-revocation`)
///
/// ## SC-081 validity reduction schedule
///
/// CA/B Forum Ballot SC-081 (approved March 2024) introduces a phased reduction
/// of TLS certificate maximum validity:
/// - 398 days → current cap (enforced here; pre-SC-081 deployments)
/// - 200 days → effective 2026-03-15
/// - 100 days → effective 2027-03-15
/// - 47 days  → effective 2029-03-15
///
/// This function uses the 398-day cap and is correct for certificates issued
/// before the SC-081 phase-in dates. Relying parties validating certificates
/// after 2026-03-15 should tighten `max_validity_secs` to match the applicable
/// cap for their deployment context.
#[must_use]
pub fn web_pki_policy(now_unix: u64) -> ValidationPolicy {
    let mut p = ValidationPolicy::new(now_unix);
    // BR §6.3.2: maximum certificate validity is 398 days (pre-SC-081).
    // See the SC-081 note in the doc comment for the phased reduction schedule.
    p.max_validity_secs = Some(398 * 86_400);
    // BR §6.1.5: SHA-1 prohibited; only the listed modern hash algorithms are accepted.
    p.allowed_signature_algs = Some(CABF_ALLOWED_ALGS.to_vec());
    // BR §6.1.5: RSA keys must be at least 2048 bits.
    p.min_rsa_key_bits = Some(2048);
    // BR §7.1.4.2: the SAN extension must be present and non-empty on the leaf.
    p.require_subject_alt_name = true;
    // BR §7.1.2.7.3: id-kp-serverAuth must be asserted in the leaf's EKU.
    p.required_leaf_eku = Some(vec![ID_KP_SERVER_AUTH]);
    // BR §7.1.1: at most 2 non-self-issued intermediates in the path.
    p.max_path_len = 2;
    p
}

/// Return a [`ValidationPolicy`] conforming to the CA/Browser Forum
/// S/MIME Baseline Requirements.
///
/// # Constraints enforced
///
/// This implementation targets the Mailbox-validated / strict profile.
///
/// | Field | Value | Normative reference |
/// |-------|-------|---------------------|
/// | `max_validity_secs` | 1185 days (~39 months) | S/MIME BR §6.3.2 |
/// | `allowed_signature_algs` | SHA-256/384/512 RSA + ECDSA; SHA-1 excluded | S/MIME BR §6.1.5 |
/// | `min_rsa_key_bits` | 2048 | S/MIME BR §6.1.5 |
/// | `require_subject_alt_name` | true | non-empty SubjectAltName extension required |
/// | `required_leaf_eku` | id-kp-emailProtection (1.3.6.1.5.5.7.3.4) | S/MIME BR §7.3 |
/// | `max_path_len` | 1 | S/MIME BR §7.2 (at most one Subordinate CA between Root and EE) |
///
/// # Limitations
///
/// Only the Mailbox-validated / strict profile is enforced. Organization-validated,
/// Sponsor-validated, and Individual-validated profiles are planned for v0.3.
///
/// The `require_subject_alt_name` flag causes `pkix-path` to require a non-empty
/// SubjectAltName extension; it does **not** verify that the SAN contains an
/// `rfc822Name` entry. A certificate with only a `dNSName` SAN would pass this
/// check. Verifying the specific SAN type is planned for v0.2.
///
/// Revocation checking (OCSP/CRL) is out of scope; use `pkix-revocation`.
#[must_use]
pub fn smime_policy(now_unix: u64) -> ValidationPolicy {
    let mut p = ValidationPolicy::new(now_unix);
    // S/MIME BR §6.3.2: strict profile maximum validity ~39 months (1185 days).
    p.max_validity_secs = Some(1185 * 86_400);
    // S/MIME BR §6.1.5: SHA-1 prohibited.
    p.allowed_signature_algs = Some(CABF_ALLOWED_ALGS.to_vec());
    // S/MIME BR §6.1.5: RSA keys must be at least 2048 bits.
    p.min_rsa_key_bits = Some(2048);
    // Mailbox-validated: non-empty SAN required (rfc822Name type not verified in v0.1).
    p.require_subject_alt_name = true;
    // S/MIME BR §7.3: id-kp-emailProtection must be asserted.
    p.required_leaf_eku = Some(vec![ID_KP_EMAIL_PROTECTION]);
    // S/MIME BR §7.2: at most one Subordinate CA between Root and end-entity; max_path_len=1.
    p.max_path_len = 1;
    p
}

/// Return a [`ValidationPolicy`] conforming to the CA/Browser Forum
/// Code Signing Baseline Requirements.
///
/// # Constraints enforced
///
/// | Field | Value | Normative reference |
/// |-------|-------|---------------------|
/// | `max_validity_secs` | 1185 days (~39 months) | CS BR §6.3.2 |
/// | `allowed_signature_algs` | SHA-256/384/512 RSA + ECDSA; SHA-1 excluded | CS BR §6.1.5 |
/// | `min_rsa_key_bits` | 3072 | CS BR §6.1.5 (effective 2023-06-01) |
/// | `require_subject_alt_name` | false | CS certs identify subjects by DN |
/// | `required_leaf_eku` | id-kp-codeSigning (1.3.6.1.5.5.7.3.3) | CS BR §7.1.2.3 |
/// | `max_path_len` | 1 | CS BR §7.1.1 (Root CA issues Subordinate CA directly) |
///
/// # Limitations
///
/// Timestamp authority verification is out of scope for `pkix-path`;
/// use a dedicated timestamp verifier. Revocation is handled by `pkix-revocation`.
#[must_use]
pub fn code_signing_policy(now_unix: u64) -> ValidationPolicy {
    let mut p = ValidationPolicy::new(now_unix);
    // CS BR §6.3.2: maximum validity ~39 months (1185 days).
    p.max_validity_secs = Some(1185 * 86_400);
    // CS BR §6.1.5: SHA-1 prohibited.
    p.allowed_signature_algs = Some(CABF_ALLOWED_ALGS.to_vec());
    // CS BR §6.1.5: RSA keys must be at least 3072 bits (raised from 2048 effective 2023-06-01).
    // This is the key differentiator from web_pki_policy (2048 bits).
    p.min_rsa_key_bits = Some(3072);
    // CS certs identify subjects by DN; SAN is not required.
    p.require_subject_alt_name = false;
    // CS BR §7.1.2.3: id-kp-codeSigning must be asserted.
    p.required_leaf_eku = Some(vec![ID_KP_CODE_SIGNING]);
    // CS BR §7.1.1: Root CA issues Subordinate CA directly; at most 1 intermediate.
    p.max_path_len = 1;
    p
}

/// Return a plain RFC 5280 [`ValidationPolicy`] with no CA/Browser Forum additions.
#[must_use]
pub fn rfc5280_policy(now_unix: u64) -> ValidationPolicy {
    ValidationPolicy::new(now_unix)
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
    // web_pki_policy field-value checks
    //
    // Oracle: CA/B Forum TLS BR values hardcoded in web_pki_policy(); we
    // assert the returned struct matches the spec rather than testing
    // round-trips through the code under test itself.
    // -----------------------------------------------------------------------

    #[test]
    fn web_pki_policy_max_validity_is_398_days() {
        let p = web_pki_policy(NOW);
        assert_eq!(
            p.max_validity_secs,
            Some(398 * 86_400),
            "web_pki_policy: max_validity_secs must be 398 days (34,387,200 s)"
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
        let server_auth: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
        let p = web_pki_policy(NOW);
        let ekus = p.required_leaf_eku.as_deref().unwrap_or(&[]);
        assert!(
            ekus.contains(&server_auth),
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
    /// web_pki_policy applies max_validity_secs to ALL certs in the chain, and
    /// the root/int fixtures have 10-year validity (well over 398 days). A single
    /// self-signed cert satisfies all constraints at once.
    ///
    /// Oracle: openssl verify -CAfile <self> <self> → OK (self-signed).
    #[test]
    fn web_pki_conforming_cert_passes() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/webpki-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        pkix_path::validate_path(&[cert], &anchors, &web_pki_policy(NOW), &EcdsaP256Verifier)
            .expect(
                "self-signed 365-day cert with SAN and serverAuth EKU must pass web_pki_policy",
            );
    }

    /// Oracle: webpki-self-signed-365d.der has 365-day validity (< 398) → passes.
    /// A cert with 400-day validity exceeds the cap → rejected.
    ///
    /// We test the rejection using the webpki-self-signed-365d cert but with a
    /// tighter cap (300 days) to trigger ValidityPeriodExceedsMax at index 0.
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
    ///
    /// **Note**: This test checks the field value and validates that a conforming cert
    /// passes. It does NOT test that a cert without a SAN is rejected — that rejection
    /// path is covered by `pkix_path::tests_policy_fields::require_san_fails_when_san_absent`.
    #[test]
    fn web_pki_policy_san_field_is_true() {
        // Verify the field is set in web_pki_policy.
        assert!(
            web_pki_policy(NOW).require_subject_alt_name,
            "web_pki_policy must set require_subject_alt_name=true"
        );
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/webpki-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        // Should pass: the self-signed cert has SAN.
        pkix_path::validate_path(&[cert], &anchors, &web_pki_policy(NOW), &EcdsaP256Verifier)
            .expect("self-signed cert with SAN must pass web_pki_policy SAN check");
    }

    /// Oracle: a cert with no EKU extension must be rejected by web_pki_policy.
    /// Uses webpki-self-signed-365d.der with a policy that has required_leaf_eku=[serverAuth]
    /// but NO eku in the cert. Since webpki-self-signed-365d.der HAS serverAuth,
    /// we test rejection using a policy requiring a different EKU.
    #[test]
    fn web_pki_missing_server_auth_eku_rejected() {
        // Verify the field is set correctly in web_pki_policy.
        let server_auth: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
        let p = web_pki_policy(NOW);
        assert!(
            p.required_leaf_eku
                .as_deref()
                .unwrap_or(&[])
                .contains(&server_auth),
            "web_pki_policy must set required_leaf_eku=[serverAuth]"
        );

        // Verify the enforcement: cert with serverAuth passes, cert without fails.
        // Use webpki-self-signed-365d (has serverAuth) to verify pass.
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/webpki-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        pkix_path::validate_path(&[cert], &anchors, &web_pki_policy(NOW), &EcdsaP256Verifier)
            .expect("cert with serverAuth must pass web_pki_policy EKU check");

        // Verify rejection: require emailProtection but cert has serverAuth.
        let email_prot: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.4");
        let cert2 = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/webpki-self-signed-365d.der"
        ));
        let anchors2 = [TrustAnchor::from_cert(cert2.clone())];
        let mut strict_policy = web_pki_policy(NOW);
        strict_policy.required_leaf_eku = Some(vec![email_prot]);
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
        // Override the EKU requirement to emailProtection to trigger MissingEku.
        let mut policy = web_pki_policy(NOW);
        let email_prot: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.4");
        policy.required_leaf_eku = Some(vec![email_prot]);
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
        let email_prot: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.4");
        let p = smime_policy(NOW);
        let ekus = p.required_leaf_eku.as_deref().unwrap_or(&[]);
        assert!(
            ekus.contains(&email_prot),
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

    /// Oracle: openssl verify -CAfile smime-self-signed-365d.pem smime-self-signed-365d.pem → OK
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
        // Verify that smime_policy requires emailProtection.
        assert!(
            smime_policy(NOW)
                .required_leaf_eku
                .as_deref()
                .unwrap_or(&[])
                .contains(&ID_KP_EMAIL_PROTECTION),
            "smime_policy must require id-kp-emailProtection"
        );
        // Verify that a cert with serverAuth (not emailProtection) is rejected.
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
    fn code_signing_policy_max_validity_is_1185_days() {
        let p = code_signing_policy(NOW);
        assert_eq!(
            p.max_validity_secs,
            Some(1185 * 86_400),
            "code_signing_policy: max_validity_secs must be 1185 days"
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
        let code_sign: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");
        let p = code_signing_policy(NOW);
        let ekus = p.required_leaf_eku.as_deref().unwrap_or(&[]);
        assert!(
            ekus.contains(&code_sign),
            "code_signing_policy: required_leaf_eku must contain id-kp-codeSigning"
        );
    }

    /// Oracle: openssl verify -CAfile codesign-self-signed-365d.pem codesign-self-signed-365d.pem → OK
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
        .expect(
            "self-signed 365-day cert with codeSigning EKU must pass code_signing_policy",
        );
    }

    /// Verify that `code_signing_policy` requires `codeSigning` EKU and that a cert
    /// with `serverAuth` (not `codeSigning`) is rejected with `MissingEku`.
    #[test]
    fn code_signing_policy_rejects_wrong_eku() {
        // Use the webpki-self-signed-365d cert which has serverAuth, not codeSigning.
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

    /// Higher RSA floor than web_pki_policy: 3072 vs 2048.
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
        // No profile-specific constraints set.
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
}
