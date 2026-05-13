#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! RFC-baseline profile implementations for `pkix-path`.
//!
//! # What this crate is
//!
//! `pkix-profiles` ships RFC-baseline [`Profile`] implementations: the structural
//! constraints that any standards-conforming PKI deployment can rely on, derived
//! directly from IETF RFCs without overlaying any individual industry-forum
//! interpretation.
//!
//! CA/Browser Forum-specific profiles ([`WebPkiProfile`], [`SmimeProfile`],
//! [`CodeSigningProfile`]) and the SC-081 phased validity helper have moved to
//! the sibling [`pkix-profiles-cabf`] crate as of `pkix-profiles 0.3.0`.
//! Deprecated re-exports are kept here for one minor cycle so existing imports
//! continue to compile (with a deprecation warning); the re-exports are
//! scheduled to drop in `pkix-profiles 0.4.0`.
//!
//! Third-party crates (`pkix-fpki`, `pkix-etsi`, etc.) implement
//! [`pkix_path::Profile`] directly against `pkix-path` and do not need to
//! depend on this crate. The [`Profile`] trait itself lives in `pkix-path`
//! so that external profile crates can depend on it without pulling in
//! these bundled implementations.
//!
//! # Profiles
//!
//! | Struct | Free-function alias | Document | Key constraints |
//! |--------|--------------------|---------| ----------------|
//! | [`Rfc5280Profile`] | [`rfc5280_policy`] | RFC 5280 only | No overlay |
//! | [`BasicTlsProfile`] | [`basic_tls_policy`] | RFC 5280 + RFC 6125 | id-kp-serverAuth EKU + non-empty SAN |
//! | [`BasicTlsClientProfile`] | [`basic_tls_client_policy`] | RFC 5280 §4.2.1.12 | id-kp-clientAuth EKU |
//! | [`BasicSmimeProfile`] | [`basic_smime_policy`] | RFC 8551 §3 | id-kp-emailProtection EKU + rfc822Name SAN |
//! | [`BasicCodeSigningProfile`] | [`basic_code_signing_policy`] | RFC 5280 §4.2.1.12 | id-kp-codeSigning EKU |
//! | [`BasicTimeStampingProfile`] | [`basic_time_stamping_policy`] | RFC 3161 §2.3 | id-kp-timeStamping EKU |
//! | [`BasicOcspResponderProfile`] | [`basic_ocsp_responder_policy`] | RFC 6960 §4.2.2.2 | id-kp-OCSPSigning EKU |
//!
//! For CA/Browser Forum profile content (TLS BR, S/MIME BR, Code Signing BR,
//! SC-081 phased validity caps), use [`pkix-profiles-cabf`].
//!
//! # Usage
//!
//! ```rust,no_run
//! use pkix_profiles::{BasicTlsProfile, Profile};
//!
//! let now_unix = 1_700_000_000_u64;
//!
//! // Via the Profile trait (for generic code or registries):
//! let profile = BasicTlsProfile;
//! let policy = profile.policy(now_unix);
//! # let _ = policy;
//!
//! // Via free-function alias (for quick one-liners):
//! let policy = pkix_profiles::basic_tls_policy(now_unix);
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
//! # Limitations
//!
//! - **RFC-baseline only.** This crate ships profiles derived from IETF
//!   RFC text only (RFC 5280 §4.2.1.12 EKU rules, RFC 6125 §6.4 SAN
//!   shape, RFC 8551 §3 S/MIME shape, RFC 3161 §2.3 TSA EKU, RFC 6960
//!   §4.2.2.2 OCSP-responder EKU). Industry-forum policy (CA/B Forum
//!   Baseline Requirements, Mozilla / Apple / Microsoft root-program
//!   rules, ETSI, FedRAMP, DoD) is **not** shipped here. CA/B Forum
//!   reference profiles live in `pkix-profiles-cabf`; comprehensive
//!   industry-forum coverage is the job of policy-adapter crates
//!   (`pkix-policy-zlint`, `pkix-policy-pkilint`).
//! - **EKU shape, not chain semantics.** The bundled profiles enforce the
//!   end-entity EKU / SAN / `BasicConstraints` shape required by the RFC.
//!   They do not enforce chain-wide policy machinery (RFC 5280 §6.1.4
//!   `PolicyMappings`, `PolicyConstraints`, `InhibitAnyPolicy`) beyond
//!   what `pkix-path` already does — these profiles add caller-friendly
//!   structural overlays on top of that core algorithm.
//! - **Deprecated re-exports drop in 0.4.0.** `WebPkiProfile`,
//!   `SmimeProfile`, `CodeSigningProfile`, and `sc081_validity_cap`
//!   moved to `pkix-profiles-cabf` in 0.3.0 and are kept here as
//!   deprecated aliases for one minor cycle. Migrate to
//!   `pkix-profiles-cabf` before upgrading past 0.3.x.
//! - **No site-local extension.** Site-local policy is the caller's
//!   responsibility; either implement [`pkix_path::Profile`] directly or
//!   wrap a bundled profile and overlay site-specific rules.
//!
//! # Spec references
//!
//! - RFC 5280 — Internet X.509 PKI Certificate and CRL Profile
//! - RFC 6125 — Representation and Verification of Domain-Based Application
//!   Service Identity within Internet PKIX Using X.509 Certificates
//! - RFC 8551 — S/MIME 4.0 Message Specification
//!
//! [`pkix-profiles-cabf`]: https://docs.rs/pkix-profiles-cabf

pub use pkix_path::{Profile, ValidationPolicy};

// ---------------------------------------------------------------------------
// Deprecated re-exports — CA/B Forum content moved to pkix-profiles-cabf
// in the 0.3.0 release. Drops in 0.4.0.
// ---------------------------------------------------------------------------

#[deprecated(
    since = "0.3.0",
    note = "moved to pkix-profiles-cabf; import `pkix_profiles_cabf::WebPkiProfile` instead. \
            This re-export drops in pkix-profiles 0.4.0."
)]
pub use pkix_profiles_cabf::WebPkiProfile;

#[deprecated(
    since = "0.3.0",
    note = "moved to pkix-profiles-cabf; import `pkix_profiles_cabf::SmimeProfile` instead. \
            This re-export drops in pkix-profiles 0.4.0."
)]
pub use pkix_profiles_cabf::SmimeProfile;

#[deprecated(
    since = "0.3.0",
    note = "moved to pkix-profiles-cabf; import `pkix_profiles_cabf::CodeSigningProfile` instead. \
            This re-export drops in pkix-profiles 0.4.0."
)]
pub use pkix_profiles_cabf::CodeSigningProfile;

#[deprecated(
    since = "0.3.0",
    note = "moved to pkix-profiles-cabf; import `pkix_profiles_cabf::web_pki_policy` instead. \
            This re-export drops in pkix-profiles 0.4.0."
)]
pub use pkix_profiles_cabf::web_pki_policy;

#[deprecated(
    since = "0.3.0",
    note = "moved to pkix-profiles-cabf; import `pkix_profiles_cabf::smime_policy` instead. \
            This re-export drops in pkix-profiles 0.4.0."
)]
pub use pkix_profiles_cabf::smime_policy;

#[deprecated(
    since = "0.3.0",
    note = "moved to pkix-profiles-cabf; import `pkix_profiles_cabf::code_signing_policy` instead. \
            This re-export drops in pkix-profiles 0.4.0."
)]
pub use pkix_profiles_cabf::code_signing_policy;

#[deprecated(
    since = "0.3.0",
    note = "moved to pkix-profiles-cabf; import `pkix_profiles_cabf::sc081_validity_cap` instead. \
            This re-export drops in pkix-profiles 0.4.0."
)]
pub use pkix_profiles_cabf::sc081_validity_cap;

use der::asn1::ObjectIdentifier;

// EKU OIDs (RFC 5280 §4.2.1.12).  Re-stated here rather than re-exported
// from pkix-profiles-cabf because these are standards-body identifiers that
// the RFC-baseline profiles depend on; coupling them to a CA/B Forum crate
// would invert the dependency direction.
const ID_KP_SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
const ID_KP_CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");
const ID_KP_CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");
const ID_KP_EMAIL_PROTECTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.4");
const ID_KP_TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");
const ID_KP_OCSP_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9");

// ---------------------------------------------------------------------------
// RFC-baseline profiles
// ---------------------------------------------------------------------------

/// Plain RFC 5280 profile with no additions.
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

/// Basic TLS server-certificate profile (RFC 5280 + RFC 6125 + serverAuth EKU).
///
/// The minimum structural constraints that any TLS server certificate must
/// satisfy across all deployment policies: RFC 5280 path validation, RFC 6125
/// SAN-based identity verification, and the universally-required
/// `id-kp-serverAuth` Extended Key Usage.
///
/// **Not** a CA/B Forum profile: no validity caps, no key-size floors, no
/// signature-algorithm whitelist. Those constraints are CA/B Forum overlay —
/// see [`pkix-profiles-cabf::WebPkiProfile`][cabf-tls] for the BR overlay.
///
/// The free-function alias [`basic_tls_policy`] is equivalent to
/// `BasicTlsProfile.policy(now_unix)`.
///
/// [cabf-tls]: https://docs.rs/pkix-profiles-cabf/latest/pkix_profiles_cabf/struct.WebPkiProfile.html
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct BasicTlsProfile;

impl Profile for BasicTlsProfile {
    fn id(&self) -> &'static str {
        // Reverse-domain style: standards body + spec scope.
        "ietf.tls-basic"
    }

    fn version(&self) -> &'static str {
        // RFC 5280 path validation + RFC 6125 identity.
        "RFC 5280 + RFC 6125"
    }

    fn policy(&self, now_unix: u64) -> ValidationPolicy {
        let mut p = ValidationPolicy::new(now_unix);
        // RFC 6125 §6: hostname matching against SAN dNSName entries is the
        // standard for TLS server identity verification. Require a non-empty
        // SAN so leaves declare their identity in the standard way.
        p.require_subject_alt_name = true;
        // RFC 5280 §4.2.1.12: id-kp-serverAuth is the universally-required
        // EKU for any certificate intended for TLS server use.
        p.required_leaf_eku = Some(vec![ID_KP_SERVER_AUTH]);
        p
    }

    fn policy_oids(&self) -> &[ObjectIdentifier] {
        &[]
    }
}

/// Basic TLS client-certificate profile (RFC 5280 + clientAuth EKU).
///
/// The minimum structural constraint that any TLS client-authentication
/// certificate must satisfy: the `id-kp-clientAuth` Extended Key Usage
/// (1.3.6.1.5.5.7.3.2). Unlike [`BasicTlsProfile`], this profile does NOT
/// set `require_subject_alt_name` — client-auth deployments commonly read
/// the identity from the Subject DN rather than the SAN. Callers that
/// want SAN-bound identity binding should pass an explicit `ServerName`
/// or `MailboxName` to `pkix_chain::verify_tls_client_dns` /
/// `verify_tls_client_mailbox`; those wrappers run the SAN check
/// separately from the profile's path-validation constraints.
///
/// **Not** a CA/B Forum profile: no validity caps, no key-size floors,
/// no signature-algorithm whitelist.
///
/// The free-function alias [`basic_tls_client_policy`] is equivalent to
/// `BasicTlsClientProfile.policy(now_unix)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct BasicTlsClientProfile;

impl Profile for BasicTlsClientProfile {
    fn id(&self) -> &'static str {
        "ietf.tls-client-basic"
    }

    fn version(&self) -> &'static str {
        // RFC 5280 EKU registry; id-kp-clientAuth is RFC 5280 §4.2.1.12.
        "RFC 5280 §4.2.1.12"
    }

    fn policy(&self, now_unix: u64) -> ValidationPolicy {
        let mut p = ValidationPolicy::new(now_unix);
        // RFC 5280 §4.2.1.12: id-kp-clientAuth is the EKU value for TLS
        // client-authentication certificates.
        p.required_leaf_eku = Some(vec![ID_KP_CLIENT_AUTH]);
        p
    }

    fn policy_oids(&self) -> &[ObjectIdentifier] {
        &[]
    }
}

/// Basic S/MIME profile (RFC 8551 §3 baseline).
///
/// The minimum structural constraints that any S/MIME end-entity certificate
/// must satisfy: `id-kp-emailProtection` Extended Key Usage and at least one
/// `rfc822Name` entry in the Subject Alternative Name extension.
///
/// **Not** a CA/B Forum profile: no validity caps, no key-size floors, no
/// signature-algorithm whitelist, no identity-tier policy OIDs. Those
/// constraints are CA/B Forum S/MIME BR overlay — see
/// [`pkix-profiles-cabf::SmimeProfile`][cabf-smime] for the BR overlay.
///
/// The free-function alias [`basic_smime_policy`] is equivalent to
/// `BasicSmimeProfile.policy(now_unix)`.
///
/// [cabf-smime]: https://docs.rs/pkix-profiles-cabf/latest/pkix_profiles_cabf/struct.SmimeProfile.html
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct BasicSmimeProfile;

impl Profile for BasicSmimeProfile {
    fn id(&self) -> &'static str {
        "ietf.smime-basic"
    }

    fn version(&self) -> &'static str {
        "RFC 8551"
    }

    fn policy(&self, now_unix: u64) -> ValidationPolicy {
        let mut p = ValidationPolicy::new(now_unix);
        // RFC 8551 §3: id-kp-emailProtection is the EKU value for S/MIME.
        p.required_leaf_eku = Some(vec![ID_KP_EMAIL_PROTECTION]);
        // RFC 8551 §3: rfc822Name SAN is the standard identity binding for S/MIME.
        p.require_subject_alt_name = true;
        p.require_rfc822_san = true;
        p
    }

    fn policy_oids(&self) -> &[ObjectIdentifier] {
        &[]
    }
}

/// Basic code-signing end-entity profile (RFC 5280 + id-kp-codeSigning EKU).
///
/// The minimum structural constraint that any code-signing end-entity
/// certificate must satisfy: the `id-kp-codeSigning` Extended Key Usage
/// (1.3.6.1.5.5.7.3.3). Code-signing certificates do not carry a
/// caller-supplied identity target (no hostname, no mailbox), so there is
/// no SAN requirement.
///
/// **Not** a CA/B Forum profile: no validity caps, no key-size floors, no
/// timestamp-counter-signature requirement, no signature-algorithm
/// whitelist. Those constraints are CA/B Forum Code Signing BR overlay —
/// see [`pkix-profiles-cabf::CodeSigningProfile`][cabf-cs] for the BR overlay.
///
/// The free-function alias [`basic_code_signing_policy`] is equivalent to
/// `BasicCodeSigningProfile.policy(now_unix)`.
///
/// [cabf-cs]: https://docs.rs/pkix-profiles-cabf/latest/pkix_profiles_cabf/struct.CodeSigningProfile.html
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct BasicCodeSigningProfile;

impl Profile for BasicCodeSigningProfile {
    fn id(&self) -> &'static str {
        "ietf.code-signing-basic"
    }

    fn version(&self) -> &'static str {
        // RFC 5280 EKU registry; id-kp-codeSigning has no separate spec doc.
        "RFC 5280 §4.2.1.12"
    }

    fn policy(&self, now_unix: u64) -> ValidationPolicy {
        let mut p = ValidationPolicy::new(now_unix);
        // RFC 5280 §4.2.1.12 + IANA registry: id-kp-codeSigning is the
        // EKU value for code-signing certificates.
        p.required_leaf_eku = Some(vec![ID_KP_CODE_SIGNING]);
        p
    }

    fn policy_oids(&self) -> &[ObjectIdentifier] {
        &[]
    }
}

/// Basic Time Stamping Authority (TSA) end-entity profile
/// (RFC 3161 + `id-kp-timeStamping` EKU).
///
/// The minimum structural constraint that any TSA end-entity certificate
/// must satisfy is the `id-kp-timeStamping` Extended Key Usage
/// (1.3.6.1.5.5.7.3.8). This profile sets `required_leaf_eku` to enforce
/// presence; RFC 3161 §2.3 additionally requires that the EKU extension
/// be **critical** and contain **only** `id-kp-timeStamping`, which
/// `pkix_chain::verify_time_stamper` enforces post-validation (the
/// presence check is sufficient for the profile-level requirement).
///
/// The free-function alias [`basic_time_stamping_policy`] is equivalent
/// to `BasicTimeStampingProfile.policy(now_unix)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct BasicTimeStampingProfile;

impl Profile for BasicTimeStampingProfile {
    fn id(&self) -> &'static str {
        "ietf.time-stamping-basic"
    }

    fn version(&self) -> &'static str {
        "RFC 3161 §2.3"
    }

    fn policy(&self, now_unix: u64) -> ValidationPolicy {
        let mut p = ValidationPolicy::new(now_unix);
        // RFC 3161 §2.3: id-kp-timeStamping is the EKU value for TSA
        // certificates. The critical-and-sole rule is enforced at the
        // wrapper layer (verify_time_stamper) because ValidationPolicy
        // does not currently express EKU criticality or singularity.
        p.required_leaf_eku = Some(vec![ID_KP_TIME_STAMPING]);
        p
    }

    fn policy_oids(&self) -> &[ObjectIdentifier] {
        &[]
    }
}

/// Basic OCSP responder end-entity profile
/// (RFC 6960 §4.2.2.2 + `id-kp-OCSPSigning` EKU).
///
/// The minimum structural constraint that any delegated OCSP responder
/// end-entity certificate must satisfy is the `id-kp-OCSPSigning`
/// Extended Key Usage (1.3.6.1.5.5.7.3.9). RFC 6960 §4.2.2.2
/// additionally requires that the responder cert be signed by the same
/// CA whose certs the responder asserts revocation status on; that
/// **delegation** check is enforced at the wrapper layer
/// (`pkix_chain::verify_ocsp_responder`) — the profile alone guarantees
/// only EKU presence.
///
/// This profile targets the **delegated** responder case. The
/// CA-direct case (the issuing CA signs OCSP responses with its own
/// CA key, no separate responder cert) is not an OCSP-responder
/// validation problem at the API surface — callers in that case
/// validate the CA cert itself with `pkix_chain::verify_chain`. See
/// `pkix_chain::verify_ocsp_responder` rustdoc for a worked example.
///
/// No SAN requirement: an OCSP responder cert has no caller-supplied
/// identity target.
///
/// The free-function alias [`basic_ocsp_responder_policy`] is
/// equivalent to `BasicOcspResponderProfile.policy(now_unix)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct BasicOcspResponderProfile;

impl Profile for BasicOcspResponderProfile {
    fn id(&self) -> &'static str {
        "ietf.ocsp-responder-basic"
    }

    fn version(&self) -> &'static str {
        "RFC 6960 §4.2.2.2"
    }

    fn policy(&self, now_unix: u64) -> ValidationPolicy {
        let mut p = ValidationPolicy::new(now_unix);
        // RFC 6960 §4.2.2.2: id-kp-OCSPSigning is the EKU value for
        // delegated OCSP responder certificates. The delegation check
        // (responder cert signed by the same issuer whose status it
        // asserts) is enforced at the wrapper layer because it
        // requires a caller-supplied `issuer` argument that
        // ValidationPolicy cannot carry.
        p.required_leaf_eku = Some(vec![ID_KP_OCSP_SIGNING]);
        p
    }

    fn policy_oids(&self) -> &[ObjectIdentifier] {
        &[]
    }
}

// ---------------------------------------------------------------------------
// Free-function convenience aliases
// ---------------------------------------------------------------------------

/// Return a plain RFC 5280 [`ValidationPolicy`] with no additions.
///
/// This is a convenience alias for `Rfc5280Profile.policy(now_unix)`.
#[must_use]
pub fn rfc5280_policy(now_unix: u64) -> ValidationPolicy {
    Rfc5280Profile.policy(now_unix)
}

/// Return a [`ValidationPolicy`] for basic TLS server-certificate validation
/// (RFC 5280 + RFC 6125 + `id-kp-serverAuth` EKU).
///
/// Convenience alias for `BasicTlsProfile.policy(now_unix)`.
///
/// # Constraints enforced
///
/// | Field | Value | Normative reference |
/// |-------|-------|---------------------|
/// | `require_subject_alt_name` | true | RFC 6125 §6 |
/// | `required_leaf_eku` | `id-kp-serverAuth` (1.3.6.1.5.5.7.3.1) | RFC 5280 §4.2.1.12 |
///
/// No CA/B Forum-specific constraints (validity caps, key-size floors,
/// signature-algorithm whitelist, path-length caps). Use
/// `pkix-profiles-cabf::web_pki_policy` for the BR overlay.
#[must_use]
pub fn basic_tls_policy(now_unix: u64) -> ValidationPolicy {
    BasicTlsProfile.policy(now_unix)
}

/// Return a [`ValidationPolicy`] for basic TLS client-certificate validation
/// (RFC 5280 + `id-kp-clientAuth` EKU).
///
/// Convenience alias for `BasicTlsClientProfile.policy(now_unix)`.
///
/// # Constraints enforced
///
/// | Field | Value | Normative reference |
/// |-------|-------|---------------------|
/// | `required_leaf_eku` | `id-kp-clientAuth` (1.3.6.1.5.5.7.3.2) | RFC 5280 §4.2.1.12 |
///
/// Unlike [`basic_tls_policy`], this does NOT set
/// `require_subject_alt_name`. Client-auth deployments commonly read
/// the identity from the Subject DN rather than the SAN; callers that
/// want SAN-bound identity binding pass an explicit `ServerName` or
/// `MailboxName` to `pkix_chain::verify_tls_client_dns` /
/// `verify_tls_client_mailbox`.
#[must_use]
pub fn basic_tls_client_policy(now_unix: u64) -> ValidationPolicy {
    BasicTlsClientProfile.policy(now_unix)
}

/// Return a [`ValidationPolicy`] for basic S/MIME end-entity validation
/// (RFC 8551 §3 baseline).
///
/// Convenience alias for `BasicSmimeProfile.policy(now_unix)`.
///
/// # Constraints enforced
///
/// | Field | Value | Normative reference |
/// |-------|-------|---------------------|
/// | `required_leaf_eku` | `id-kp-emailProtection` (1.3.6.1.5.5.7.3.4) | RFC 8551 §3 |
/// | `require_subject_alt_name` | true | RFC 8551 §3 |
/// | `require_rfc822_san` | true | RFC 8551 §3 |
///
/// No CA/B Forum S/MIME BR-specific constraints. Use
/// `pkix-profiles-cabf::smime_policy` for the BR overlay (which adds validity
/// cap, key-size floor, signature-algorithm whitelist, and path-length cap).
#[must_use]
pub fn basic_smime_policy(now_unix: u64) -> ValidationPolicy {
    BasicSmimeProfile.policy(now_unix)
}

/// Return a [`ValidationPolicy`] for basic code-signing end-entity validation
/// (RFC 5280 + `id-kp-codeSigning` EKU).
///
/// Convenience alias for `BasicCodeSigningProfile.policy(now_unix)`.
///
/// # Constraints enforced
///
/// | Field | Value | Normative reference |
/// |-------|-------|---------------------|
/// | `required_leaf_eku` | `id-kp-codeSigning` (1.3.6.1.5.5.7.3.3) | RFC 5280 §4.2.1.12 |
///
/// No CA/B Forum Code Signing BR-specific constraints. Use
/// `pkix-profiles-cabf::code_signing_policy` for the BR overlay.
#[must_use]
pub fn basic_code_signing_policy(now_unix: u64) -> ValidationPolicy {
    BasicCodeSigningProfile.policy(now_unix)
}

/// Return a [`ValidationPolicy`] for basic Time Stamping Authority validation
/// (RFC 3161 + `id-kp-timeStamping` EKU).
///
/// Convenience alias for `BasicTimeStampingProfile.policy(now_unix)`.
///
/// # Constraints enforced
///
/// | Field | Value | Normative reference |
/// |-------|-------|---------------------|
/// | `required_leaf_eku` | `id-kp-timeStamping` (1.3.6.1.5.5.7.3.8) | RFC 3161 §2.3 |
///
/// RFC 3161 §2.3's additional constraint that the EKU extension be
/// critical and contain only `id-kp-timeStamping` is enforced at the
/// wrapper layer (`pkix_chain::verify_time_stamper`); the profile alone
/// guarantees only EKU presence.
#[must_use]
pub fn basic_time_stamping_policy(now_unix: u64) -> ValidationPolicy {
    BasicTimeStampingProfile.policy(now_unix)
}

/// Return a [`ValidationPolicy`] for basic OCSP-responder validation
/// (RFC 6960 §4.2.2.2 + `id-kp-OCSPSigning` EKU).
///
/// Convenience alias for `BasicOcspResponderProfile.policy(now_unix)`.
///
/// # Constraints enforced
///
/// | Field | Value | Normative reference |
/// |-------|-------|---------------------|
/// | `required_leaf_eku` | `id-kp-OCSPSigning` (1.3.6.1.5.5.7.3.9) | RFC 6960 §4.2.2.2 |
///
/// RFC 6960 §4.2.2.2's delegation requirement (responder cert signed
/// by the same issuer whose status it asserts) and §4.2.2.2.1
/// `id-pkix-ocsp-nocheck` handling are enforced at the wrapper layer
/// (`pkix_chain::verify_ocsp_responder`); the profile alone guarantees
/// only EKU presence.
#[must_use]
pub fn basic_ocsp_responder_policy(now_unix: u64) -> ValidationPolicy {
    BasicOcspResponderProfile.policy(now_unix)
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

    // Reuse the policy-checks fixtures from pkix-path's fixture directory.
    // Test time: 2026-06-01T00:00:00Z = 1_780_272_000 unix seconds.
    // All fixtures have NOT_BEFORE=2026-01-01 and are valid at this time.
    const NOW: u64 = 1_780_272_000;

    fn load(bytes: &[u8]) -> Certificate {
        Certificate::from_der(bytes).expect("valid DER fixture")
    }

    // -----------------------------------------------------------------------
    // Profile trait identity tests
    // -----------------------------------------------------------------------

    #[test]
    fn profile_ids_are_stable() {
        assert_eq!(Rfc5280Profile.id(), "ietf.rfc5280");
        assert_eq!(BasicTlsProfile.id(), "ietf.tls-basic");
        assert_eq!(BasicTlsClientProfile.id(), "ietf.tls-client-basic");
        assert_eq!(BasicSmimeProfile.id(), "ietf.smime-basic");
        assert_eq!(BasicCodeSigningProfile.id(), "ietf.code-signing-basic");
        assert_eq!(BasicTimeStampingProfile.id(), "ietf.time-stamping-basic");
        assert_eq!(
            BasicOcspResponderProfile.id(),
            "ietf.ocsp-responder-basic"
        );
    }

    #[test]
    fn profile_policy_sets_correct_timestamp() {
        assert_eq!(Rfc5280Profile.policy(NOW).current_time_unix, NOW);
        assert_eq!(BasicTlsProfile.policy(NOW).current_time_unix, NOW);
        assert_eq!(BasicTlsClientProfile.policy(NOW).current_time_unix, NOW);
        assert_eq!(BasicSmimeProfile.policy(NOW).current_time_unix, NOW);
        assert_eq!(BasicCodeSigningProfile.policy(NOW).current_time_unix, NOW);
        assert_eq!(BasicTimeStampingProfile.policy(NOW).current_time_unix, NOW);
        assert_eq!(
            BasicOcspResponderProfile.policy(NOW).current_time_unix,
            NOW
        );
    }

    #[test]
    fn basic_tls_client_policy_requires_client_auth_eku() {
        let p = BasicTlsClientProfile.policy(NOW);
        let eku = p.required_leaf_eku.expect("EKU must be required");
        assert_eq!(eku.len(), 1, "exactly one EKU expected");
        assert_eq!(eku[0], ID_KP_CLIENT_AUTH);
        // No SAN requirement: client-auth deployments commonly carry the
        // identity in the Subject DN rather than a SAN. The wrapper layer
        // (verify_tls_client_dns / verify_tls_client_mailbox) handles
        // caller-supplied SAN binding independently.
        assert!(
            !p.require_subject_alt_name,
            "BasicTlsClientProfile must not require SAN (unlike BasicTlsProfile)"
        );
        assert!(!p.require_rfc822_san);
    }

    /// OID pin: `id-kp-clientAuth` is `1.3.6.1.5.5.7.3.2` per RFC 5280
    /// §4.2.1.12. Locks the OID against accidental drift.
    #[test]
    fn id_kp_client_auth_oid_pinned() {
        assert_eq!(
            ID_KP_CLIENT_AUTH.to_string(),
            "1.3.6.1.5.5.7.3.2",
            "id-kp-clientAuth OID must match RFC 5280 §4.2.1.12"
        );
    }

    #[test]
    fn basic_code_signing_policy_requires_code_signing_eku() {
        let p = BasicCodeSigningProfile.policy(NOW);
        let eku = p.required_leaf_eku.expect("EKU must be required");
        assert_eq!(eku.len(), 1, "exactly one EKU expected");
        assert_eq!(eku[0], ID_KP_CODE_SIGNING);
        // No SAN requirement (code signing has no caller-supplied identity).
        assert!(!p.require_subject_alt_name);
        assert!(!p.require_rfc822_san);
    }

    #[test]
    fn basic_time_stamping_policy_requires_time_stamping_eku() {
        let p = BasicTimeStampingProfile.policy(NOW);
        let eku = p.required_leaf_eku.expect("EKU must be required");
        assert_eq!(eku.len(), 1, "exactly one EKU expected");
        assert_eq!(eku[0], ID_KP_TIME_STAMPING);
        // No SAN requirement (TSA cert has no caller-supplied identity).
        assert!(!p.require_subject_alt_name);
        assert!(!p.require_rfc822_san);
    }

    #[test]
    fn basic_ocsp_responder_policy_requires_ocsp_signing_eku() {
        let p = BasicOcspResponderProfile.policy(NOW);
        let eku = p.required_leaf_eku.expect("EKU must be required");
        assert_eq!(eku.len(), 1, "exactly one EKU expected");
        assert_eq!(eku[0], ID_KP_OCSP_SIGNING);
        // No SAN requirement (OCSP responder cert has no caller-supplied
        // identity target).
        assert!(!p.require_subject_alt_name);
        assert!(!p.require_rfc822_san);
    }

    /// OID pin: `id-kp-OCSPSigning` is `1.3.6.1.5.5.7.3.9` per RFC 6960
    /// §4.2.2.2. Locks the OID against accidental drift.
    #[test]
    fn id_kp_ocsp_signing_oid_pinned() {
        assert_eq!(
            ID_KP_OCSP_SIGNING.to_string(),
            "1.3.6.1.5.5.7.3.9",
            "id-kp-OCSPSigning OID must match RFC 6960 §4.2.2.2"
        );
    }

    #[test]
    fn profile_policy_matches_free_function() {
        let via_trait = Rfc5280Profile.policy(NOW);
        let via_fn = rfc5280_policy(NOW);
        assert_eq!(
            via_trait, via_fn,
            "Rfc5280Profile.policy and rfc5280_policy must agree"
        );

        let via_trait = BasicTlsProfile.policy(NOW);
        let via_fn = basic_tls_policy(NOW);
        assert_eq!(
            via_trait, via_fn,
            "BasicTlsProfile.policy and basic_tls_policy must agree"
        );

        let via_trait = BasicTlsClientProfile.policy(NOW);
        let via_fn = basic_tls_client_policy(NOW);
        assert_eq!(
            via_trait, via_fn,
            "BasicTlsClientProfile.policy and basic_tls_client_policy must agree"
        );

        let via_trait = BasicSmimeProfile.policy(NOW);
        let via_fn = basic_smime_policy(NOW);
        assert_eq!(
            via_trait, via_fn,
            "BasicSmimeProfile.policy and basic_smime_policy must agree"
        );

        let via_trait = BasicCodeSigningProfile.policy(NOW);
        let via_fn = basic_code_signing_policy(NOW);
        assert_eq!(
            via_trait, via_fn,
            "BasicCodeSigningProfile.policy and basic_code_signing_policy must agree"
        );

        let via_trait = BasicTimeStampingProfile.policy(NOW);
        let via_fn = basic_time_stamping_policy(NOW);
        assert_eq!(
            via_trait, via_fn,
            "BasicTimeStampingProfile.policy and basic_time_stamping_policy must agree"
        );

        let via_trait = BasicOcspResponderProfile.policy(NOW);
        let via_fn = basic_ocsp_responder_policy(NOW);
        assert_eq!(
            via_trait, via_fn,
            "BasicOcspResponderProfile.policy and basic_ocsp_responder_policy must agree"
        );
    }

    // -----------------------------------------------------------------------
    // Rfc5280Profile basic sanity
    // -----------------------------------------------------------------------

    #[test]
    fn rfc5280_policy_has_no_constraints() {
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
    // BasicTlsProfile field-value checks
    //
    // Oracle: RFC 5280 §4.2.1.12 + RFC 6125 §6 specify these requirements.
    // Asserting the returned struct matches the standards-body text.
    // -----------------------------------------------------------------------

    #[test]
    fn basic_tls_policy_requires_san() {
        let p = basic_tls_policy(NOW);
        assert!(
            p.require_subject_alt_name,
            "basic_tls_policy: require_subject_alt_name must be true (RFC 6125 §6)"
        );
    }

    #[test]
    fn basic_tls_policy_requires_server_auth_eku() {
        let p = basic_tls_policy(NOW);
        let ekus = p.required_leaf_eku.as_deref().unwrap_or(&[]);
        assert!(
            ekus.contains(&ID_KP_SERVER_AUTH),
            "basic_tls_policy: required_leaf_eku must contain id-kp-serverAuth"
        );
    }

    #[test]
    fn basic_tls_policy_has_no_cabf_constraints() {
        // The whole point of BasicTlsProfile: no CA/B Forum overlay.
        let p = basic_tls_policy(NOW);
        assert!(
            p.max_validity_secs.is_none(),
            "basic_tls_policy must not set max_validity_secs (CA/B Forum overlay)"
        );
        assert!(
            p.allowed_signature_algs.is_none(),
            "basic_tls_policy must not set allowed_signature_algs (CA/B Forum overlay)"
        );
        assert!(
            p.min_rsa_key_bits.is_none(),
            "basic_tls_policy must not set min_rsa_key_bits (CA/B Forum overlay)"
        );
    }

    /// Oracle: webpki-self-signed-365d.der — 365 days, self-signed, SAN, serverAuth EKU.
    /// Without CA/B Forum overlay, any validity period is accepted.
    #[test]
    fn basic_tls_conforming_cert_passes() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/webpki-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        pkix_path::validate_path(
            &[cert],
            &anchors,
            &basic_tls_policy(NOW),
            &EcdsaP256Verifier,
        )
        .expect("self-signed cert with SAN and serverAuth EKU must pass basic_tls_policy");
    }

    /// A cert with `emailProtection` (not `serverAuth`) must be rejected.
    #[test]
    fn basic_tls_wrong_eku_rejected() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/webpki-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        let mut policy = basic_tls_policy(NOW);
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
    // BasicSmimeProfile field-value checks
    //
    // Oracle: RFC 8551 §3 specifies these requirements.
    // -----------------------------------------------------------------------

    #[test]
    fn basic_smime_policy_requires_email_protection_eku() {
        let p = basic_smime_policy(NOW);
        let ekus = p.required_leaf_eku.as_deref().unwrap_or(&[]);
        assert!(
            ekus.contains(&ID_KP_EMAIL_PROTECTION),
            "basic_smime_policy: required_leaf_eku must contain id-kp-emailProtection"
        );
    }

    #[test]
    fn basic_smime_policy_requires_rfc822_san() {
        let p = basic_smime_policy(NOW);
        assert!(
            p.require_subject_alt_name,
            "basic_smime_policy: require_subject_alt_name must be true"
        );
        assert!(
            p.require_rfc822_san,
            "basic_smime_policy: require_rfc822_san must be true (RFC 8551 §3)"
        );
    }

    #[test]
    fn basic_smime_policy_has_no_cabf_constraints() {
        let p = basic_smime_policy(NOW);
        assert!(
            p.max_validity_secs.is_none(),
            "basic_smime_policy must not set max_validity_secs (CA/B Forum overlay)"
        );
        assert!(
            p.allowed_signature_algs.is_none(),
            "basic_smime_policy must not set allowed_signature_algs (CA/B Forum overlay)"
        );
        assert!(
            p.min_rsa_key_bits.is_none(),
            "basic_smime_policy must not set min_rsa_key_bits (CA/B Forum overlay)"
        );
    }

    /// Oracle: smime-self-signed-365d.der has SAN=rfc822Name:test@example.com
    /// and emailProtection EKU.
    #[test]
    fn basic_smime_conforming_cert_passes() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/smime-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        pkix_path::validate_path(
            &[cert],
            &anchors,
            &basic_smime_policy(NOW),
            &EcdsaP256Verifier,
        )
        .expect("cert with rfc822Name SAN and emailProtection EKU must pass basic_smime_policy");
    }

    /// Cert with dNSName-only SAN must fail with MissingRfc822San.
    #[test]
    fn basic_smime_dnsname_only_san_fails() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/webpki-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        let mut policy = basic_smime_policy(NOW);
        // webpki-self-signed-365d has serverAuth EKU; override required EKU to serverAuth
        // so the EKU check passes and the rfc822Name SAN type check fires.
        policy.required_leaf_eku = Some(vec![ID_KP_SERVER_AUTH]);
        assert!(
            matches!(
                pkix_path::validate_path(&[cert], &anchors, &policy, &EcdsaP256Verifier),
                Err(pkix_path::Error::MissingRfc822San)
            ),
            "cert with dNSName-only SAN must fail basic_smime_policy with MissingRfc822San"
        );
    }

    // -----------------------------------------------------------------------
    // Deprecated re-exports: confirm they still resolve to the new crate.
    //
    // The re-exports are scheduled to drop in pkix-profiles 0.4.0; these tests
    // exist to catch accidental removal before that release, and to confirm
    // the deprecated symbols are still callable (with #[allow(deprecated)]).
    // -----------------------------------------------------------------------

    #[test]
    #[allow(deprecated)]
    fn deprecated_reexports_resolve_to_cabf_crate() {
        // sc081_validity_cap from pkix-profiles must equal the one from
        // pkix-profiles-cabf (same symbol via re-export).
        assert_eq!(
            crate::sc081_validity_cap(1_773_532_800),
            pkix_profiles_cabf::sc081_validity_cap(1_773_532_800),
            "deprecated re-export must resolve to pkix-profiles-cabf"
        );
    }

    #[test]
    #[allow(deprecated)]
    fn deprecated_profile_reexports_have_same_ids() {
        // Compare via Profile trait without any name collision.
        let tls_via_old: crate::WebPkiProfile = crate::WebPkiProfile;
        let tls_via_new: pkix_profiles_cabf::WebPkiProfile = pkix_profiles_cabf::WebPkiProfile;
        assert_eq!(
            tls_via_old.id(),
            tls_via_new.id(),
            "deprecated WebPkiProfile re-export must resolve to pkix-profiles-cabf"
        );
    }
}
