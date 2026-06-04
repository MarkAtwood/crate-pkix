//! # pkix-profiles-cabf
//!
//! **Reference implementation of CA/Browser Forum cert profile requirements. Not authoritative.**
//!
//! CA/B Forum Baseline Requirements (TLS BR, S/MIME BR, Code Signing BR) change
//! on a ballot cycle. The implementations in this crate are a small, curated
//! snapshot of marquee BR requirements. They are intended as a starting point:
//! fork and adapt to your deployment's current interpretation of the BR text,
//! which is the only canonical source.
//!
//! For the current Baseline Requirements:
//! - <https://cabforum.org/baseline-requirements/> (TLS)
//! - <https://cabforum.org/smime-br/> (S/MIME)
//! - <https://cabforum.org/code-signing-baseline-requirements/> (Code Signing)
//!
//! Maintained on a best-effort basis. If your deployment depends on bit-exact
//! CA/B Forum conformance, you SHOULD vendor and review the relevant rule
//! definitions yourself, or use `pkix-policy-zlint` (see below).
//!
//! # Unprincipled exception
//!
//! This crate is an **explicit, bounded violation** of the workspace's
//! no-transcription rule (AGENTS.md non-negotiable #5, three-mode policy-class
//! architecture). Under that rule, industry-forum / vendor policies (CA/B
//! Forum BR, Mozilla / Apple / Microsoft root programs, ETSI, DoD, FedRAMP,
//! individual CA CPSs) are NOT transcribed into Rust — they are consumed via
//! sibling policy-adapter crates (`pkix-policy-zlint`, `pkix-policy-pkilint`)
//! that defer to the upstream maintainer's tool at runtime.
//!
//! This crate does contain Rust transcriptions of CA/B Forum BR rules and
//! does violate that rule. It exists because (a) CA/B Forum BR is the
//! most-asked-about industry-forum spec, and (b) a small marquee-violation
//! reference is useful for downstream consumers comparing their interpretation
//! against the workspace's.
//!
//! The exception is **not a template.** No equivalent `pkix-profiles-mozilla`,
//! `pkix-profiles-fedramp`, `pkix-profiles-dod`, or `pkix-profiles-etsi`
//! crates are admitted without explicit human re-decision. For comprehensive
//! CA/B Forum coverage (matching zlint's ~700-lint scope), use
//! `pkix-policy-zlint` (PKIX-jy95).
//!
//! # Reporting divergences
//!
//! This crate is a snapshot interpretation of the CA/B Forum Baseline
//! Requirements. The canonical source is the CA/B Forum's published BR
//! text; this crate is reference, not authoritative. See `divergences.md`
//! in this crate's source tree for the spec versions last refreshed
//! against and the known intentional divergences.
//!
//! If you find that a constraint in this crate differs from what the
//! current CA/B Forum BR says — wrong section reference, outdated rule,
//! missing new ballot — please open an issue or PR at
//! <https://github.com/MarkAtwood/crate-pkix>. Divergence fixes are
//! welcomed from anyone in the community; you do not need to be a
//! maintainer.
//!
//! Canonical BR sources:
//!
//! - TLS BR: <https://github.com/cabforum/servercert/blob/main/docs/BR.md>
//! - S/MIME BR: <https://github.com/cabforum/smime/blob/main/SBR.md>
//! - Code Signing BR: <https://github.com/cabforum/code-signing/blob/main/docs/CSBR.md>
//! - EV Guidelines: <https://github.com/cabforum/servercert/blob/main/docs/EVG.md>
//!
//! # Profiles
//!
//! S/MIME Profile types target either the **Strict generation** (`.3`
//! OID suffix — the modern canonical target per the AGENTS.md
//! spec-taxonomy principle PKIX-mzsk) or the **Multipurpose generation**
//! (`.2` OID suffix — sibling profiles per the PKIX-jbvb.9 epic).
//! Legacy generation (`.1`) is BR-banned for new issuance effective
//! 2025-07-15 per S/MIME BR §7.1.6.1 and is not represented here.
//!
//! | Struct | Free-function alias | Document | Key constraints |
//! |--------|--------------------|---------| ----------------|
//! | [`WebPkiProfile`] | [`web_pki_policy`] | CA/B Forum TLS BR | SAN required, SHA-1 prohibited, RSA ≥ 2048 |
//! | [`SmimeProfile`] | [`smime_policy`] | CA/B Forum S/MIME BR | Mailbox-validated Strict: rfc822Name SAN, emailProtection EKU, max validity 825 days |
//! | [`SmimeSponsorValidated`] | [`smime_sponsor_policy`] | CA/B Forum S/MIME BR §7.5 | Mailbox baseline + policy OID 2.23.140.1.5.3.3 + Subject DN organizationName ∧ organizationIdentifier ∧ ((givenName ∧ surname) ∨ pseudonym) |
//! | [`SmimeSponsorValidatedMultipurpose`] | [`smime_sponsor_multipurpose_policy`] | CA/B Forum S/MIME BR §7.5 (Multipurpose row) | Mailbox baseline + policy OID 2.23.140.1.5.3.2 + Subject DN organizationName ∧ organizationIdentifier ∧ ((givenName ∧ surname) ∨ pseudonym) + additional EKUs permitted |
//! | [`SmimeIndividualValidated`] | [`smime_individual_policy`] | CA/B Forum S/MIME BR §7.6 | Mailbox baseline + policy OID 2.23.140.1.5.4.3 + Subject DN (givenName+surname) ∨ pseudonym |
//! | [`SmimeIndividualValidatedMultipurpose`] | [`smime_individual_multipurpose_policy`] | CA/B Forum S/MIME BR §7.6 (Multipurpose row) | Mailbox baseline + policy OID 2.23.140.1.5.4.2 + Subject DN (givenName+surname) ∨ pseudonym + additional EKUs permitted |
//! | [`CodeSigningProfile`] | [`code_signing_policy`] | CA/B Forum Code Signing BR | codeSigning EKU, RSA ≥ 3072 |
//!
//! For RFC 5280 baseline and `BasicTlsProfile` / `BasicSmimeProfile` (RFC 8551
//! §3 baseline), see the upstream [`pkix-profiles`] crate.
//!
//! # Usage
//!
//! ```rust,no_run
//! use pkix_profiles_cabf::{WebPkiProfile, web_pki_policy};
//! use pkix_path::Profile;
//!
//! let now_unix = 1_700_000_000_u64;
//!
//! // Via the Profile trait (for generic code or registries):
//! let profile = WebPkiProfile;
//! let policy = profile.policy(now_unix);
//! # let _ = policy;
//!
//! // Via free-function alias (for quick one-liners):
//! let policy = web_pki_policy(now_unix);
//! # let _ = policy;
//! ```
//!
//! # Stance
//!
//! - AGENTS.md non-negotiable #5 — three-mode policy-class architecture,
//!   including the unprincipled-exception clause that admits this crate.
//! - Stance / epic: [PKIX-amgn].
//!
//! # Limitations
//!
//! - **Reference, not authoritative.** See the unprincipled-exception
//!   clause above. The BR text is the only canonical source; this crate
//!   ships a curated subset.
//! - **Subscriber-cert taxonomy only.** Per the AGENTS.md spec-taxonomy
//!   principle (`PKIX-mzsk`), this crate ships idiomatic Rust [`Profile`]
//!   types for each subscriber-certificate profile explicitly named in
//!   the BR. CA-cert / Root-cert profile machinery is not duplicated
//!   here — that is the path validator's job (RFC 5280 §6.1, in
//!   `pkix-path`). Per-predicate Lint enforcement is not in scope —
//!   that is `pkix-policy-zlint`'s job.
//! - **S/MIME BR sub-profile families partially split.** [`SmimeProfile`]
//!   ships the Mailbox-validated tier baseline targeting the Strict generation;
//!   [`SmimeSponsorValidated`] ships the Sponsor-validated tier (§7.5) Strict
//!   generation; [`SmimeSponsorValidatedMultipurpose`] ships the
//!   Sponsor-validated tier (§7.5) Multipurpose generation;
//!   [`SmimeIndividualValidated`] ships the Individual-validated
//!   tier (§7.6) Strict generation; [`SmimeIndividualValidatedMultipurpose`]
//!   ships the Individual-validated tier (§7.6) Multipurpose generation;
//!   the Organization-validated tier (Strict) and the Mailbox / Organization
//!   Multipurpose siblings remain tracked under `PKIX-jbvb`
//!   (Org Strict: PKIX-jbvb.1; remaining Multipurpose siblings: PKIX-jbvb.9).
//!   Legacy generation (`.1`) Profile types are not shipped — Legacy
//!   issuance was BR-banned effective 2025-07-15 per §7.1.6.1.
//! - **No `-mozilla`, `-fedramp`, `-dod`, `-etsi`.** Cross-spec horizontal
//!   expansion is barred by the AGENTS.md spec-taxonomy clause. Other
//!   industry-forum / vendor / government policies must come in via
//!   policy-adapter crates that defer to upstream tools, not via
//!   workspace-internal transcription.
//!
//! [PKIX-amgn]: https://github.com/MarkAtwood/crate-pkix
//! [`pkix-profiles`]: https://docs.rs/pkix-profiles
//! [`Profile`]: https://docs.rs/pkix-path/latest/pkix_path/trait.Profile.html

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

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
/// Canonical source: [TLS BR §7.1.3 Algorithm object identifiers](https://github.com/cabforum/servercert/blob/main/docs/BR.md#713-algorithm-object-identifiers).
///
/// SHA-1 (`sha1WithRSAEncryption`, `ecdsa-with-SHA1`) is intentionally absent.
/// The list currently matches S/MIME BR §7.1.3 and CS BR §7.1.3, but they are
/// maintained as separate constants because each regime may diverge independently.
pub const CABF_TLS_BR_ALLOWED_ALGS: &[ObjectIdentifier] = &[
    SHA256_WITH_RSA,
    SHA384_WITH_RSA,
    SHA512_WITH_RSA,
    ECDSA_WITH_SHA256,
    ECDSA_WITH_SHA384,
    ECDSA_WITH_SHA512,
];

/// CA/B Forum S/MIME BR §7.1.3 — approved signature algorithms for S/MIME certificates.
///
/// Canonical source: [S/MIME BR §7.1.3 Algorithm object identifiers](https://github.com/cabforum/smime/blob/main/SBR.md#713-algorithm-object-identifiers).
///
/// Currently identical to [`CABF_TLS_BR_ALLOWED_ALGS`] but maintained independently
/// because the S/MIME BR algorithm policy may diverge from TLS BR in future ballots.
pub const CABF_SMIME_BR_ALLOWED_ALGS: &[ObjectIdentifier] = &[
    SHA256_WITH_RSA,
    SHA384_WITH_RSA,
    SHA512_WITH_RSA,
    ECDSA_WITH_SHA256,
    ECDSA_WITH_SHA384,
    ECDSA_WITH_SHA512,
];

/// CA/B Forum Code Signing BR §7.1.3 — approved signature algorithms for CS certificates.
///
/// Canonical source: [CS BR §7.1.3 Algorithm object identifiers](https://github.com/cabforum/code-signing/blob/main/docs/CSBR.md#713-algorithm-object-identifiers).
///
/// Currently identical to TLS BR list. Code Signing BR also requires RSA ≥ 3072 bits;
/// that is enforced via [`ValidationPolicy::min_rsa_key_bits`], not via this list.
pub const CABF_CS_BR_ALLOWED_ALGS: &[ObjectIdentifier] = &[
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

// Subject DN attribute OIDs (RFC 4519 / X.520).
//
// Used by S/MIME BR sub-profile families (Individual / Sponsor / Organization)
// to construct the `required_leaf_subject_dn_attrs` rule in their
// `ValidationPolicy` outputs.
pub(crate) const OID_SURNAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.4");
pub(crate) const OID_ORGANIZATION_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
pub(crate) const OID_GIVEN_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.42");
pub(crate) const OID_PSEUDONYM: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.65");
pub(crate) const OID_ORGANIZATION_IDENTIFIER: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.4.97");

// CA/B Forum S/MIME BR reserved policy OIDs (§7.1.6.1 / Appendix A).
//
// Each (validation type, generation) cell has its own OID. The `-cabf` crate
// ships Profile types targeting the **Strict** generation (`.3` suffix) as
// the modern canonical target per the AGENTS.md spec-taxonomy principle
// (PKIX-mzsk), plus **Multipurpose** generation (`.2` suffix) sibling
// types per PKIX-jbvb.9 (decision recorded in PKIX-jbvb.8).
//
// Legacy generation (`.1` suffix) is BR-banned for new issuance effective
// 2025-07-15 per §7.1.6.1 line 2600 and is intentionally not represented here.
// Multipurpose generation (`.2` suffix) is a transitional bridge for
// document-signing crossover use cases; Multipurpose Profile types ship as
// Strict siblings under the PKIX-jbvb.9 implementation epic.
pub(crate) const CABF_SMIME_SPONSOR_VALIDATED_STRICT_POLICY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.23.140.1.5.3.3");
pub(crate) const CABF_SMIME_INDIVIDUAL_VALIDATED_STRICT_POLICY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.23.140.1.5.4.3");
pub(crate) const CABF_SMIME_INDIVIDUAL_VALIDATED_MULTIPURPOSE_POLICY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.23.140.1.5.4.2");
pub(crate) const CABF_SMIME_SPONSOR_VALIDATED_MULTIPURPOSE_POLICY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.23.140.1.5.3.2");

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
/// # Canonical source
///
/// Canonical CA/B Forum TLS BR document:
/// <https://github.com/cabforum/servercert/blob/main/docs/BR.md>
///
/// Specific section anchors for this profile's constraints are listed in
/// the [`web_pki_policy`] free-function rustdoc.
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
        // Dotted spec version of the TLS BR document this profile was last
        // refreshed against. The current BR text is the canonical source;
        // this string is informational only.
        "2.2.6"
    }

    fn policy(&self, now_unix: u64) -> ValidationPolicy {
        let mut p = ValidationPolicy::new(now_unix);
        // SC-081 validity cap enforcement is NOT set here; see struct-level doc.
        // BR §7.1.3: SHA-1 prohibited.
        p.allowed_signature_algs = Some(CABF_TLS_BR_ALLOWED_ALGS.to_vec());
        // BR §6.1.5: RSA keys must be at least 2048 bits.
        p.min_rsa_key_bits = Some(2048);
        // BR §7.1.2.7.12 (Subscriber Certificate Subject Alternative Name):
        // SAN must be present and non-empty on the leaf.
        p.require_subject_alt_name = true;
        // BR §7.1.2.7.10 (Subscriber Certificate Extended Key Usage):
        // id-kp-serverAuth must be asserted in the leaf's EKU.
        p.required_leaf_eku = Some(vec![ID_KP_SERVER_AUTH]);
        // Note: TLS BR 2.2.6 does not impose a numeric chain-depth cap.
        // pathLenConstraint enforcement on individual CA certs is handled
        // by RFC 5280 §4.2.1.9 in pkix-path.
        p
    }

    fn policy_oids(&self) -> &[ObjectIdentifier] {
        // CA/B Forum does not define an OID for the TLS BR policy itself;
        // cert policy OIDs are issued by individual CAs, not by the Forum.
        &[]
    }
}

impl pkix_lint::LintProfile for WebPkiProfile {
    /// Return the canonical list of CA/B Forum TLS BR lints bundled with this profile.
    ///
    /// The returned slice is backed by a lazily-initialized `static OnceLock`,
    /// so calling `lints()` multiple times is cheap. The lint instances inside
    /// the slice are different objects from those used inside a [`pkix_lint::LintRunner`]
    /// produced by [`lint_runner`](#method.lint_runner): each call to
    /// `lint_runner()` allocates a fresh set of instances via
    /// [`pkix_lint_cabf::cabf_tls_br::all_lints`]. Both routes source their
    /// lint types from the same constructor; the objects are distinct
    /// allocations. The set of lint IDs is identical.
    fn lints(&self) -> &[Box<dyn pkix_lint::Lint>] {
        // `OnceLock` (stable since Rust 1.70) gives us a lazily-initialized
        // static `Vec<Box<dyn Lint>>` whose reference outlives `&self`.
        static LINTS: std::sync::OnceLock<Vec<Box<dyn pkix_lint::Lint>>> =
            std::sync::OnceLock::new();
        LINTS.get_or_init(pkix_lint_cabf::cabf_tls_br::all_lints)
    }

    /// Allocate a fresh [`pkix_lint::LintRunner`] backed by a new set of
    /// CA/B Forum TLS BR lint instances on each call.
    ///
    /// For repeated use, cache the returned [`pkix_lint::LintRunner`] at the
    /// call site rather than calling this method on every evaluation.
    fn lint_runner(&self) -> pkix_lint::LintRunner {
        pkix_lint::LintRunner::new(pkix_lint_cabf::cabf_tls_br::all_lints())
    }
}

/// CA/Browser Forum S/MIME Baseline Requirements profile (Mailbox-validated, Strict generation).
///
/// Implements [`Profile`] for the Mailbox-validated tier baseline targeting
/// the **Strict generation**. Per S/MIME BR glossary (§372), Strict is the
/// "long term target profile for S/MIME Certificates" — `extKeyUsage`
/// limited to `id-kp-emailProtection`, stricter Subject DN attribute use,
/// stricter extension handling. The free-function alias [`smime_policy`]
/// is equivalent to `SmimeProfile.policy(now_unix)`.
///
/// Sibling tier profiles ([`SmimeSponsorValidated`], [`SmimeIndividualValidated`])
/// also target the Strict generation. The Organization-validated tier profile
/// is tracked as PKIX-jbvb.
///
/// # Canonical source
///
/// Canonical CA/B Forum S/MIME BR document:
/// <https://github.com/cabforum/smime/blob/main/SBR.md>
///
/// Specific section anchors for this profile's constraints are listed in
/// the [`smime_policy`] free-function rustdoc.
///
/// # Limitations
///
/// Only the Mailbox-validated tier is enforced by this struct. Organization-validated
/// is tracked as PKIX-jbvb.1; Sponsor-validated and Individual-validated ship
/// as [`SmimeSponsorValidated`] and [`SmimeIndividualValidated`].
///
/// **Legacy generation is not represented.** Per S/MIME BR §7.1.6.1 line 2600,
/// Legacy generation (policy OIDs `.1`) was banned for new issuance effective
/// 2025-07-15. Callers wanting to validate Legacy-tier certs issued before
/// the ban must construct a custom [`ValidationPolicy`] or use
/// `pkix-policy-zlint`. Multipurpose generation (policy OIDs `.2`) sibling
/// Profile types ship incrementally per the PKIX-jbvb.9 epic;
/// [`SmimeIndividualValidatedMultipurpose`] and
/// [`SmimeSponsorValidatedMultipurpose`] are shipped.
///
/// [`ValidationPolicy::max_validity_secs`] applies to **every** certificate in
/// the chain, not just the leaf. Typical S/MIME CA certificates have validity
/// periods of 10–20 years (well over 825 days). Callers using `SmimeProfile`
/// with a standard S/MIME CA hierarchy will see validation failures on the
/// intermediate or root CA certificates. To avoid this, use a custom policy
/// that sets only the leaf validity cap, or construct the chain with CA
/// certificates whose validity is within 825 days.
///
/// Revocation checking (OCSP/CRL) is out of scope; use `pkix-revocation`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SmimeProfile;

impl Profile for SmimeProfile {
    fn id(&self) -> &'static str {
        "cabf.smime"
    }

    fn version(&self) -> &'static str {
        // Dotted spec version of the S/MIME BR document this profile was last
        // refreshed against. The current BR text is the canonical source;
        // this string is informational only.
        "1.0.14"
    }

    fn policy(&self, now_unix: u64) -> ValidationPolicy {
        let mut p = ValidationPolicy::new(now_unix);
        // S/MIME BR §6.3.2 (table): Strict and Multipurpose generation maximum
        // validity is 825 days. (Legacy was 1185 days but was banned for new
        // issuance effective 2025-07-15 per §7.1.6.1; the `-cabf` crate ships
        // Strict-targeted Profile types only.)
        p.max_validity_secs = Some(825 * SECS_PER_DAY);
        // S/MIME BR §7.1.3: SHA-1 prohibited.
        p.allowed_signature_algs = Some(CABF_SMIME_BR_ALLOWED_ALGS.to_vec());
        // S/MIME BR §6.1.5: RSA keys must be at least 2048 bits.
        p.min_rsa_key_bits = Some(2048);
        // Mailbox-validated: non-empty SAN required; must contain an rfc822Name entry.
        p.require_subject_alt_name = true;
        p.require_rfc822_san = true;
        // S/MIME BR §7.1.2.3(f) (Subscriber certificates / extKeyUsage):
        // id-kp-emailProtection must be asserted.
        p.required_leaf_eku = Some(vec![ID_KP_EMAIL_PROTECTION]);
        // Note: S/MIME BR 1.0.14 does not impose a numeric chain-depth cap.
        // pathLenConstraint enforcement on individual CA certs is handled
        // by RFC 5280 §4.2.1.9 in pkix-path.
        p
    }

    fn policy_oids(&self) -> &[ObjectIdentifier] {
        &[]
    }
}

impl pkix_lint::LintProfile for SmimeProfile {
    /// Return the CA/B Forum S/MIME BR lint set for this profile.
    ///
    /// **Currently empty.** `pkix-lint-cabf` does not yet ship a
    /// `cabf_smime_br` lint module; per AGENTS.md non-negotiable #5, the
    /// path of least surface area is to wait for either a curated marquee
    /// set (sibling to `cabf_tls_br`) or to rely on `pkix-policy-zlint` for
    /// comprehensive predicate coverage. Until those land, this profile's
    /// `LintProfile` impl returns no lints.
    ///
    /// Callers needing RFC-baseline S/MIME shape checks should call
    /// `pkix_profiles::check_basic_smime_shape` separately, which bundles
    /// RFC 8551 + RFC 8398 + RFC 5280 baseline lints.
    fn lints(&self) -> &[Box<dyn pkix_lint::Lint>] {
        static LINTS: std::sync::OnceLock<Vec<Box<dyn pkix_lint::Lint>>> =
            std::sync::OnceLock::new();
        LINTS.get_or_init(Vec::new)
    }

    fn lint_runner(&self) -> pkix_lint::LintRunner {
        pkix_lint::LintRunner::new(Vec::new())
    }
}

/// CA/Browser Forum S/MIME Baseline Requirements — Individual-validated profile (Strict generation).
///
/// Implements [`Profile`] for the S/MIME BR Individual-validated subscriber-
/// certificate tier targeting the **Strict generation**. Per S/MIME BR §7.6
/// (Individual Validated), the subscriber's real-world identity is verified
/// (typically via passport, national ID, driver's license, or equivalent
/// evidence) and the cert asserts policy OID `2.23.140.1.5.4.3` plus
/// tier-specific Subject DN attributes.
///
/// The free-function alias [`smime_individual_policy`] is equivalent to
/// `SmimeIndividualValidated.policy(now_unix)`.
///
/// # Canonical source
///
/// Canonical CA/B Forum S/MIME BR document:
/// <https://github.com/cabforum/smime/blob/main/SBR.md>
///
/// Tier-specific section: §7.6 (Individual Validated subscriber certificates).
/// Reserved policy OID: §7.1.6.1 / Appendix A (`2.23.140.1.5.4.3` — Strict generation).
///
/// # Tier discrimination
///
/// Distinct from [`SmimeProfile`] (Mailbox-validated baseline) by:
///
/// - **Asserted policy OID** `2.23.140.1.5.4.3` (Individual-validated Strict)
///   is required on the leaf's `CertificatePolicies` extension. Mailbox-validated
///   certs lacking the OID fail with [`pkix_path::Error::MissingLeafPolicyOid`].
/// - **Subject DN** must satisfy: `(givenName AND surname) OR pseudonym` per
///   §7.1.4.2.6 Note 2 (Strict and Multipurpose Generation profiles SHALL
///   include either givenName and/or surname, or the pseudonym). Certs that
///   assert the policy OID but lack the tier-specific DN attributes fail
///   with [`pkix_path::Error::SubjectDnAttrRuleUnmet`].
///
/// # Limitations
///
/// Reference, not authoritative. See the crate-level "Unprincipled
/// exception" rustdoc. The BR text is the only canonical source.
///
/// **Legacy generation is not represented.** Per §7.1.6.1 line 2600, Legacy
/// generation (policy OID `2.23.140.1.5.4.1`) was banned for new issuance
/// effective 2025-07-15. This struct targets the Strict generation only;
/// see [`SmimeProfile`]'s rustdoc for the broader rationale.
///
/// The validation-side check is structural: the cert *carries* the
/// tier-marker policy OID and DN attributes. The BR's CA-side
/// identity-proofing requirements (passport / national ID / etc.) are not
/// validator-side concerns — this profile checks the cert AS IF the issuing
/// CA correctly proofed the subscriber.
///
/// `max_validity_secs` applies to every certificate in the chain (matches
/// [`SmimeProfile`]'s shape); see that profile's limitations for the chain
/// composition implications.
///
/// [`SmimeProfile`]: crate::SmimeProfile
/// [`pkix_path::Error::MissingLeafPolicyOid`]: https://docs.rs/pkix-path/latest/pkix_path/enum.Error.html#variant.MissingLeafPolicyOid
/// [`pkix_path::Error::SubjectDnAttrRuleUnmet`]: https://docs.rs/pkix-path/latest/pkix_path/enum.Error.html#variant.SubjectDnAttrRuleUnmet
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SmimeIndividualValidated;

impl Profile for SmimeIndividualValidated {
    fn id(&self) -> &'static str {
        "cabf.smime.individual"
    }

    fn version(&self) -> &'static str {
        // Dotted spec version of the S/MIME BR document this profile was last
        // refreshed against; matches `SmimeProfile`'s version per PKIX-d5rh.
        "1.0.14"
    }

    fn policy(&self, now_unix: u64) -> ValidationPolicy {
        use pkix_path::DnAttrRule;

        let mut p = ValidationPolicy::new(now_unix);
        // S/MIME BR §6.3.2: Strict and Multipurpose generation max validity 825 days.
        p.max_validity_secs = Some(825 * SECS_PER_DAY);
        // S/MIME BR §7.1.3: SHA-1 prohibited.
        p.allowed_signature_algs = Some(CABF_SMIME_BR_ALLOWED_ALGS.to_vec());
        // S/MIME BR §6.1.5: RSA ≥ 2048 bits.
        p.min_rsa_key_bits = Some(2048);
        // Mailbox-validated baseline: non-empty SAN with at least one rfc822Name.
        p.require_subject_alt_name = true;
        p.require_rfc822_san = true;
        // S/MIME BR §7.1.2.3(f): id-kp-emailProtection EKU.
        p.required_leaf_eku = Some(vec![ID_KP_EMAIL_PROTECTION]);
        // S/MIME BR §7.1.6.1 (Reserved Certificate Policy Identifiers) / Appendix A:
        //   2.23.140.1.5.4.3 — Individual-validated subscriber, Strict generation.
        p.required_leaf_policy_oids = Some(vec![CABF_SMIME_INDIVIDUAL_VALIDATED_STRICT_POLICY]);
        // S/MIME BR §7.1.4.2.6 (Subject DN attributes for individual-validated
        // profile) Note 2: "Strict and Multipurpose Generation profiles SHALL
        // include either subject:givenName and/or subject:surname, or the
        // subject:pseudonym."
        //
        // serialNumber is MAY in all generations (§7.1.4.2.6 table column),
        // so we do not require it here.
        //
        // DN rule:
        //   AnyOf: pseudonym OR (givenName + surname)
        p.required_leaf_subject_dn_attrs = Some(DnAttrRule::AnyOf(vec![
            DnAttrRule::Field(OID_PSEUDONYM),
            DnAttrRule::AllOf(vec![
                DnAttrRule::Field(OID_GIVEN_NAME),
                DnAttrRule::Field(OID_SURNAME),
            ]),
        ]));
        p
    }

    fn policy_oids(&self) -> &[ObjectIdentifier] {
        &[]
    }
}

impl pkix_lint::LintProfile for SmimeIndividualValidated {
    /// Return the CA/B Forum S/MIME BR lint set for this profile.
    ///
    /// **Currently empty.** Matches [`SmimeProfile`]'s `LintProfile` shape;
    /// comprehensive predicate coverage belongs to `pkix-policy-zlint` per
    /// AGENTS.md non-negotiable #5.
    ///
    /// [`SmimeProfile`]: crate::SmimeProfile
    fn lints(&self) -> &[Box<dyn pkix_lint::Lint>] {
        static LINTS: std::sync::OnceLock<Vec<Box<dyn pkix_lint::Lint>>> =
            std::sync::OnceLock::new();
        LINTS.get_or_init(Vec::new)
    }

    fn lint_runner(&self) -> pkix_lint::LintRunner {
        pkix_lint::LintRunner::new(Vec::new())
    }
}

/// CA/Browser Forum S/MIME Baseline Requirements — Individual-validated profile (Multipurpose generation).
///
/// Implements [`Profile`] for the S/MIME BR Individual-validated subscriber-
/// certificate tier targeting the **Multipurpose generation**. Per S/MIME BR
/// §7.6 (Individual Validated), the subscriber's real-world identity is
/// verified (typically via passport, national ID, driver's license, or
/// equivalent evidence); the cert asserts policy OID `2.23.140.1.5.4.2` plus
/// tier-specific Subject DN attributes.
///
/// The free-function alias [`smime_individual_multipurpose_policy`] is
/// equivalent to `SmimeIndividualValidatedMultipurpose.policy(now_unix)`.
///
/// # Canonical source
///
/// Canonical CA/B Forum S/MIME BR document:
/// <https://github.com/cabforum/smime/blob/main/SBR.md>
///
/// Tier-specific section: §7.6 (Individual Validated subscriber certificates).
/// Reserved policy OID: §7.1.6.1 / Appendix A (`2.23.140.1.5.4.2` —
/// Multipurpose generation).
///
/// # Strict vs Multipurpose
///
/// Multipurpose generation differs from Strict in two respects:
///
/// - **Asserted policy OID** `2.23.140.1.5.4.2` instead of
///   [`SmimeIndividualValidated`]'s `2.23.140.1.5.4.3`.
/// - **EKU permissiveness** per §7.1.2.3(f) Multipurpose row: while
///   Strict-generation subscriber certs are constrained to assert
///   `id-kp-emailProtection` as the sole EKU, Multipurpose-generation
///   certs may additionally assert other EKU values (typically
///   document-signing crossover use cases such as `id-kp-codeSigning`).
///   The workspace `ValidationPolicy::required_leaf_eku` field is a
///   subset-of check (cert's EKU MUST contain each required OID; other
///   OIDs are permitted), so this Profile sets it to
///   `[ID_KP_EMAIL_PROTECTION]` — the cert must still carry
///   emailProtection, but additional EKUs are accepted. The "exactly
///   one EKU" enforcement on Strict-generation certs is a predicate
///   `ValidationPolicy` does not express; that audit belongs to
///   `pkix-policy-zlint` per AGENTS.md non-negotiable #5.
///
/// Subject DN rule is identical to Strict per §7.1.4.2.6 Note 2
/// ("Strict and Multipurpose Generation profiles SHALL include either
/// subject:givenName and/or subject:surname, or the subject:pseudonym").
/// Same 825-day validity cap per §6.3.2. Same Mailbox-validated baseline
/// (rfc822Name SAN, emailProtection EKU, SHA-256/384/512 algs, RSA ≥ 2048).
///
/// # Tier discrimination
///
/// Distinct from [`SmimeProfile`] (Mailbox-validated baseline) and from
/// [`SmimeIndividualValidated`] (Individual-validated Strict generation) by:
///
/// - **Asserted policy OID** `2.23.140.1.5.4.2` (Individual-validated
///   Multipurpose) is required on the leaf's `CertificatePolicies` extension.
///   Certs asserting a different tier or generation OID (or no OID) fail
///   with [`pkix_path::Error::MissingLeafPolicyOid`].
/// - **Subject DN** must satisfy: `(givenName AND surname) OR pseudonym`
///   per §7.1.4.2.6 Note 2 (Strict and Multipurpose Generation profiles
///   SHALL include either givenName and/or surname, or the pseudonym).
///   Certs asserting the policy OID but lacking the tier-specific DN
///   attributes fail with [`pkix_path::Error::SubjectDnAttrRuleUnmet`].
///
/// # Limitations
///
/// Reference, not authoritative. See the crate-level "Unprincipled
/// exception" rustdoc. The BR text is the only canonical source.
///
/// **Legacy generation is not represented.** Per §7.1.6.1 line 2600,
/// Legacy generation (policy OID `2.23.140.1.5.4.1`) was banned for new
/// issuance effective 2025-07-15. This struct targets the Multipurpose
/// generation; [`SmimeIndividualValidated`] targets the Strict generation.
///
/// **The "additional EKUs allowed" semantic is not validator-enforced
/// as a positive predicate.** The §7.1.2.3(f) BR table is structured as
/// "Strict permits only emailProtection; Multipurpose permits
/// emailProtection plus crossover EKUs". The Strict half is not
/// expressed by `ValidationPolicy` (no "forbidden EKU" or "exact EKU
/// set" field), so the Strict and Multipurpose Profiles only differ in
/// the asserted policy OID at the validator level. Comprehensive
/// enforcement of "Strict cert has emailProtection only" belongs to
/// `pkix-policy-zlint`.
///
/// The validation-side check is structural: the cert *carries* the
/// tier-marker policy OID and DN attributes. The BR's CA-side
/// identity-proofing requirements (passport / national ID / etc.) are not
/// validator-side concerns — this profile checks the cert AS IF the issuing
/// CA correctly proofed the subscriber.
///
/// `max_validity_secs` applies to every certificate in the chain (matches
/// [`SmimeProfile`]'s shape); see that profile's limitations for the chain
/// composition implications.
///
/// [`SmimeProfile`]: crate::SmimeProfile
/// [`SmimeIndividualValidated`]: crate::SmimeIndividualValidated
/// [`pkix_path::Error::MissingLeafPolicyOid`]: https://docs.rs/pkix-path/latest/pkix_path/enum.Error.html#variant.MissingLeafPolicyOid
/// [`pkix_path::Error::SubjectDnAttrRuleUnmet`]: https://docs.rs/pkix-path/latest/pkix_path/enum.Error.html#variant.SubjectDnAttrRuleUnmet
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SmimeIndividualValidatedMultipurpose;

impl Profile for SmimeIndividualValidatedMultipurpose {
    fn id(&self) -> &'static str {
        "cabf.smime.individual.multipurpose"
    }

    fn version(&self) -> &'static str {
        // Dotted spec version of the S/MIME BR document this profile was last
        // refreshed against; matches `SmimeIndividualValidated`'s version.
        "1.0.14"
    }

    fn policy(&self, now_unix: u64) -> ValidationPolicy {
        use pkix_path::DnAttrRule;

        let mut p = ValidationPolicy::new(now_unix);
        // S/MIME BR §6.3.2: Strict and Multipurpose generation max validity 825 days.
        p.max_validity_secs = Some(825 * SECS_PER_DAY);
        // S/MIME BR §7.1.3: SHA-1 prohibited.
        p.allowed_signature_algs = Some(CABF_SMIME_BR_ALLOWED_ALGS.to_vec());
        // S/MIME BR §6.1.5: RSA ≥ 2048 bits.
        p.min_rsa_key_bits = Some(2048);
        // Mailbox-validated baseline: non-empty SAN with at least one rfc822Name.
        p.require_subject_alt_name = true;
        p.require_rfc822_san = true;
        // S/MIME BR §7.1.2.3(f) Multipurpose row: id-kp-emailProtection EKU
        // is required; additional EKUs (e.g. id-kp-codeSigning) are permitted.
        // `required_leaf_eku` is a subset-of check, so additional EKUs pass
        // automatically. See struct rustdoc "Strict vs Multipurpose".
        p.required_leaf_eku = Some(vec![ID_KP_EMAIL_PROTECTION]);
        // S/MIME BR §7.1.6.1 (Reserved Certificate Policy Identifiers) / Appendix A:
        //   2.23.140.1.5.4.2 — Individual-validated subscriber, Multipurpose generation.
        p.required_leaf_policy_oids =
            Some(vec![CABF_SMIME_INDIVIDUAL_VALIDATED_MULTIPURPOSE_POLICY]);
        // S/MIME BR §7.1.4.2.6 (Subject DN attributes for individual-validated
        // profile) Note 2: "Strict and Multipurpose Generation profiles SHALL
        // include either subject:givenName and/or subject:surname, or the
        // subject:pseudonym."
        //
        // serialNumber is MAY in all generations (§7.1.4.2.6 table column),
        // so we do not require it here. Identical to the Strict generation
        // DN rule.
        //
        // DN rule:
        //   AnyOf: pseudonym OR (givenName + surname)
        p.required_leaf_subject_dn_attrs = Some(DnAttrRule::AnyOf(vec![
            DnAttrRule::Field(OID_PSEUDONYM),
            DnAttrRule::AllOf(vec![
                DnAttrRule::Field(OID_GIVEN_NAME),
                DnAttrRule::Field(OID_SURNAME),
            ]),
        ]));
        p
    }

    fn policy_oids(&self) -> &[ObjectIdentifier] {
        &[]
    }
}

impl pkix_lint::LintProfile for SmimeIndividualValidatedMultipurpose {
    /// Return the CA/B Forum S/MIME BR lint set for this profile.
    ///
    /// **Currently empty.** Matches [`SmimeIndividualValidated`]'s
    /// `LintProfile` shape; comprehensive predicate coverage belongs to
    /// `pkix-policy-zlint` per AGENTS.md non-negotiable #5.
    ///
    /// [`SmimeIndividualValidated`]: crate::SmimeIndividualValidated
    fn lints(&self) -> &[Box<dyn pkix_lint::Lint>] {
        static LINTS: std::sync::OnceLock<Vec<Box<dyn pkix_lint::Lint>>> =
            std::sync::OnceLock::new();
        LINTS.get_or_init(Vec::new)
    }

    fn lint_runner(&self) -> pkix_lint::LintRunner {
        pkix_lint::LintRunner::new(Vec::new())
    }
}

/// CA/Browser Forum S/MIME Baseline Requirements — Sponsor-validated profile (Strict generation).
///
/// Implements [`Profile`] for the S/MIME BR Sponsor-validated subscriber-
/// certificate tier targeting the **Strict generation**. Per S/MIME BR §7.5
/// (Sponsor Validated), an employer or sponsoring organization vouches for
/// the named individual: the cert carries BOTH organizational identity
/// (organizationName + organizationIdentifier) AND individual identity
/// (givenName + surname or pseudonym), and asserts policy OID
/// `2.23.140.1.5.3.3`.
///
/// The free-function alias [`smime_sponsor_policy`] is equivalent to
/// `SmimeSponsorValidated.policy(now_unix)`.
///
/// # Canonical source
///
/// Canonical CA/B Forum S/MIME BR document:
/// <https://github.com/cabforum/smime/blob/main/SBR.md>
///
/// Tier-specific section: §7.5 (Sponsor Validated subscriber certificates).
/// Reserved policy OID: §7.1.6.1 / Appendix A (`2.23.140.1.5.3.3` — Strict generation).
///
/// # Tier discrimination
///
/// Distinct from [`SmimeProfile`] (Mailbox-validated baseline) and
/// [`SmimeIndividualValidated`] (Individual-validated tier) by:
///
/// - **Asserted policy OID** `2.23.140.1.5.3.3` (Sponsor-validated Strict)
///   is required on the leaf's `CertificatePolicies` extension. Certs
///   asserting a different tier OID (or no OID) fail with
///   [`pkix_path::Error::MissingLeafPolicyOid`].
/// - **Subject DN** must satisfy: `organizationName AND
///   organizationIdentifier AND ((givenName AND surname) OR pseudonym)`
///   per §7.1.4.2.5 (organizationName + organizationIdentifier are SHALL
///   across all generations; Note 2 mandates givenName+surname or pseudonym
///   for Strict and Multipurpose). Certs lacking any of these (e.g.
///   Individual-validated certs without organizationName) fail with
///   [`pkix_path::Error::SubjectDnAttrRuleUnmet`].
///
/// # Limitations
///
/// Reference, not authoritative. See the crate-level "Unprincipled
/// exception" rustdoc. The BR text is the only canonical source.
///
/// **Legacy generation is not represented.** Per §7.1.6.1 line 2600, Legacy
/// generation (policy OID `2.23.140.1.5.3.1`) was banned for new issuance
/// effective 2025-07-15. This struct targets the Strict generation only;
/// see [`SmimeProfile`]'s rustdoc for the broader rationale.
///
/// The validation-side check is structural: the cert *carries* the
/// tier-marker policy OID and DN attributes. The BR's CA-side sponsorship-
/// proofing requirements (employment verification, etc.) are not
/// validator-side concerns — this profile checks the cert AS IF the
/// issuing CA correctly verified the sponsor-individual relationship.
///
/// `max_validity_secs` applies to every certificate in the chain (matches
/// [`SmimeProfile`]'s shape); see that profile's limitations for the chain
/// composition implications.
///
/// [`SmimeProfile`]: crate::SmimeProfile
/// [`SmimeIndividualValidated`]: crate::SmimeIndividualValidated
/// [`pkix_path::Error::MissingLeafPolicyOid`]: https://docs.rs/pkix-path/latest/pkix_path/enum.Error.html#variant.MissingLeafPolicyOid
/// [`pkix_path::Error::SubjectDnAttrRuleUnmet`]: https://docs.rs/pkix-path/latest/pkix_path/enum.Error.html#variant.SubjectDnAttrRuleUnmet
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SmimeSponsorValidated;

impl Profile for SmimeSponsorValidated {
    fn id(&self) -> &'static str {
        "cabf.smime.sponsor"
    }

    fn version(&self) -> &'static str {
        // Dotted spec version of the S/MIME BR document this profile was last
        // refreshed against; matches `SmimeProfile`'s version per PKIX-d5rh.
        "1.0.14"
    }

    fn policy(&self, now_unix: u64) -> ValidationPolicy {
        use pkix_path::DnAttrRule;

        let mut p = ValidationPolicy::new(now_unix);
        // S/MIME BR §6.3.2: Strict and Multipurpose generation max validity 825 days.
        p.max_validity_secs = Some(825 * SECS_PER_DAY);
        // S/MIME BR §7.1.3: SHA-1 prohibited.
        p.allowed_signature_algs = Some(CABF_SMIME_BR_ALLOWED_ALGS.to_vec());
        // S/MIME BR §6.1.5: RSA ≥ 2048 bits.
        p.min_rsa_key_bits = Some(2048);
        // Mailbox-validated baseline: non-empty SAN with at least one rfc822Name.
        p.require_subject_alt_name = true;
        p.require_rfc822_san = true;
        // S/MIME BR §7.1.2.3(f): id-kp-emailProtection EKU.
        p.required_leaf_eku = Some(vec![ID_KP_EMAIL_PROTECTION]);
        // S/MIME BR §7.1.6.1 (Reserved Certificate Policy Identifiers) / Appendix A:
        //   2.23.140.1.5.3.3 — Sponsor-validated subscriber, Strict generation.
        p.required_leaf_policy_oids = Some(vec![CABF_SMIME_SPONSOR_VALIDATED_STRICT_POLICY]);
        // S/MIME BR §7.1.4.2.5 (Subject DN attributes for sponsor-validated
        // profile): organizationName and organizationIdentifier are SHALL
        // across all generations. Note 2: "Strict and Multipurpose Generation
        // profiles SHALL include either subject:givenName and/or subject:surname,
        // or the subject:pseudonym."
        //
        // serialNumber is MAY in all generations (§7.1.4.2.5 table column),
        // so we do not require it here.
        //
        // DN rule:
        //   AllOf:
        //     organizationName
        //     organizationIdentifier
        //     AnyOf: pseudonym OR (givenName + surname)
        p.required_leaf_subject_dn_attrs = Some(DnAttrRule::AllOf(vec![
            DnAttrRule::Field(OID_ORGANIZATION_NAME),
            DnAttrRule::Field(OID_ORGANIZATION_IDENTIFIER),
            DnAttrRule::AnyOf(vec![
                DnAttrRule::Field(OID_PSEUDONYM),
                DnAttrRule::AllOf(vec![
                    DnAttrRule::Field(OID_GIVEN_NAME),
                    DnAttrRule::Field(OID_SURNAME),
                ]),
            ]),
        ]));
        p
    }

    fn policy_oids(&self) -> &[ObjectIdentifier] {
        &[]
    }
}

impl pkix_lint::LintProfile for SmimeSponsorValidated {
    /// Return the CA/B Forum S/MIME BR lint set for this profile.
    ///
    /// **Currently empty.** Matches [`SmimeProfile`]'s `LintProfile` shape;
    /// comprehensive predicate coverage belongs to `pkix-policy-zlint` per
    /// AGENTS.md non-negotiable #5.
    ///
    /// [`SmimeProfile`]: crate::SmimeProfile
    fn lints(&self) -> &[Box<dyn pkix_lint::Lint>] {
        static LINTS: std::sync::OnceLock<Vec<Box<dyn pkix_lint::Lint>>> =
            std::sync::OnceLock::new();
        LINTS.get_or_init(Vec::new)
    }

    fn lint_runner(&self) -> pkix_lint::LintRunner {
        pkix_lint::LintRunner::new(Vec::new())
    }
}

/// CA/Browser Forum S/MIME Baseline Requirements — Sponsor-validated profile (Multipurpose generation).
///
/// Implements [`Profile`] for the S/MIME BR Sponsor-validated subscriber-
/// certificate tier targeting the **Multipurpose generation**. Per S/MIME BR
/// §7.5 (Sponsor Validated), an employer or sponsoring organization vouches
/// for the named individual: the cert carries BOTH organizational identity
/// (organizationName + organizationIdentifier) AND individual identity
/// (givenName + surname or pseudonym), and asserts policy OID
/// `2.23.140.1.5.3.2`.
///
/// The free-function alias [`smime_sponsor_multipurpose_policy`] is
/// equivalent to `SmimeSponsorValidatedMultipurpose.policy(now_unix)`.
///
/// # Canonical source
///
/// Canonical CA/B Forum S/MIME BR document:
/// <https://github.com/cabforum/smime/blob/main/SBR.md>
///
/// Tier-specific section: §7.5 (Sponsor Validated subscriber certificates).
/// Reserved policy OID: §7.1.6.1 / Appendix A (`2.23.140.1.5.3.2` —
/// Multipurpose generation).
///
/// # Strict vs Multipurpose
///
/// Multipurpose generation differs from Strict in two respects:
///
/// - **Asserted policy OID** `2.23.140.1.5.3.2` instead of
///   [`SmimeSponsorValidated`]'s `2.23.140.1.5.3.3`.
/// - **EKU permissiveness** per §7.1.2.3(f) Multipurpose row: while
///   Strict-generation subscriber certs are constrained to assert
///   `id-kp-emailProtection` as the sole EKU, Multipurpose-generation
///   certs may additionally assert other EKU values (typically
///   document-signing crossover use cases such as `id-kp-codeSigning`).
///   The workspace `ValidationPolicy::required_leaf_eku` field is a
///   subset-of check (cert's EKU MUST contain each required OID; other
///   OIDs are permitted), so this Profile sets it to
///   `[ID_KP_EMAIL_PROTECTION]` — the cert must still carry
///   emailProtection, but additional EKUs are accepted. The "exactly
///   one EKU" enforcement on Strict-generation certs is a predicate
///   `ValidationPolicy` does not express; that audit belongs to
///   `pkix-policy-zlint` per AGENTS.md non-negotiable #5.
///
/// Subject DN rule is identical to Strict per §7.1.4.2.5 Note 2
/// ("Strict and Multipurpose Generation profiles SHALL include either
/// subject:givenName and/or subject:surname, or the subject:pseudonym")
/// plus the §7.1.4.2.5 table's "SHALL" requirement of `organizationName`
/// and `organizationIdentifier` across all generations. Same 825-day
/// validity cap per §6.3.2. Same Mailbox-validated baseline
/// (rfc822Name SAN, emailProtection EKU, SHA-256/384/512 algs, RSA ≥ 2048).
///
/// # Tier discrimination
///
/// Distinct from [`SmimeProfile`] (Mailbox-validated baseline),
/// [`SmimeSponsorValidated`] (Sponsor-validated Strict generation), and
/// [`SmimeIndividualValidated`] / [`SmimeIndividualValidatedMultipurpose`]
/// (Individual-validated tiers) by:
///
/// - **Asserted policy OID** `2.23.140.1.5.3.2` (Sponsor-validated
///   Multipurpose) is required on the leaf's `CertificatePolicies` extension.
///   Certs asserting a different tier or generation OID (or no OID) fail
///   with [`pkix_path::Error::MissingLeafPolicyOid`].
/// - **Subject DN** must satisfy: `organizationName AND
///   organizationIdentifier AND ((givenName AND surname) OR pseudonym)`
///   per §7.1.4.2.5. Certs lacking any of these (e.g. Individual-validated
///   certs without organizationName) fail with
///   [`pkix_path::Error::SubjectDnAttrRuleUnmet`].
///
/// # Limitations
///
/// Reference, not authoritative. See the crate-level "Unprincipled
/// exception" rustdoc. The BR text is the only canonical source.
///
/// **Legacy generation is not represented.** Per §7.1.6.1 line 2600,
/// Legacy generation (policy OID `2.23.140.1.5.3.1`) was banned for new
/// issuance effective 2025-07-15.
///
/// **The "additional EKUs allowed" semantic is not validator-enforced
/// as a positive predicate.** Matches [`SmimeIndividualValidatedMultipurpose`]'s
/// limitation; see that struct's rustdoc for the full discussion.
///
/// The validation-side check is structural: the cert *carries* the
/// tier-marker policy OID and DN attributes. The BR's CA-side sponsorship-
/// proofing requirements (employment verification, etc.) are not
/// validator-side concerns — this profile checks the cert AS IF the
/// issuing CA correctly verified the sponsor-individual relationship.
///
/// `max_validity_secs` applies to every certificate in the chain (matches
/// [`SmimeProfile`]'s shape); see that profile's limitations for the chain
/// composition implications.
///
/// [`SmimeProfile`]: crate::SmimeProfile
/// [`SmimeSponsorValidated`]: crate::SmimeSponsorValidated
/// [`SmimeIndividualValidated`]: crate::SmimeIndividualValidated
/// [`SmimeIndividualValidatedMultipurpose`]: crate::SmimeIndividualValidatedMultipurpose
/// [`pkix_path::Error::MissingLeafPolicyOid`]: https://docs.rs/pkix-path/latest/pkix_path/enum.Error.html#variant.MissingLeafPolicyOid
/// [`pkix_path::Error::SubjectDnAttrRuleUnmet`]: https://docs.rs/pkix-path/latest/pkix_path/enum.Error.html#variant.SubjectDnAttrRuleUnmet
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SmimeSponsorValidatedMultipurpose;

impl Profile for SmimeSponsorValidatedMultipurpose {
    fn id(&self) -> &'static str {
        "cabf.smime.sponsor.multipurpose"
    }

    fn version(&self) -> &'static str {
        // Dotted spec version of the S/MIME BR document this profile was last
        // refreshed against; matches `SmimeSponsorValidated`'s version.
        "1.0.14"
    }

    fn policy(&self, now_unix: u64) -> ValidationPolicy {
        use pkix_path::DnAttrRule;

        let mut p = ValidationPolicy::new(now_unix);
        // S/MIME BR §6.3.2: Strict and Multipurpose generation max validity 825 days.
        p.max_validity_secs = Some(825 * SECS_PER_DAY);
        // S/MIME BR §7.1.3: SHA-1 prohibited.
        p.allowed_signature_algs = Some(CABF_SMIME_BR_ALLOWED_ALGS.to_vec());
        // S/MIME BR §6.1.5: RSA ≥ 2048 bits.
        p.min_rsa_key_bits = Some(2048);
        // Mailbox-validated baseline: non-empty SAN with at least one rfc822Name.
        p.require_subject_alt_name = true;
        p.require_rfc822_san = true;
        // S/MIME BR §7.1.2.3(f) Multipurpose row: id-kp-emailProtection EKU
        // is required; additional EKUs (e.g. id-kp-codeSigning) are permitted.
        // `required_leaf_eku` is a subset-of check, so additional EKUs pass
        // automatically. See struct rustdoc "Strict vs Multipurpose".
        p.required_leaf_eku = Some(vec![ID_KP_EMAIL_PROTECTION]);
        // S/MIME BR §7.1.6.1 (Reserved Certificate Policy Identifiers) / Appendix A:
        //   2.23.140.1.5.3.2 — Sponsor-validated subscriber, Multipurpose generation.
        p.required_leaf_policy_oids = Some(vec![CABF_SMIME_SPONSOR_VALIDATED_MULTIPURPOSE_POLICY]);
        // S/MIME BR §7.1.4.2.5 (Subject DN attributes for sponsor-validated
        // profile): organizationName and organizationIdentifier are SHALL
        // across all generations. Note 2: "Strict and Multipurpose Generation
        // profiles SHALL include either subject:givenName and/or subject:surname,
        // or the subject:pseudonym."
        //
        // serialNumber is MAY in all generations (§7.1.4.2.5 table column),
        // so we do not require it here. Identical to the Strict generation
        // DN rule.
        //
        // DN rule:
        //   AllOf:
        //     organizationName
        //     organizationIdentifier
        //     AnyOf: pseudonym OR (givenName + surname)
        p.required_leaf_subject_dn_attrs = Some(DnAttrRule::AllOf(vec![
            DnAttrRule::Field(OID_ORGANIZATION_NAME),
            DnAttrRule::Field(OID_ORGANIZATION_IDENTIFIER),
            DnAttrRule::AnyOf(vec![
                DnAttrRule::Field(OID_PSEUDONYM),
                DnAttrRule::AllOf(vec![
                    DnAttrRule::Field(OID_GIVEN_NAME),
                    DnAttrRule::Field(OID_SURNAME),
                ]),
            ]),
        ]));
        p
    }

    fn policy_oids(&self) -> &[ObjectIdentifier] {
        &[]
    }
}

impl pkix_lint::LintProfile for SmimeSponsorValidatedMultipurpose {
    /// Return the CA/B Forum S/MIME BR lint set for this profile.
    ///
    /// **Currently empty.** Matches [`SmimeSponsorValidated`]'s
    /// `LintProfile` shape; comprehensive predicate coverage belongs to
    /// `pkix-policy-zlint` per AGENTS.md non-negotiable #5.
    ///
    /// [`SmimeSponsorValidated`]: crate::SmimeSponsorValidated
    fn lints(&self) -> &[Box<dyn pkix_lint::Lint>] {
        static LINTS: std::sync::OnceLock<Vec<Box<dyn pkix_lint::Lint>>> =
            std::sync::OnceLock::new();
        LINTS.get_or_init(Vec::new)
    }

    fn lint_runner(&self) -> pkix_lint::LintRunner {
        pkix_lint::LintRunner::new(Vec::new())
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
/// # Canonical source
///
/// Canonical CA/B Forum Code Signing BR document:
/// <https://github.com/cabforum/code-signing/blob/main/docs/CSBR.md>
///
/// Specific section anchors for this profile's constraints are listed in
/// the [`code_signing_policy`] free-function rustdoc.
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
        // Dotted spec version of the CS BR document this profile was last
        // refreshed against. The current BR text is the canonical source;
        // this string is informational only.
        "3.10.0"
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
        // CS BR §7.1.2.3(f) (Code signing and Timestamp Certificate / extKeyUsage):
        // id-kp-codeSigning must be asserted.
        p.required_leaf_eku = Some(vec![ID_KP_CODE_SIGNING]);
        // Note: CS BR 3.10.0 does not impose a numeric chain-depth cap.
        // pathLenConstraint enforcement on individual CA certs is handled
        // by RFC 5280 §4.2.1.9 in pkix-path.
        p
    }

    fn policy_oids(&self) -> &[ObjectIdentifier] {
        &[]
    }
}

impl pkix_lint::LintProfile for CodeSigningProfile {
    /// Return the CA/B Forum CS BR lint set for this profile.
    ///
    /// **Currently empty.** `pkix-lint-cabf` does not yet ship a
    /// `cabf_cs_br` lint module; per AGENTS.md non-negotiable #5, the
    /// path of least surface area is to wait for either a curated marquee
    /// set (sibling to `cabf_tls_br`) or to rely on `pkix-policy-zlint` for
    /// comprehensive predicate coverage. Until those land, this profile's
    /// `LintProfile` impl returns no lints.
    fn lints(&self) -> &[Box<dyn pkix_lint::Lint>] {
        static LINTS: std::sync::OnceLock<Vec<Box<dyn pkix_lint::Lint>>> =
            std::sync::OnceLock::new();
        LINTS.get_or_init(Vec::new)
    }

    fn lint_runner(&self) -> pkix_lint::LintRunner {
        pkix_lint::LintRunner::new(Vec::new())
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
/// Canonical CA/B Forum TLS BR:
/// <https://github.com/cabforum/servercert/blob/main/docs/BR.md>
///
/// | Field | Value | Normative reference |
/// |-------|-------|---------------------|
/// | `allowed_signature_algs` | SHA-256/384/512 RSA + ECDSA; SHA-1 excluded | [TLS BR §7.1.3](https://github.com/cabforum/servercert/blob/main/docs/BR.md#713-algorithm-object-identifiers) |
/// | `min_rsa_key_bits` | 2048 | [TLS BR §6.1.5](https://github.com/cabforum/servercert/blob/main/docs/BR.md#615-key-sizes) |
/// | `require_subject_alt_name` | true | [TLS BR §7.1.2.7.12](https://github.com/cabforum/servercert/blob/main/docs/BR.md#712712-subscriber-certificate-subject-alternative-name) |
/// | `required_leaf_eku` | id-kp-serverAuth (1.3.6.1.5.5.7.3.1) | [TLS BR §7.1.2.7.10](https://github.com/cabforum/servercert/blob/main/docs/BR.md#712710-subscriber-certificate-extended-key-usage) |
///
/// `max_path_len` is intentionally not set. The TLS BR does not impose a
/// numeric chain-depth cap; per-cert `pathLenConstraint` enforcement is
/// handled by RFC 5280 §4.2.1.9 in `pkix-path`.
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
/// S/MIME Baseline Requirements (Mailbox-validated, Strict generation).
///
/// This is a convenience alias for `SmimeProfile.policy(now_unix)`.
///
/// # Constraints enforced
///
/// Canonical CA/B Forum S/MIME BR:
/// <https://github.com/cabforum/smime/blob/main/SBR.md>
///
/// | Field | Value | Normative reference |
/// |-------|-------|---------------------|
/// | `max_validity_secs` | 825 days | [S/MIME BR §6.3.2](https://github.com/cabforum/smime/blob/main/SBR.md#632-certificate-operational-periods-and-key-pair-usage-periods) (Strict and Multipurpose) |
/// | `allowed_signature_algs` | SHA-256/384/512 RSA + ECDSA; SHA-1 excluded | [S/MIME BR §7.1.3](https://github.com/cabforum/smime/blob/main/SBR.md#713-algorithm-object-identifiers) |
/// | `min_rsa_key_bits` | 2048 | [S/MIME BR §6.1.5](https://github.com/cabforum/smime/blob/main/SBR.md#615-key-sizes) |
/// | `require_subject_alt_name` | true | non-empty `SubjectAltName` extension required |
/// | `require_rfc822_san` | true | at least one `rfc822Name` entry required in SAN |
/// | `required_leaf_eku` | id-kp-emailProtection (1.3.6.1.5.5.7.3.4) | [S/MIME BR §7.1.2.3(f)](https://github.com/cabforum/smime/blob/main/SBR.md#7123-subscriber-certificates) |
///
/// `max_path_len` is intentionally not set. The S/MIME BR does not impose a
/// numeric chain-depth cap; per-cert `pathLenConstraint` enforcement is
/// handled by RFC 5280 §4.2.1.9 in `pkix-path`.
///
/// # Limitations
///
/// Only the Mailbox-validated tier (Strict generation) is enforced by this
/// alias. Sister tier aliases [`smime_sponsor_policy`] and
/// [`smime_individual_policy`] cover the Sponsor- and Individual-validated
/// tiers (also Strict generation). Organization-validated is tracked as
/// PKIX-jbvb.1. Legacy (`.1`) generation Profile types are not shipped — the
/// generation has been banned for new issuance since 2025-07-15 per
/// [§7.1.6.1](https://github.com/cabforum/smime/blob/main/SBR.md#7161-reserved-certificate-policy-identifiers).
///
/// `max_validity_secs` applies to **every** certificate in the chain, not just
/// the leaf. Typical S/MIME CA certificates have validity periods of 10–20 years
/// (well over 825 days). Callers using this policy with a standard S/MIME CA
/// hierarchy will see validation failures on intermediate or root CA certificates.
/// Use a custom policy or chain with short-lived CA certificates to avoid this.
///
/// Revocation checking (OCSP/CRL) is out of scope; use `pkix-revocation`.
#[must_use]
pub fn smime_policy(now_unix: u64) -> ValidationPolicy {
    SmimeProfile.policy(now_unix)
}

/// Return a [`ValidationPolicy`] for the CA/Browser Forum S/MIME BR
/// Individual-validated subscriber-certificate profile (Strict generation).
///
/// This is a convenience alias for `SmimeIndividualValidated.policy(now_unix)`.
///
/// # Constraints enforced
///
/// Canonical CA/B Forum S/MIME BR:
/// <https://github.com/cabforum/smime/blob/main/SBR.md>
///
/// | Field | Value | Normative reference |
/// |-------|-------|---------------------|
/// | `max_validity_secs` | 825 days | [S/MIME BR §6.3.2](https://github.com/cabforum/smime/blob/main/SBR.md#632-certificate-operational-periods-and-key-pair-usage-periods) (Strict and Multipurpose) |
/// | `allowed_signature_algs` | SHA-256/384/512 RSA + ECDSA; SHA-1 excluded | [S/MIME BR §7.1.3](https://github.com/cabforum/smime/blob/main/SBR.md#713-algorithm-object-identifiers) |
/// | `min_rsa_key_bits` | 2048 | [S/MIME BR §6.1.5](https://github.com/cabforum/smime/blob/main/SBR.md#615-key-sizes) |
/// | `require_subject_alt_name` | true | rfc822Name SAN required |
/// | `require_rfc822_san` | true | at least one rfc822Name in SAN |
/// | `required_leaf_eku` | id-kp-emailProtection (1.3.6.1.5.5.7.3.4) | [S/MIME BR §7.1.2.3(f)](https://github.com/cabforum/smime/blob/main/SBR.md#7123-subscriber-certificates) |
/// | `required_leaf_policy_oids` | `[2.23.140.1.5.4.3]` (Individual-validated Strict) | [S/MIME BR §7.1.6.1](https://github.com/cabforum/smime/blob/main/SBR.md#7161-reserved-certificate-policy-identifiers) |
/// | `required_leaf_subject_dn_attrs` | `(givenName ∧ surname) ∨ pseudonym` | [S/MIME BR §7.1.4.2.6](https://github.com/cabforum/smime/blob/main/SBR.md#71426-subject-dn-attributes-for-individual-validated-profile) Note 2 |
///
/// `max_path_len` is intentionally not set; per-cert `pathLenConstraint`
/// enforcement (RFC 5280 §4.2.1.9) covers the CA chain-depth case.
///
/// # Limitations
///
/// Reference, not authoritative. See [`SmimeIndividualValidated`].
///
/// `max_validity_secs` applies to **every** certificate in the chain, not
/// just the leaf — same limitation as [`smime_policy`].
///
/// Revocation checking (OCSP/CRL) is out of scope; use `pkix-revocation`.
#[must_use]
pub fn smime_individual_policy(now_unix: u64) -> ValidationPolicy {
    SmimeIndividualValidated.policy(now_unix)
}

/// Return a [`ValidationPolicy`] for the CA/Browser Forum S/MIME BR
/// Individual-validated subscriber-certificate profile (Multipurpose generation).
///
/// This is a convenience alias for
/// `SmimeIndividualValidatedMultipurpose.policy(now_unix)`.
///
/// # Constraints enforced
///
/// Canonical CA/B Forum S/MIME BR:
/// <https://github.com/cabforum/smime/blob/main/SBR.md>
///
/// | Field | Value | Normative reference |
/// |-------|-------|---------------------|
/// | `max_validity_secs` | 825 days | [S/MIME BR §6.3.2](https://github.com/cabforum/smime/blob/main/SBR.md#632-certificate-operational-periods-and-key-pair-usage-periods) (Strict and Multipurpose) |
/// | `allowed_signature_algs` | SHA-256/384/512 RSA + ECDSA; SHA-1 excluded | [S/MIME BR §7.1.3](https://github.com/cabforum/smime/blob/main/SBR.md#713-algorithm-object-identifiers) |
/// | `min_rsa_key_bits` | 2048 | [S/MIME BR §6.1.5](https://github.com/cabforum/smime/blob/main/SBR.md#615-key-sizes) |
/// | `require_subject_alt_name` | true | rfc822Name SAN required |
/// | `require_rfc822_san` | true | at least one rfc822Name in SAN |
/// | `required_leaf_eku` | id-kp-emailProtection (1.3.6.1.5.5.7.3.4) | [S/MIME BR §7.1.2.3(f)](https://github.com/cabforum/smime/blob/main/SBR.md#7123-subscriber-certificates) (Multipurpose row — additional EKUs permitted) |
/// | `required_leaf_policy_oids` | `[2.23.140.1.5.4.2]` (Individual-validated Multipurpose) | [S/MIME BR §7.1.6.1](https://github.com/cabforum/smime/blob/main/SBR.md#7161-reserved-certificate-policy-identifiers) |
/// | `required_leaf_subject_dn_attrs` | `(givenName ∧ surname) ∨ pseudonym` | [S/MIME BR §7.1.4.2.6](https://github.com/cabforum/smime/blob/main/SBR.md#71426-subject-dn-attributes-for-individual-validated-profile) Note 2 |
///
/// `max_path_len` is intentionally not set; per-cert `pathLenConstraint`
/// enforcement (RFC 5280 §4.2.1.9) covers the CA chain-depth case.
///
/// # Strict vs Multipurpose
///
/// At the `ValidationPolicy` level, this policy differs from
/// [`smime_individual_policy`] only in the asserted policy OID
/// (`.4.2` vs `.4.3`). The §7.1.2.3(f) "Strict permits only
/// emailProtection EKU" constraint is not expressed by
/// `ValidationPolicy` (no "forbidden EKU" or "exact EKU set" field);
/// comprehensive enforcement of that semantic belongs to
/// `pkix-policy-zlint` per AGENTS.md non-negotiable #5. See
/// [`SmimeIndividualValidatedMultipurpose`]'s struct rustdoc for the
/// full discussion.
///
/// # Limitations
///
/// Reference, not authoritative. See [`SmimeIndividualValidatedMultipurpose`].
///
/// `max_validity_secs` applies to **every** certificate in the chain, not
/// just the leaf — same limitation as [`smime_policy`].
///
/// Revocation checking (OCSP/CRL) is out of scope; use `pkix-revocation`.
#[must_use]
pub fn smime_individual_multipurpose_policy(now_unix: u64) -> ValidationPolicy {
    SmimeIndividualValidatedMultipurpose.policy(now_unix)
}

/// Return a [`ValidationPolicy`] for the CA/Browser Forum S/MIME BR
/// Sponsor-validated subscriber-certificate profile (Strict generation).
///
/// This is a convenience alias for `SmimeSponsorValidated.policy(now_unix)`.
///
/// # Constraints enforced
///
/// Canonical CA/B Forum S/MIME BR:
/// <https://github.com/cabforum/smime/blob/main/SBR.md>
///
/// | Field | Value | Normative reference |
/// |-------|-------|---------------------|
/// | `max_validity_secs` | 825 days | [S/MIME BR §6.3.2](https://github.com/cabforum/smime/blob/main/SBR.md#632-certificate-operational-periods-and-key-pair-usage-periods) (Strict and Multipurpose) |
/// | `allowed_signature_algs` | SHA-256/384/512 RSA + ECDSA; SHA-1 excluded | [S/MIME BR §7.1.3](https://github.com/cabforum/smime/blob/main/SBR.md#713-algorithm-object-identifiers) |
/// | `min_rsa_key_bits` | 2048 | [S/MIME BR §6.1.5](https://github.com/cabforum/smime/blob/main/SBR.md#615-key-sizes) |
/// | `require_subject_alt_name` | true | rfc822Name SAN required |
/// | `require_rfc822_san` | true | at least one rfc822Name in SAN |
/// | `required_leaf_eku` | id-kp-emailProtection (1.3.6.1.5.5.7.3.4) | [S/MIME BR §7.1.2.3(f)](https://github.com/cabforum/smime/blob/main/SBR.md#7123-subscriber-certificates) |
/// | `required_leaf_policy_oids` | `[2.23.140.1.5.3.3]` (Sponsor-validated Strict) | [S/MIME BR §7.1.6.1](https://github.com/cabforum/smime/blob/main/SBR.md#7161-reserved-certificate-policy-identifiers) |
/// | `required_leaf_subject_dn_attrs` | `organizationName ∧ organizationIdentifier ∧ ((givenName ∧ surname) ∨ pseudonym)` | [S/MIME BR §7.1.4.2.5](https://github.com/cabforum/smime/blob/main/SBR.md#71425-subject-dn-attributes-for-sponsor-validated-profile) Note 2 |
///
/// `max_path_len` is intentionally not set; per-cert `pathLenConstraint`
/// enforcement (RFC 5280 §4.2.1.9) covers the CA chain-depth case.
///
/// # Limitations
///
/// Reference, not authoritative. See [`SmimeSponsorValidated`].
///
/// `max_validity_secs` applies to **every** certificate in the chain, not
/// just the leaf — same limitation as [`smime_policy`].
///
/// Revocation checking (OCSP/CRL) is out of scope; use `pkix-revocation`.
#[must_use]
pub fn smime_sponsor_policy(now_unix: u64) -> ValidationPolicy {
    SmimeSponsorValidated.policy(now_unix)
}

/// Return a [`ValidationPolicy`] for the CA/Browser Forum S/MIME BR
/// Sponsor-validated subscriber-certificate profile (Multipurpose generation).
///
/// This is a convenience alias for
/// `SmimeSponsorValidatedMultipurpose.policy(now_unix)`.
///
/// # Constraints enforced
///
/// Canonical CA/B Forum S/MIME BR:
/// <https://github.com/cabforum/smime/blob/main/SBR.md>
///
/// | Field | Value | Normative reference |
/// |-------|-------|---------------------|
/// | `max_validity_secs` | 825 days | [S/MIME BR §6.3.2](https://github.com/cabforum/smime/blob/main/SBR.md#632-certificate-operational-periods-and-key-pair-usage-periods) (Strict and Multipurpose) |
/// | `allowed_signature_algs` | SHA-256/384/512 RSA + ECDSA; SHA-1 excluded | [S/MIME BR §7.1.3](https://github.com/cabforum/smime/blob/main/SBR.md#713-algorithm-object-identifiers) |
/// | `min_rsa_key_bits` | 2048 | [S/MIME BR §6.1.5](https://github.com/cabforum/smime/blob/main/SBR.md#615-key-sizes) |
/// | `require_subject_alt_name` | true | rfc822Name SAN required |
/// | `require_rfc822_san` | true | at least one rfc822Name in SAN |
/// | `required_leaf_eku` | id-kp-emailProtection (1.3.6.1.5.5.7.3.4) | [S/MIME BR §7.1.2.3(f)](https://github.com/cabforum/smime/blob/main/SBR.md#7123-subscriber-certificates) (Multipurpose row — additional EKUs permitted) |
/// | `required_leaf_policy_oids` | `[2.23.140.1.5.3.2]` (Sponsor-validated Multipurpose) | [S/MIME BR §7.1.6.1](https://github.com/cabforum/smime/blob/main/SBR.md#7161-reserved-certificate-policy-identifiers) |
/// | `required_leaf_subject_dn_attrs` | `organizationName ∧ organizationIdentifier ∧ ((givenName ∧ surname) ∨ pseudonym)` | [S/MIME BR §7.1.4.2.5](https://github.com/cabforum/smime/blob/main/SBR.md#71425-subject-dn-attributes-for-sponsor-validated-profile) Note 2 |
///
/// `max_path_len` is intentionally not set; per-cert `pathLenConstraint`
/// enforcement (RFC 5280 §4.2.1.9) covers the CA chain-depth case.
///
/// # Strict vs Multipurpose
///
/// At the `ValidationPolicy` level, this policy differs from
/// [`smime_sponsor_policy`] only in the asserted policy OID
/// (`.3.2` vs `.3.3`). The §7.1.2.3(f) "Strict permits only
/// emailProtection EKU" constraint is not expressed by
/// `ValidationPolicy` (no "forbidden EKU" or "exact EKU set" field);
/// comprehensive enforcement of that semantic belongs to
/// `pkix-policy-zlint` per AGENTS.md non-negotiable #5. See
/// [`SmimeSponsorValidatedMultipurpose`]'s struct rustdoc for the
/// full discussion.
///
/// # Limitations
///
/// Reference, not authoritative. See [`SmimeSponsorValidatedMultipurpose`].
///
/// `max_validity_secs` applies to **every** certificate in the chain, not
/// just the leaf — same limitation as [`smime_policy`].
///
/// Revocation checking (OCSP/CRL) is out of scope; use `pkix-revocation`.
#[must_use]
pub fn smime_sponsor_multipurpose_policy(now_unix: u64) -> ValidationPolicy {
    SmimeSponsorValidatedMultipurpose.policy(now_unix)
}

/// Return a [`ValidationPolicy`] conforming to the CA/Browser Forum
/// Code Signing Baseline Requirements.
///
/// This is a convenience alias for `CodeSigningProfile.policy(now_unix)`.
///
/// # Constraints enforced
///
/// Canonical CA/B Forum Code Signing BR:
/// <https://github.com/cabforum/code-signing/blob/main/docs/CSBR.md>
///
/// | Field | Value | Normative reference |
/// |-------|-------|---------------------|
/// | `max_validity_secs` | 460 days | [CS BR §6.3.2](https://github.com/cabforum/code-signing/blob/main/docs/CSBR.md#632-certificate-operational-periods-and-key-pair-usage-periods) (effective 2026-03-01) |
/// | `allowed_signature_algs` | SHA-256/384/512 RSA + ECDSA; SHA-1 excluded | [CS BR §7.1.3](https://github.com/cabforum/code-signing/blob/main/docs/CSBR.md#713-algorithm-object-identifiers) |
/// | `min_rsa_key_bits` | 3072 | [CS BR §6.1.5](https://github.com/cabforum/code-signing/blob/main/docs/CSBR.md#615-key-sizes) (effective 2023-06-01) |
/// | `require_subject_alt_name` | false | CS certs identify subjects by DN |
/// | `required_leaf_eku` | id-kp-codeSigning (1.3.6.1.5.5.7.3.3) | [CS BR §7.1.2.3(f)](https://github.com/cabforum/code-signing/blob/main/docs/CSBR.md#7123-code-signing-and-timestamp-certificate) |
///
/// `max_path_len` is intentionally not set. The CS BR does not impose a
/// numeric chain-depth cap; per-cert `pathLenConstraint` enforcement is
/// handled by RFC 5280 §4.2.1.9 in `pkix-path`.
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

// ---------------------------------------------------------------------------
// Shape-check convenience aliases (PKIX-9vnx.9.2)
//
// One-line wrappers over `pkix_lint::check_shape(cert, SubjectKind::Leaf,
// now_unix, &<Profile>)` for each cabf Profile that ships a LintProfile
// impl. Sister aliases for the RFC-baseline profiles live in
// `pkix-profiles` (`check_basic_tls_shape`, `check_basic_smime_shape`).
//
// The cabf alias function names mirror each Profile's struct slug
// (`WebPkiProfile` -> `check_web_pki_shape`, etc.) per Mark's 2026-05-12
// naming decision recorded in PKIX-9vnx.9.2.
// ---------------------------------------------------------------------------

/// Run [`WebPkiProfile`]'s lint set against a single CA/B Forum TLS server
/// certificate as a fast structural shape check.
///
/// Returns `Ok(())` when no `Error`/`Fatal` findings are produced; returns
/// `Err(findings)` with the complete `Vec<Finding>` from
/// [`pkix_lint::LintRunner::run_cert`] otherwise.
///
/// Convenience alias for
/// `pkix_lint::check_shape(cert, pkix_lint::SubjectKind::Leaf, now_unix, &WebPkiProfile)`.
///
/// # Constraints checked
///
/// See [`WebPkiProfile`]'s `LintProfile` impl. The bundle covers the six
/// CA/B Forum TLS BR predicates implemented in
/// `pkix_lint_cabf::cabf_tls_br`: SC-081 phased validity cap, SHA-1
/// prohibition, RSA min-key-size (2048 bits), SAN presence,
/// id-kp-serverAuth EKU presence, and `BasicConstraints.cA=TRUE` on
/// intermediates.
///
/// Note: this check covers the CA/B Forum TLS BR overlay only.
/// RFC 5280 + RFC 6125 baseline checks (e.g. subscriber non-CA,
/// SAN-when-empty-DN, signatureAlgorithm match) are bundled separately
/// under `pkix_profiles::check_basic_tls_shape`; callers wanting full
/// coverage run both.
///
/// # Errors
///
/// Returns `Err(Vec<Finding>)` containing the full lint runner output if
/// any cert-scope lint records an `Error` or `Fatal` finding.
pub fn check_web_pki_shape(
    cert: &x509_cert::Certificate,
    now_unix: u64,
) -> Result<(), Vec<pkix_lint::Finding>> {
    pkix_lint::check_shape(cert, pkix_lint::SubjectKind::Leaf, now_unix, &WebPkiProfile)
}

/// Run [`SmimeProfile`]'s lint set against a single CA/B Forum S/MIME
/// end-entity certificate as a fast structural shape check.
///
/// Convenience alias for
/// `pkix_lint::check_shape(cert, pkix_lint::SubjectKind::Leaf, now_unix, &SmimeProfile)`.
///
/// # Constraints checked
///
/// **Currently empty.** [`SmimeProfile`]'s `LintProfile` impl returns
/// no lints today because `pkix-lint-cabf` has no `cabf_smime_br`
/// module yet (a curated marquee S/MIME BR lint set, sibling to
/// `cabf_tls_br`, has not been authored). Until that lands, this alias
/// will return `Ok(())` for any cert. Callers needing RFC-baseline
/// S/MIME shape checks should call `pkix_profiles::check_basic_smime_shape`
/// separately, which bundles RFC 8551 + RFC 8398 + RFC 5280 baseline
/// lints.
///
/// # Errors
///
/// Returns `Err(Vec<Finding>)` if and only if the future lint set fires
/// any `Error` or `Fatal` finding. Today the lint set is empty so this
/// branch is unreachable.
pub fn check_smime_shape(
    cert: &x509_cert::Certificate,
    now_unix: u64,
) -> Result<(), Vec<pkix_lint::Finding>> {
    pkix_lint::check_shape(cert, pkix_lint::SubjectKind::Leaf, now_unix, &SmimeProfile)
}

/// Run [`CodeSigningProfile`]'s lint set against a single CA/B Forum
/// code-signing end-entity certificate as a fast structural shape check.
///
/// Convenience alias for
/// `pkix_lint::check_shape(cert, pkix_lint::SubjectKind::Leaf, now_unix, &CodeSigningProfile)`.
///
/// # Constraints checked
///
/// **Currently empty.** [`CodeSigningProfile`]'s `LintProfile` impl
/// returns no lints today because `pkix-lint-cabf` has no `cabf_cs_br`
/// module yet (a curated marquee CS BR lint set, sibling to
/// `cabf_tls_br`, has not been authored). Until that lands, this alias
/// will return `Ok(())` for any cert.
///
/// # Errors
///
/// Returns `Err(Vec<Finding>)` if and only if the future lint set fires
/// any `Error` or `Fatal` finding. Today the lint set is empty so this
/// branch is unreachable.
pub fn check_code_signing_shape(
    cert: &x509_cert::Certificate,
    now_unix: u64,
) -> Result<(), Vec<pkix_lint::Finding>> {
    pkix_lint::check_shape(
        cert,
        pkix_lint::SubjectKind::Leaf,
        now_unix,
        &CodeSigningProfile,
    )
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
    // accessed via relative path from the pkix-profiles-cabf crate root).
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
        assert_eq!(SmimeSponsorValidated.id(), "cabf.smime.sponsor");
        assert_eq!(
            SmimeSponsorValidatedMultipurpose.id(),
            "cabf.smime.sponsor.multipurpose"
        );
        assert_eq!(SmimeIndividualValidated.id(), "cabf.smime.individual");
        assert_eq!(
            SmimeIndividualValidatedMultipurpose.id(),
            "cabf.smime.individual.multipurpose"
        );
        assert_eq!(CodeSigningProfile.id(), "cabf.cs");
    }

    #[test]
    fn profile_policy_sets_correct_timestamp() {
        // profile.policy(NOW) must set current_time_unix = NOW.
        assert_eq!(WebPkiProfile.policy(NOW).current_time_unix, NOW);
        assert_eq!(SmimeProfile.policy(NOW).current_time_unix, NOW);
        assert_eq!(SmimeSponsorValidated.policy(NOW).current_time_unix, NOW);
        assert_eq!(
            SmimeSponsorValidatedMultipurpose
                .policy(NOW)
                .current_time_unix,
            NOW
        );
        assert_eq!(SmimeIndividualValidated.policy(NOW).current_time_unix, NOW);
        assert_eq!(
            SmimeIndividualValidatedMultipurpose
                .policy(NOW)
                .current_time_unix,
            NOW
        );
        assert_eq!(CodeSigningProfile.policy(NOW).current_time_unix, NOW);
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

        let via_trait = SmimeSponsorValidated.policy(NOW);
        let via_fn = smime_sponsor_policy(NOW);
        assert_eq!(
            via_trait, via_fn,
            "SmimeSponsorValidated.policy and smime_sponsor_policy must agree"
        );

        let via_trait = SmimeIndividualValidated.policy(NOW);
        let via_fn = smime_individual_policy(NOW);
        assert_eq!(
            via_trait, via_fn,
            "SmimeIndividualValidated.policy and smime_individual_policy must agree"
        );

        let via_trait = SmimeIndividualValidatedMultipurpose.policy(NOW);
        let via_fn = smime_individual_multipurpose_policy(NOW);
        assert_eq!(
            via_trait, via_fn,
            "SmimeIndividualValidatedMultipurpose.policy and \
             smime_individual_multipurpose_policy must agree"
        );

        let via_trait = SmimeSponsorValidatedMultipurpose.policy(NOW);
        let via_fn = smime_sponsor_multipurpose_policy(NOW);
        assert_eq!(
            via_trait, via_fn,
            "SmimeSponsorValidatedMultipurpose.policy and \
             smime_sponsor_multipurpose_policy must agree"
        );

        let via_trait = CodeSigningProfile.policy(NOW);
        let via_fn = code_signing_policy(NOW);
        assert_eq!(
            via_trait, via_fn,
            "CodeSigningProfile.policy and code_signing_policy must agree"
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
    fn smime_policy_max_validity_is_825_days() {
        let p = smime_policy(NOW);
        assert_eq!(
            p.max_validity_secs,
            Some(825 * 86_400),
            "smime_policy: max_validity_secs must be 825 days (Strict generation cap)"
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
    // Algorithm separation test
    //
    // Oracle: The three per-profile algorithm lists must currently be identical
    // (they're sourced from the same specs and haven't diverged yet), but they
    // must be structurally separate constants so they can diverge independently.
    // -----------------------------------------------------------------------

    #[test]
    fn per_profile_alg_lists_are_independent_owned_copies() {
        // Verify that TLS, SMIME, and CS each return their own owned allowed_algs
        // by mutating one copy and verifying the others are unchanged.
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

    // -----------------------------------------------------------------------
    // smime_individual_policy — Individual-validated tier, Strict generation (PKIX-jbvb.7)
    //
    // Oracle: pkix-path/tests/fixtures/policy-checks/
    //   smime-individual-validated-self-signed-365d.der    — givenName+surname form
    //   smime-individual-pseudonym-self-signed-365d.der    — pseudonym form
    //   smime-self-signed-365d.der                         — Mailbox-validated tier (negative oracle)
    //   webpki-self-signed-365d.der                        — wrong EKU/SAN (negative oracle)
    //
    // Fixture provenance: `gen-smime-tier-fixtures.py` modeled after zlint
    // smime_leg1_iv_eff1.pem (Individual-validated marker) with BR §7.1.4.2.6
    // Note 2 Subject DN attributes; OID updated to Strict generation
    // 2.23.140.1.5.4.3 per PKIX-jbvb.6 (zlint's fixture used Legacy `.1`
    // which is BR-banned for new issuance per §7.1.6.1 effective 2025-07-15).
    // -----------------------------------------------------------------------

    #[test]
    fn smime_individual_policy_asserts_individual_policy_oid() {
        let p = smime_individual_policy(NOW);
        let oids = p.required_leaf_policy_oids.as_deref().unwrap_or(&[]);
        assert_eq!(
            oids,
            &[CABF_SMIME_INDIVIDUAL_VALIDATED_STRICT_POLICY],
            "smime_individual_policy: required_leaf_policy_oids must be exactly [2.23.140.1.5.4.3]"
        );
    }

    #[test]
    fn smime_individual_policy_sets_dn_attr_rule() {
        let p = smime_individual_policy(NOW);
        assert!(
            p.required_leaf_subject_dn_attrs.is_some(),
            "smime_individual_policy: required_leaf_subject_dn_attrs must be set"
        );
    }

    #[test]
    fn smime_individual_policy_max_validity_is_825_days() {
        // Inherits the Mailbox-validated Strict-generation cap.
        let p = smime_individual_policy(NOW);
        assert_eq!(
            p.max_validity_secs,
            Some(825 * 86_400),
            "smime_individual_policy: max_validity_secs must be 825 days (Strict generation cap)"
        );
    }

    #[test]
    fn smime_individual_policy_requires_email_protection_eku() {
        let p = smime_individual_policy(NOW);
        let ekus = p.required_leaf_eku.as_deref().unwrap_or(&[]);
        assert!(
            ekus.contains(&ID_KP_EMAIL_PROTECTION),
            "smime_individual_policy: required_leaf_eku must contain id-kp-emailProtection"
        );
    }

    /// Positive #1: cert with givenName + surname form passes.
    ///
    /// Oracle: smime-individual-validated-self-signed-365d.der has:
    ///   Subject = C=GB, GN=Test, SN=Person, CN=Test Person
    ///   CertificatePolicies = 2.23.140.1.5.4.3
    ///   rfc822Name SAN = individual@example.com
    ///   emailProtection EKU
    ///   cA=TRUE (self-signed anchor)
    /// Verified via openssl x509 -inform DER -text -noout.
    #[test]
    fn smime_individual_givenname_surname_form_passes() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/smime-individual-validated-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        pkix_path::validate_path(
            &[cert],
            &anchors,
            &smime_individual_policy(NOW),
            &EcdsaP256Verifier,
        )
        .expect(
            "Individual-validated cert with givenName+surname+serialNumber DN, \
             policy OID 2.23.140.1.5.4.3, rfc822 SAN, and emailProtection EKU \
             must pass smime_individual_policy",
        );
    }

    /// Positive #2: cert with pseudonym form passes.
    ///
    /// Oracle: smime-individual-pseudonym-self-signed-365d.der has:
    ///   Subject = C=GB, pseudonym=TestBox, CN=TestBox
    ///   CertificatePolicies = 2.23.140.1.5.4.3
    ///   rfc822Name SAN = testbox@example.com
    /// Exercises the `AnyOf(pseudonym, AllOf(givenName, surname))` branch of
    /// the DN rule: pseudonym alone (without givenName/surname) satisfies
    /// the AnyOf clause.
    #[test]
    fn smime_individual_pseudonym_form_passes() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/smime-individual-pseudonym-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        pkix_path::validate_path(
            &[cert],
            &anchors,
            &smime_individual_policy(NOW),
            &EcdsaP256Verifier,
        )
        .expect(
            "Individual-validated cert with pseudonym+serialNumber DN \
             must pass smime_individual_policy (AnyOf branch)",
        );
    }

    /// Negative #1: Mailbox-validated cert (no policy OID, no tier DN attrs)
    /// fails with `MissingLeafPolicyOid`.
    ///
    /// Oracle: smime-self-signed-365d.der is a Mailbox-validated baseline cert
    /// — it has emailProtection EKU and rfc822 SAN (passing the (e3)/(e4)
    /// checks) but no `CertificatePolicies` extension. The (e3a) leaf-policy-OID
    /// check fires and returns `MissingLeafPolicyOid { required: 2.23.140.1.5.4.3 }`.
    /// Exercises tier disambiguation: a sibling-tier cert that satisfies
    /// `smime_policy` does NOT satisfy `smime_individual_policy`.
    #[test]
    fn smime_individual_rejects_mailbox_validated_cert() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/smime-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        let result = pkix_path::validate_path(
            &[cert],
            &anchors,
            &smime_individual_policy(NOW),
            &EcdsaP256Verifier,
        );
        assert!(
            matches!(
                result,
                Err(pkix_path::Error::MissingLeafPolicyOid { required })
                    if required == CABF_SMIME_INDIVIDUAL_VALIDATED_STRICT_POLICY
            ),
            "Mailbox-validated cert (no policy OID) must fail smime_individual_policy \
             with MissingLeafPolicyOid {{ required: 2.23.140.1.5.4.3 }}, got {result:?}"
        );
    }

    /// Negative #2: WebPKI cert (wrong EKU, no rfc822 SAN) fails with
    /// `MissingEku` — the (e3) EKU check fires before the tier-specific
    /// (e3a)/(e3b) checks.
    ///
    /// Oracle: webpki-self-signed-365d.der has serverAuth EKU (not
    /// emailProtection), DNS SAN (not rfc822).
    #[test]
    fn smime_individual_rejects_webpki_cert() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/webpki-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        assert!(
            matches!(
                pkix_path::validate_path(
                    &[cert],
                    &anchors,
                    &smime_individual_policy(NOW),
                    &EcdsaP256Verifier
                ),
                Err(pkix_path::Error::MissingEku)
            ),
            "WebPKI cert (wrong EKU) must fail smime_individual_policy with MissingEku"
        );
    }

    // -----------------------------------------------------------------------
    // smime_sponsor_policy — Sponsor-validated tier, Strict generation (PKIX-jbvb.7)
    //
    // Oracle: pkix-path/tests/fixtures/policy-checks/
    //   smime-sponsor-validated-self-signed-365d.der  — org + orgID + given+surname form
    //   smime-sponsor-pseudonym-self-signed-365d.der  — org + orgID + pseudonym form
    //   smime-self-signed-365d.der                    — Mailbox-validated (negative)
    //   webpki-self-signed-365d.der                   — wrong EKU/SAN (negative)
    //
    // Fixture provenance: `gen-smime-tier-fixtures.py` modeled after zlint
    // smime_leg1_sv_eff1.pem (Sponsor-validated marker) with BR §7.1.4.2.5
    // Subject DN attributes (organizationName + organizationIdentifier SHALL,
    // plus Note 2 givenName+surname or pseudonym); OID updated to Strict
    // generation 2.23.140.1.5.3.3 per PKIX-jbvb.6 (zlint's fixture used
    // Legacy `.1` which is BR-banned for new issuance per §7.1.6.1 effective
    // 2025-07-15).
    // -----------------------------------------------------------------------

    #[test]
    fn smime_sponsor_policy_asserts_sponsor_policy_oid() {
        let p = smime_sponsor_policy(NOW);
        let oids = p.required_leaf_policy_oids.as_deref().unwrap_or(&[]);
        assert_eq!(
            oids,
            &[CABF_SMIME_SPONSOR_VALIDATED_STRICT_POLICY],
            "smime_sponsor_policy: required_leaf_policy_oids must be exactly [2.23.140.1.5.3.3]"
        );
    }

    #[test]
    fn smime_sponsor_policy_sets_dn_attr_rule() {
        let p = smime_sponsor_policy(NOW);
        assert!(
            p.required_leaf_subject_dn_attrs.is_some(),
            "smime_sponsor_policy: required_leaf_subject_dn_attrs must be set"
        );
    }

    #[test]
    fn smime_sponsor_policy_max_validity_is_825_days() {
        // Inherits the Mailbox-validated Strict-generation cap.
        let p = smime_sponsor_policy(NOW);
        assert_eq!(
            p.max_validity_secs,
            Some(825 * 86_400),
            "smime_sponsor_policy: max_validity_secs must be 825 days (Strict generation cap)"
        );
    }

    #[test]
    fn smime_sponsor_policy_requires_email_protection_eku() {
        let p = smime_sponsor_policy(NOW);
        let ekus = p.required_leaf_eku.as_deref().unwrap_or(&[]);
        assert!(
            ekus.contains(&ID_KP_EMAIL_PROTECTION),
            "smime_sponsor_policy: required_leaf_eku must contain id-kp-emailProtection"
        );
    }

    /// Positive #1: cert with organizationName + organizationIdentifier +
    /// givenName + surname form passes.
    ///
    /// Oracle: smime-sponsor-validated-self-signed-365d.der has:
    ///   Subject = C=GB, O=Acme Sponsor Ltd, organizationIdentifier=VATGB-12345678,
    ///             GN=Alice, SN=Sponsored, CN=Alice Sponsored
    ///   CertificatePolicies = 2.23.140.1.5.3.3
    ///   rfc822Name SAN = alice.sponsored@acme-sponsor.example.com
    ///   emailProtection EKU, cA=TRUE
    /// Verified via openssl x509 -inform DER -text -noout.
    #[test]
    fn smime_sponsor_givenname_surname_form_passes() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/smime-sponsor-validated-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        pkix_path::validate_path(
            &[cert],
            &anchors,
            &smime_sponsor_policy(NOW),
            &EcdsaP256Verifier,
        )
        .expect(
            "Sponsor-validated cert with organizationName+givenName+surname+serialNumber \
             DN, policy OID 2.23.140.1.5.3.3, rfc822 SAN, and emailProtection EKU \
             must pass smime_sponsor_policy",
        );
    }

    /// Positive #2: cert with organizationName + organizationIdentifier +
    /// pseudonym form passes. Exercises the `AnyOf(pseudonym, AllOf(givenName,
    /// surname))` branch of the DN rule alongside the required organizationName
    /// + organizationIdentifier.
    #[test]
    fn smime_sponsor_pseudonym_form_passes() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/smime-sponsor-pseudonym-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        pkix_path::validate_path(
            &[cert],
            &anchors,
            &smime_sponsor_policy(NOW),
            &EcdsaP256Verifier,
        )
        .expect(
            "Sponsor-validated cert with organizationName+pseudonym+serialNumber \
             DN must pass smime_sponsor_policy (AnyOf branch)",
        );
    }

    /// Negative #1: Mailbox-validated cert (no policy OID, no tier DN attrs)
    /// fails with `MissingLeafPolicyOid`.
    ///
    /// Oracle: smime-self-signed-365d.der is a Mailbox-validated baseline cert
    /// — it has emailProtection EKU and rfc822 SAN (passing the (e3)/(e4)
    /// checks) but no `CertificatePolicies` extension. The (e3a) leaf-policy-OID
    /// check fires and returns `MissingLeafPolicyOid { required: 2.23.140.1.5.3.3 }`.
    /// Exercises tier disambiguation: a sibling-tier cert that satisfies
    /// `smime_policy` does NOT satisfy `smime_sponsor_policy`.
    #[test]
    fn smime_sponsor_rejects_mailbox_validated_cert() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/smime-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        let result = pkix_path::validate_path(
            &[cert],
            &anchors,
            &smime_sponsor_policy(NOW),
            &EcdsaP256Verifier,
        );
        assert!(
            matches!(
                result,
                Err(pkix_path::Error::MissingLeafPolicyOid { required })
                    if required == CABF_SMIME_SPONSOR_VALIDATED_STRICT_POLICY
            ),
            "Mailbox-validated cert (no policy OID) must fail smime_sponsor_policy \
             with MissingLeafPolicyOid {{ required: 2.23.140.1.5.3.3 }}, got {result:?}"
        );
    }

    /// Negative #2: WebPKI cert (wrong EKU, no rfc822 SAN) fails with
    /// `MissingEku` — the (e3) EKU check fires before the tier-specific
    /// (e3a)/(e3b) checks.
    #[test]
    fn smime_sponsor_rejects_webpki_cert() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/webpki-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        assert!(
            matches!(
                pkix_path::validate_path(
                    &[cert],
                    &anchors,
                    &smime_sponsor_policy(NOW),
                    &EcdsaP256Verifier
                ),
                Err(pkix_path::Error::MissingEku)
            ),
            "WebPKI cert (wrong EKU) must fail smime_sponsor_policy with MissingEku"
        );
    }

    // -----------------------------------------------------------------------
    // smime_individual_multipurpose_policy — Individual-validated tier,
    // Multipurpose generation (PKIX-jbvb.9.5)
    //
    // Oracle: pkix-path/tests/fixtures/policy-checks/
    //   smime-individual-multipurpose-self-signed-365d.der    — givenName+surname form, policy OID 2.23.140.1.5.4.2
    //   smime-individual-multipurpose-pseudonym-self-signed-365d.der — pseudonym form, policy OID 2.23.140.1.5.4.2
    //   smime-individual-validated-self-signed-365d.der       — Strict generation (negative cross-tier oracle)
    //   smime-self-signed-365d.der                            — Mailbox-validated baseline (negative oracle)
    //   webpki-self-signed-365d.der                           — wrong EKU/SAN (negative oracle)
    //
    // Fixture provenance: `gen-smime-tier-fixtures.py` Multipurpose block;
    // structurally mirrors the Strict-generation Individual fixtures with
    // the asserted policy OID changed from `.4.3` to `.4.2`.
    // -----------------------------------------------------------------------

    #[test]
    fn smime_individual_multipurpose_policy_asserts_multipurpose_policy_oid() {
        let p = smime_individual_multipurpose_policy(NOW);
        let oids = p.required_leaf_policy_oids.as_deref().unwrap_or(&[]);
        assert_eq!(
            oids,
            &[CABF_SMIME_INDIVIDUAL_VALIDATED_MULTIPURPOSE_POLICY],
            "smime_individual_multipurpose_policy: required_leaf_policy_oids must be exactly [2.23.140.1.5.4.2]"
        );
    }

    #[test]
    fn smime_individual_multipurpose_policy_sets_dn_attr_rule() {
        let p = smime_individual_multipurpose_policy(NOW);
        assert!(
            p.required_leaf_subject_dn_attrs.is_some(),
            "smime_individual_multipurpose_policy: required_leaf_subject_dn_attrs must be set"
        );
    }

    #[test]
    fn smime_individual_multipurpose_policy_max_validity_is_825_days() {
        // Inherits the Strict-and-Multipurpose-generation cap per §6.3.2.
        let p = smime_individual_multipurpose_policy(NOW);
        assert_eq!(
            p.max_validity_secs,
            Some(825 * 86_400),
            "smime_individual_multipurpose_policy: max_validity_secs must be 825 days"
        );
    }

    #[test]
    fn smime_individual_multipurpose_policy_requires_email_protection_eku() {
        let p = smime_individual_multipurpose_policy(NOW);
        let ekus = p.required_leaf_eku.as_deref().unwrap_or(&[]);
        assert!(
            ekus.contains(&ID_KP_EMAIL_PROTECTION),
            "smime_individual_multipurpose_policy: required_leaf_eku must contain id-kp-emailProtection"
        );
    }

    /// Positive #1: cert with givenName + surname form passes.
    ///
    /// Oracle: smime-individual-multipurpose-self-signed-365d.der has:
    ///   Subject = C=GB, GN=Test, SN=Person, CN=Test Person
    ///   CertificatePolicies = 2.23.140.1.5.4.2 (Multipurpose)
    ///   rfc822Name SAN = individual-mp@example.com
    ///   emailProtection EKU
    ///   cA=TRUE (self-signed anchor)
    /// Verified via openssl x509 -inform DER -text -noout.
    #[test]
    fn smime_individual_multipurpose_givenname_surname_form_passes() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/smime-individual-multipurpose-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        pkix_path::validate_path(
            &[cert],
            &anchors,
            &smime_individual_multipurpose_policy(NOW),
            &EcdsaP256Verifier,
        )
        .expect(
            "Individual-validated Multipurpose cert with givenName+surname DN, \
             policy OID 2.23.140.1.5.4.2, rfc822 SAN, and emailProtection EKU \
             must pass smime_individual_multipurpose_policy",
        );
    }

    /// Positive #2: cert with pseudonym form passes.
    ///
    /// Oracle: smime-individual-multipurpose-pseudonym-self-signed-365d.der has:
    ///   Subject = C=GB, pseudonym=TestBoxMP, CN=TestBoxMP
    ///   CertificatePolicies = 2.23.140.1.5.4.2
    ///   rfc822Name SAN = testbox-mp@example.com
    /// Exercises the `AnyOf(pseudonym, AllOf(givenName, surname))` branch of
    /// the DN rule: pseudonym alone (without givenName/surname) satisfies
    /// the AnyOf clause.
    #[test]
    fn smime_individual_multipurpose_pseudonym_form_passes() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/smime-individual-multipurpose-pseudonym-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        pkix_path::validate_path(
            &[cert],
            &anchors,
            &smime_individual_multipurpose_policy(NOW),
            &EcdsaP256Verifier,
        )
        .expect(
            "Individual-validated Multipurpose cert with pseudonym DN \
             must pass smime_individual_multipurpose_policy (AnyOf branch)",
        );
    }

    /// Cross-tier negative #1: Strict-generation Individual cert fails the
    /// Multipurpose policy with `MissingLeafPolicyOid` because the asserted
    /// OID is `.4.3` but the Multipurpose policy requires `.4.2`.
    ///
    /// Oracle: smime-individual-validated-self-signed-365d.der asserts
    /// policy OID 2.23.140.1.5.4.3 (Strict). The Multipurpose policy's
    /// (e3a) check requires 2.23.140.1.5.4.2 and rejects.
    /// Exercises generation disambiguation: a sibling-generation cert that
    /// satisfies `smime_individual_policy` does NOT satisfy
    /// `smime_individual_multipurpose_policy`.
    #[test]
    fn smime_individual_multipurpose_rejects_strict_generation_cert() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/smime-individual-validated-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        let result = pkix_path::validate_path(
            &[cert],
            &anchors,
            &smime_individual_multipurpose_policy(NOW),
            &EcdsaP256Verifier,
        );
        assert!(
            matches!(
                result,
                Err(pkix_path::Error::MissingLeafPolicyOid { required })
                    if required == CABF_SMIME_INDIVIDUAL_VALIDATED_MULTIPURPOSE_POLICY
            ),
            "Strict-generation cert (policy OID 2.23.140.1.5.4.3) must fail \
             smime_individual_multipurpose_policy with MissingLeafPolicyOid \
             {{ required: 2.23.140.1.5.4.2 }}, got {result:?}"
        );
    }

    /// Cross-tier negative #2: Multipurpose cert fails the Strict policy
    /// with `MissingLeafPolicyOid`. Symmetric guarantee for the Strict
    /// direction — the two generations are mutually exclusive at the
    /// policy-OID level.
    #[test]
    fn smime_individual_strict_rejects_multipurpose_generation_cert() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/smime-individual-multipurpose-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        let result = pkix_path::validate_path(
            &[cert],
            &anchors,
            &smime_individual_policy(NOW),
            &EcdsaP256Verifier,
        );
        assert!(
            matches!(
                result,
                Err(pkix_path::Error::MissingLeafPolicyOid { required })
                    if required == CABF_SMIME_INDIVIDUAL_VALIDATED_STRICT_POLICY
            ),
            "Multipurpose-generation cert (policy OID 2.23.140.1.5.4.2) must fail \
             smime_individual_policy with MissingLeafPolicyOid \
             {{ required: 2.23.140.1.5.4.3 }}, got {result:?}"
        );
    }

    /// Negative #3: Mailbox-validated cert (no policy OID) fails with
    /// `MissingLeafPolicyOid`.
    #[test]
    fn smime_individual_multipurpose_rejects_mailbox_validated_cert() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/smime-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        let result = pkix_path::validate_path(
            &[cert],
            &anchors,
            &smime_individual_multipurpose_policy(NOW),
            &EcdsaP256Verifier,
        );
        assert!(
            matches!(
                result,
                Err(pkix_path::Error::MissingLeafPolicyOid { required })
                    if required == CABF_SMIME_INDIVIDUAL_VALIDATED_MULTIPURPOSE_POLICY
            ),
            "Mailbox-validated cert (no policy OID) must fail \
             smime_individual_multipurpose_policy with MissingLeafPolicyOid \
             {{ required: 2.23.140.1.5.4.2 }}, got {result:?}"
        );
    }

    /// Negative #4: WebPKI cert (wrong EKU, no rfc822 SAN) fails with
    /// `MissingEku` — the (e3) EKU check fires before the tier-specific
    /// (e3a)/(e3b) checks.
    #[test]
    fn smime_individual_multipurpose_rejects_webpki_cert() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/webpki-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        assert!(
            matches!(
                pkix_path::validate_path(
                    &[cert],
                    &anchors,
                    &smime_individual_multipurpose_policy(NOW),
                    &EcdsaP256Verifier
                ),
                Err(pkix_path::Error::MissingEku)
            ),
            "WebPKI cert (wrong EKU) must fail smime_individual_multipurpose_policy with MissingEku"
        );
    }

    // -----------------------------------------------------------------------
    // smime_sponsor_multipurpose_policy — Sponsor-validated tier, Multipurpose
    // generation (PKIX-jbvb.9.4)
    //
    // Oracle: pkix-path/tests/fixtures/policy-checks/
    //   smime-sponsor-multipurpose-self-signed-365d.der          — org+orgID+given+surname form, policy OID 2.23.140.1.5.3.2
    //   smime-sponsor-multipurpose-pseudonym-self-signed-365d.der — org+orgID+pseudonym form, policy OID 2.23.140.1.5.3.2
    //   smime-sponsor-validated-self-signed-365d.der             — Strict generation (negative cross-tier oracle)
    //   smime-self-signed-365d.der                               — Mailbox-validated baseline (negative oracle)
    //   webpki-self-signed-365d.der                              — wrong EKU/SAN (negative oracle)
    //
    // Fixture provenance: `gen-smime-tier-fixtures.py` Sponsor Multipurpose
    // block; structurally mirrors the Strict-generation Sponsor fixtures
    // with the asserted policy OID changed from `.3.3` to `.3.2`.
    // -----------------------------------------------------------------------

    #[test]
    fn smime_sponsor_multipurpose_policy_asserts_multipurpose_policy_oid() {
        let p = smime_sponsor_multipurpose_policy(NOW);
        let oids = p.required_leaf_policy_oids.as_deref().unwrap_or(&[]);
        assert_eq!(
            oids,
            &[CABF_SMIME_SPONSOR_VALIDATED_MULTIPURPOSE_POLICY],
            "smime_sponsor_multipurpose_policy: required_leaf_policy_oids must be exactly [2.23.140.1.5.3.2]"
        );
    }

    #[test]
    fn smime_sponsor_multipurpose_policy_sets_dn_attr_rule() {
        let p = smime_sponsor_multipurpose_policy(NOW);
        assert!(
            p.required_leaf_subject_dn_attrs.is_some(),
            "smime_sponsor_multipurpose_policy: required_leaf_subject_dn_attrs must be set"
        );
    }

    #[test]
    fn smime_sponsor_multipurpose_policy_max_validity_is_825_days() {
        // Inherits the Strict-and-Multipurpose-generation cap per §6.3.2.
        let p = smime_sponsor_multipurpose_policy(NOW);
        assert_eq!(
            p.max_validity_secs,
            Some(825 * 86_400),
            "smime_sponsor_multipurpose_policy: max_validity_secs must be 825 days"
        );
    }

    #[test]
    fn smime_sponsor_multipurpose_policy_requires_email_protection_eku() {
        let p = smime_sponsor_multipurpose_policy(NOW);
        let ekus = p.required_leaf_eku.as_deref().unwrap_or(&[]);
        assert!(
            ekus.contains(&ID_KP_EMAIL_PROTECTION),
            "smime_sponsor_multipurpose_policy: required_leaf_eku must contain id-kp-emailProtection"
        );
    }

    /// Positive #1: cert with org + orgID + givenName + surname form passes.
    ///
    /// Oracle: smime-sponsor-multipurpose-self-signed-365d.der has:
    ///   Subject = C=GB, O=Acme Sponsor Ltd, orgID=VATGB-12345678,
    ///             GN=Alice, SN=Sponsored, CN=Alice Sponsored
    ///   CertificatePolicies = 2.23.140.1.5.3.2 (Sponsor-validated Multipurpose)
    ///   rfc822Name SAN = alice.sponsored-mp@acme-sponsor.example.com
    ///   emailProtection EKU
    ///   cA=TRUE (self-signed anchor)
    /// Verified via openssl x509 -inform DER -text -noout.
    #[test]
    fn smime_sponsor_multipurpose_givenname_surname_form_passes() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/smime-sponsor-multipurpose-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        pkix_path::validate_path(
            &[cert],
            &anchors,
            &smime_sponsor_multipurpose_policy(NOW),
            &EcdsaP256Verifier,
        )
        .expect(
            "Sponsor-validated Multipurpose cert with org+orgID+givenName+surname DN, \
             policy OID 2.23.140.1.5.3.2, rfc822 SAN, and emailProtection EKU \
             must pass smime_sponsor_multipurpose_policy",
        );
    }

    /// Positive #2: cert with org + orgID + pseudonym form passes.
    ///
    /// Oracle: smime-sponsor-multipurpose-pseudonym-self-signed-365d.der has:
    ///   Subject = C=GB, O=Acme Sponsor Ltd, orgID=VATGB-87654321,
    ///             pseudonym=SponsoredAliasMP, CN=SponsoredAliasMP
    ///   CertificatePolicies = 2.23.140.1.5.3.2
    ///   rfc822Name SAN = sponsored-mp.alias@acme-sponsor.example.com
    /// Exercises the inner `AnyOf(pseudonym, AllOf(givenName, surname))` branch
    /// of the DN rule alongside the outer `AllOf` of organizationName and
    /// organizationIdentifier.
    #[test]
    fn smime_sponsor_multipurpose_pseudonym_form_passes() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/smime-sponsor-multipurpose-pseudonym-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        pkix_path::validate_path(
            &[cert],
            &anchors,
            &smime_sponsor_multipurpose_policy(NOW),
            &EcdsaP256Verifier,
        )
        .expect(
            "Sponsor-validated Multipurpose cert with org+orgID+pseudonym DN \
             must pass smime_sponsor_multipurpose_policy (AnyOf branch)",
        );
    }

    /// Cross-tier negative #1: Strict-generation Sponsor cert fails the
    /// Multipurpose policy with `MissingLeafPolicyOid` because the asserted
    /// OID is `.3.3` but the Multipurpose policy requires `.3.2`.
    ///
    /// Oracle: smime-sponsor-validated-self-signed-365d.der asserts
    /// policy OID 2.23.140.1.5.3.3 (Strict). The Multipurpose policy's
    /// (e3a) check requires 2.23.140.1.5.3.2 and rejects.
    /// Exercises generation disambiguation: a sibling-generation cert that
    /// satisfies `smime_sponsor_policy` does NOT satisfy
    /// `smime_sponsor_multipurpose_policy`.
    #[test]
    fn smime_sponsor_multipurpose_rejects_strict_generation_cert() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/smime-sponsor-validated-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        let result = pkix_path::validate_path(
            &[cert],
            &anchors,
            &smime_sponsor_multipurpose_policy(NOW),
            &EcdsaP256Verifier,
        );
        assert!(
            matches!(
                result,
                Err(pkix_path::Error::MissingLeafPolicyOid { required })
                    if required == CABF_SMIME_SPONSOR_VALIDATED_MULTIPURPOSE_POLICY
            ),
            "Strict-generation cert (policy OID 2.23.140.1.5.3.3) must fail \
             smime_sponsor_multipurpose_policy with MissingLeafPolicyOid \
             {{ required: 2.23.140.1.5.3.2 }}, got {result:?}"
        );
    }

    /// Cross-tier negative #2: Multipurpose cert fails the Strict policy
    /// with `MissingLeafPolicyOid`. Symmetric guarantee for the Strict
    /// direction — the two generations are mutually exclusive at the
    /// policy-OID level.
    #[test]
    fn smime_sponsor_strict_rejects_multipurpose_generation_cert() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/smime-sponsor-multipurpose-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        let result = pkix_path::validate_path(
            &[cert],
            &anchors,
            &smime_sponsor_policy(NOW),
            &EcdsaP256Verifier,
        );
        assert!(
            matches!(
                result,
                Err(pkix_path::Error::MissingLeafPolicyOid { required })
                    if required == CABF_SMIME_SPONSOR_VALIDATED_STRICT_POLICY
            ),
            "Multipurpose-generation cert (policy OID 2.23.140.1.5.3.2) must fail \
             smime_sponsor_policy with MissingLeafPolicyOid \
             {{ required: 2.23.140.1.5.3.3 }}, got {result:?}"
        );
    }

    /// Negative #3: Mailbox-validated cert (no policy OID, no tier DN attrs)
    /// fails with `MissingLeafPolicyOid`.
    #[test]
    fn smime_sponsor_multipurpose_rejects_mailbox_validated_cert() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/smime-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        let result = pkix_path::validate_path(
            &[cert],
            &anchors,
            &smime_sponsor_multipurpose_policy(NOW),
            &EcdsaP256Verifier,
        );
        assert!(
            matches!(
                result,
                Err(pkix_path::Error::MissingLeafPolicyOid { required })
                    if required == CABF_SMIME_SPONSOR_VALIDATED_MULTIPURPOSE_POLICY
            ),
            "Mailbox-validated cert (no policy OID) must fail \
             smime_sponsor_multipurpose_policy with MissingLeafPolicyOid \
             {{ required: 2.23.140.1.5.3.2 }}, got {result:?}"
        );
    }

    /// Negative #4: WebPKI cert (wrong EKU, no rfc822 SAN) fails with
    /// `MissingEku` — the (e3) EKU check fires before the tier-specific
    /// (e3a)/(e3b) checks.
    #[test]
    fn smime_sponsor_multipurpose_rejects_webpki_cert() {
        let cert = load(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/webpki-self-signed-365d.der"
        ));
        let anchors = [TrustAnchor::from_cert(cert.clone())];
        assert!(
            matches!(
                pkix_path::validate_path(
                    &[cert],
                    &anchors,
                    &smime_sponsor_multipurpose_policy(NOW),
                    &EcdsaP256Verifier
                ),
                Err(pkix_path::Error::MissingEku)
            ),
            "WebPKI cert (wrong EKU) must fail smime_sponsor_multipurpose_policy with MissingEku"
        );
    }
}
