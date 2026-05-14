//! NIST OSCAL bridge for pkix-lint outputs.
//!
//! This module provides an OSCAL Assessment Results JSON projection of a
//! pkix-lint run. OSCAL is one supported output format, not the source of
//! truth: pkix-lint's internal Rust types ([`crate::Finding`],
//! [`crate::report::EvaluationReport`], …) remain the authoritative
//! in-process representation, and this module bridges between them and
//! OSCAL JSON at serialization time. Other output formats (custom JSON
//! shapes, plain-text reports, machine-consumable Rust enums) are
//! perfectly reasonable alternatives; choosing OSCAL is a deployment
//! decision, not a workspace mandate. See the project stance memory
//! `pkix-oscal-demoted-2026-05-11` for the framing change that demoted
//! OSCAL from "canonical" to "available, not privileged."
//!
//! [`emit::assessment_results`] projects an
//! [`crate::report::EvaluationReport`] into an OSCAL Assessment Results
//! `serde_json::Value`.
//!
//! [`parse::deviation_store_from_risks`] is the inverse of
//! [`emit::risks_from_store`]: it reconstructs a
//! [`crate::deviation::DeviationStore`] from an OSCAL Risk array. The two
//! halves form a closed round-trip loop for deviation-policy persistence
//! (`(parse . emit)` over a non-empty store yields an `Eq`-equal store).
//! All [`crate::deviation::Deviation`] fields — including the optional
//! `priority` resolution-ordering hint — round-trip through the OSCAL
//! Risk array. The priority field is encoded as the optional
//! `pkix-lint.deviation-priority` prop, emitted only when non-zero so
//! pre-priority OSCAL files (which lack the prop) round-trip
//! byte-identically.
//!
//! # Feature
//!
//! This module is gated behind the `oscal` cargo feature, which pulls in
//! `serde_json` as a real dependency. The core lint engine stays
//! dep-light when consumers do not need OSCAL output.

pub mod catalog;
pub mod emit;
pub mod parse;
pub mod profile;

/// OSCAL schema version this module targets. Encoded as
/// `metadata.oscal-version` by every emitter and validated against the
/// same string by every parser that consumes a full OSCAL document.
///
/// Tied to NIST OSCAL v1.1.2 — the latest stable release at the time
/// of this module's introduction. Bumping requires re-checking
/// field-shape changes in the Assessment Results, Catalog, and Profile
/// schemas.
pub(crate) const OSCAL_VERSION: &str = "1.1.2";

/// Set of OSCAL schema versions the parsers in this module accept on
/// `metadata.oscal-version`. Currently a singleton `[OSCAL_VERSION]`;
/// expanding the set requires verifying field-shape compatibility for
/// each additional version.
///
/// See [`parse::check_oscal_version`] for the entry-point validator
/// used by [`parse::lint_ids_from_catalog`] and
/// [`profile::resolve_profile`]. The bare-Risk-array parser
/// [`parse::deviation_store_from_risks`] does not consume metadata —
/// callers wrapping it in a full OSCAL document are responsible for
/// validating the enclosing document's version separately.
pub(crate) const SUPPORTED_OSCAL_VERSIONS: &[&str] = &[OSCAL_VERSION];
