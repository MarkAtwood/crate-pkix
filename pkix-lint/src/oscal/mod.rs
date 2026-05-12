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
