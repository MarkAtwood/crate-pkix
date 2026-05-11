//! NIST OSCAL bridge for pkix-lint outputs.
//!
//! Under the project's OSCAL alignment stance (PKIX-ztmr / PKIX-9vnx) the
//! canonical wire format for a pkix-lint run is an OSCAL Assessment Results
//! JSON document. Architecture 2 is in effect: pkix-lint's internal Rust
//! types ([`crate::Finding`], [`crate::report::EvaluationReport`], …) are
//! kept lean and tailored to lint work, and this module bridges between
//! them and OSCAL JSON at serialization time.
//!
//! [`emit::assessment_results`] is the canonical projection from an
//! [`crate::report::EvaluationReport`] to an OSCAL Assessment Results
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
