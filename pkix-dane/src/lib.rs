//! # pkix-dane
//!
//! **DANE (RFC 6698 / RFC 7671) TLSA record parsing and per-usage match
//! logic. Stub crate.**
//!
//! Accepts pre-validated TLSA records (the caller is responsible for DNS
//! resolution and DNSSEC validation) and evaluates them against
//! certificates using the four DANE usage modes:
//!
//! - **DANE-TA (usage 2)** — TLSA record pins a trust anchor; the
//!   certificate chain must chain to that anchor.
//! - **DANE-EE (usage 3)** — TLSA record pins the end-entity
//!   certificate directly; PKIX validation is bypassed.
//! - **PKIX-TA (usage 0)** — like DANE-TA, but the trust anchor must
//!   also pass standard PKIX path validation.
//! - **PKIX-EE (usage 1)** — like DANE-EE, but the end-entity
//!   certificate must also pass standard PKIX path validation.
//!
//! Selector (full certificate vs. SubjectPublicKeyInfo) and matching
//! type (exact, SHA-256, SHA-512) are handled per RFC 6698 §2.1.
//!
//! ## Design
//!
//! This crate deliberately does **not** perform DNS lookups. The
//! companion crate [`pkix-dane-resolver`] provides DNSSEC-validating
//! DNS resolution for callers that need it. Separating parsing/matching
//! from resolution keeps this crate `no_std`-friendly and testable
//! without network access.
//!
//! ## Status
//!
//! Stub crate — namespace reservation. The substantive content (TLSA
//! record types, selector/matching-type logic, per-usage evaluation)
//! is planned for a future release.
//!
//! [`pkix-dane-resolver`]: https://docs.rs/pkix-dane-resolver

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
