//! # pkix-lint-cabf
//!
//! **Reference CA/Browser Forum lint bundles for [`pkix-lint`]. Not authoritative.**
//!
//! CA/B Forum Baseline Requirements (TLS BR, S/MIME BR) change on a ballot
//! cycle. The lint bundles in this crate are a small, curated snapshot of
//! marquee BR requirements. They are intended as a starting point: fork and
//! adapt to your deployment's current interpretation of the BR text, which is
//! the only canonical source.
//!
//! For the current Baseline Requirements:
//! - <https://cabforum.org/baseline-requirements/> (TLS)
//! - <https://cabforum.org/smime-br/> (S/MIME)
//!
//! Maintained on a best-effort basis. If your deployment depends on bit-exact
//! CA/B Forum conformance, you SHOULD vendor and review the relevant rule
//! definitions yourself, or use `pkix-policy-zlint` (see below).
//!
//! ## Unprincipled exception
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
//! The exception is **not a template.** No equivalent `pkix-lint-mozilla`,
//! `pkix-lint-fedramp`, `pkix-lint-dod`, or `pkix-lint-etsi` crates are
//! admitted without explicit human re-decision. For comprehensive CA/B Forum
//! coverage (matching zlint's ~700-lint scope), use `pkix-policy-zlint`
//! (PKIX-jy95).
//!
//! ## Modules
//!
//! - [`cabf_tls_br`] — CA/B Forum TLS Baseline Requirements lints. Bundles
//!   SC-081 phased validity caps, SHA-1 prohibition, RSA min-key-size,
//!   SAN/EKU presence, and `BasicConstraints` cA-flag checks behind
//!   [`cabf_tls_br::CabfTlsBrProfile`].
//!
//! ## Stance cross-references
//!
//! - AGENTS.md non-negotiable #5 — three-mode policy-class architecture,
//!   including the unprincipled-exception clause that admits this crate.
//! - Stance / epic: [PKIX-amgn].
//!
//! [PKIX-amgn]: https://github.com/MarkAtwood/crate-pkix
//! [`pkix-lint`]: https://docs.rs/pkix-lint

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, unreachable_pub)]
#![warn(missing_docs)]

pub mod cabf_tls_br;
