//! # pkix-profiles-cabf
//!
//! **Reference implementation of CA/Browser Forum cert profile requirements. Not authoritative.**
//!
//! CA/B Forum Baseline Requirements (TLS BR, S/MIME BR, Code Signing BR) change
//! on a ballot cycle. The implementations in this crate are a snapshot of those
//! requirements at the time of the most recent revision. They are intended as a
//! starting point: fork and adapt to your deployment's current interpretation of
//! the BR text, which is the only canonical source.
//!
//! For the current Baseline Requirements:
//! - <https://cabforum.org/baseline-requirements/> (TLS)
//! - <https://cabforum.org/smime-br/> (S/MIME)
//! - <https://cabforum.org/code-signing-baseline-requirements/> (Code Signing)
//!
//! Maintained on a best-effort basis. If your deployment depends on bit-exact
//! CA/B Forum conformance, you SHOULD vendor and review the relevant rule
//! definitions yourself.
//!
//! ## Status
//!
//! Stub crate. The substantive content (`TlsBrProfile`, `SmimeBrProfile`,
//! `CodeSigningBrProfile`, CA/B Forum allowed-algorithm tables, validity-cap
//! helpers, identity-tier required-field tables) is scheduled to land via
//! [PKIX-amgn.4] — refactor of [`pkix-profiles`] to strip CA/B Forum content
//! into this crate and keep only RFC-baseline profiles upstream.
//!
//! Crate-level stance:
//! - Framework, not policy: workspace stance [PKIX-amgn].
//! - Per-rule split (standards-body specs in fast Rust, policy choices in
//!   OSCAL Profiles): workspace stance [PKIX-8qz1].
//!
//! [PKIX-amgn]: https://github.com/MarkAtwood/crate-pkix
//! [PKIX-amgn.4]: https://github.com/MarkAtwood/crate-pkix
//! [PKIX-8qz1]: https://github.com/MarkAtwood/crate-pkix
//! [`pkix-profiles`]: https://docs.rs/pkix-profiles

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, unreachable_pub)]
#![warn(missing_docs)]
