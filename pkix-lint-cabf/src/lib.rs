//! # pkix-lint-cabf
//!
//! **Reference CA/Browser Forum lint bundles for [`pkix-lint`]. Not authoritative.**
//!
//! CA/B Forum Baseline Requirements (TLS BR, S/MIME BR) change on a ballot
//! cycle. The lint bundles in this crate are a snapshot of those requirements
//! at the time of the most recent revision. They are intended as a starting
//! point: fork and adapt to your deployment's current interpretation of the
//! BR text, which is the only canonical source.
//!
//! For the current Baseline Requirements:
//! - <https://cabforum.org/baseline-requirements/> (TLS)
//! - <https://cabforum.org/smime-br/> (S/MIME)
//!
//! Maintained on a best-effort basis. If your deployment depends on bit-exact
//! CA/B Forum conformance, you SHOULD vendor and review the relevant rule
//! definitions yourself.
//!
//! ## Modules
//!
//! - [`cabf_tls_br`] — CA/B Forum TLS Baseline Requirements lints. Migrated
//!   from `pkix-lint` 0.4.0 in [PKIX-amgn.5]. Bundles SC-081 phased validity
//!   caps, SHA-1 prohibition, RSA min-key-size, SAN/EKU presence, and
//!   `BasicConstraints` cA-flag checks behind [`cabf_tls_br::CabfTlsBrProfile`].
//!
//! Future bundles (`cabf_smime_br`, `cabf_cs_br`) and zlint-derived OSCAL
//! Catalogs will land via [PKIX-amgn.8] and friends.
//!
//! This crate authors lint bundles as OSCAL Profiles per the workspace OSCAL
//! alignment stance ([PKIX-ztmr] / [PKIX-9vnx]). The executable lint impls
//! consumed by those Profiles live in [`pkix-lint`].
//!
//! Crate-level stance:
//! - Framework, not policy: workspace stance [PKIX-amgn].
//! - Per-rule split (standards-body specs in fast Rust, policy choices in
//!   OSCAL Profiles): workspace stance [PKIX-8qz1].
//!
//! [PKIX-ztmr]: https://github.com/MarkAtwood/crate-pkix
//! [PKIX-9vnx]: https://github.com/MarkAtwood/crate-pkix
//! [PKIX-amgn]: https://github.com/MarkAtwood/crate-pkix
//! [PKIX-amgn.5]: https://github.com/MarkAtwood/crate-pkix
//! [PKIX-amgn.8]: https://github.com/MarkAtwood/crate-pkix
//! [PKIX-8qz1]: https://github.com/MarkAtwood/crate-pkix
//! [`pkix-lint`]: https://docs.rs/pkix-lint

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, unreachable_pub)]
#![warn(missing_docs)]

pub mod cabf_tls_br;
