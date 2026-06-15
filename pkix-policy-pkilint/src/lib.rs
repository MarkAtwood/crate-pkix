//! # pkix-policy-pkilint
//!
//! **Thin [`pkix_lint::Lint`] adapter over [`pkix_pkilint_bridge`]. Stub
//! crate.**
//!
//! `pkix-policy-pkilint` will expose each of pkilint's per-check
//! verdicts as a workspace [`pkix_lint::Lint`] implementation, so
//! callers can mix pkilint findings into a [`pkix_lint::LintRunner`]
//! alongside the workspace's own RFC-conformance and `-cabf` reference
//! lints, without any awareness that the verdicts come from a
//! subprocess.
//!
//! This is the pkilint analog of [`pkix-policy-zlint`].
//!
//! ## Status
//!
//! Stub crate — namespace reservation. The substantive content (Lint
//! impl wrapping pkilint checks, verdict mapping, catalog enumeration)
//! is planned for a future release.
//!
//! [`pkix_lint::Lint`]: https://docs.rs/pkix-lint
//! [`pkix_lint::LintRunner`]: https://docs.rs/pkix-lint
//! [`pkix_pkilint_bridge`]: https://docs.rs/pkix-pkilint-bridge
//! [`pkix-policy-zlint`]: https://docs.rs/pkix-policy-zlint

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
