//! # pkix-pkilint-bridge
//!
//! **Shared subprocess and output-parsing infrastructure for running
//! [pkilint] on certificates. Stub crate.**
//!
//! `pkix-pkilint-bridge` will provide Rust-shaped infrastructure for
//! running pkilint on X.509 certificates: subprocess plumbing, output
//! parsing, verdict normalization, and a per-certificate cache. It is
//! the pkilint analog of [`pkix-zlint-bridge`] and will be consumed by:
//!
//! - **`pkix-policy-pkilint`** — a runtime adapter that exposes each of
//!   pkilint's checks as a workspace [`pkix_lint::Lint`] impl, so that
//!   compliance-rule selection happens at the [`pkix_lint::LintRunner`]
//!   level.
//! - **`pkix-difftest`**'s pkilint oracle — differential testing of
//!   workspace lints against pkilint's verdicts on the same certificate.
//!
//! ## Status
//!
//! Stub crate — namespace reservation. The substantive content
//! (subprocess management, pkilint JSON output parsing, verdict cache,
//! error types) is planned for a future release.
//!
//! [pkilint]: https://github.com/digicert/pkilint
//! [`pkix-zlint-bridge`]: https://docs.rs/pkix-zlint-bridge
//! [`pkix_lint::Lint`]: https://docs.rs/pkix-lint
//! [`pkix_lint::LintRunner`]: https://docs.rs/pkix-lint

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
