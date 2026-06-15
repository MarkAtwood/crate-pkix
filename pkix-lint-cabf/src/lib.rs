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
//! ## Reporting divergences
//!
//! This crate is a snapshot interpretation of the CA/B Forum Baseline
//! Requirements. The canonical source is the CA/B Forum's published BR
//! text; this crate is reference, not authoritative. See `divergences.md`
//! in this crate's source tree for the spec versions last refreshed
//! against and the known intentional divergences.
//!
//! If you find that a lint in this crate differs from what the current
//! CA/B Forum BR says — wrong section reference, outdated rule, missing
//! new ballot — please open an issue or PR at
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
//! ## Modules
//!
//! - [`cabf_tls_br`] — CA/B Forum TLS Baseline Requirements lints: SC-081
//!   phased validity caps, SHA-1 prohibition, RSA min-key-size, SAN/EKU
//!   presence, and `BasicConstraints` cA-flag checks. Individual `Lint`
//!   impls plus the canonical [`cabf_tls_br::all_lints`] constructor; the
//!   `LintProfile` bundling lives on
//!   `pkix_profiles_cabf::WebPkiProfile`.
//!
//! ## Stance cross-references
//!
//! - AGENTS.md non-negotiable #5 — three-mode policy-class architecture,
//!   including the unprincipled-exception clause that admits this crate.
//! - Stance / epic: [PKIX-amgn].
//!
//! ## Limitations
//!
//! - **Reference, not authoritative.** See the unprincipled-exception
//!   clause above. The BR text is the only canonical source; this crate
//!   ships a curated subset of marquee BR predicates as Lint impls.
//! - **Not predicate-comprehensive.** [`cabf_tls_br`] covers SC-081
//!   phased validity caps, SHA-1 prohibition, RSA min-key-size, SAN/EKU
//!   presence, and `BasicConstraints` cA-flag checks. Full TLS BR
//!   predicate coverage (matching zlint's CA/B Forum lints, roughly
//!   one Lint per BR sub-section) is the job of `pkix-policy-zlint`
//!   (tracked under `PKIX-jy95.10`).
//! - **No S/MIME BR or Code Signing BR lint module yet.** The
//!   `pkix-profiles-cabf` crate ships the corresponding [`Profile`]
//!   types (`SmimeProfile`, `CodeSigningProfile`); per-predicate Lint
//!   coverage for those BRs is comprehensive via `pkix-policy-zlint`.
//! - **No `-mozilla`, `-fedramp`, `-dod`, `-etsi`.** The unprincipled
//!   exception applies to CA/B Forum content only. Other industry-forum,
//!   government, or vendor policies must come in via policy-adapter
//!   crates that defer to upstream tools.
//!
//! [PKIX-amgn]: https://github.com/MarkAtwood/crate-pkix
//! [`pkix-lint`]: https://docs.rs/pkix-lint
//! [`Profile`]: https://docs.rs/pkix-path/latest/pkix_path/trait.Profile.html

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod cabf_tls_br;
