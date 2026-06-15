//! # pkix-dane-resolver
//!
//! **DNSSEC-validating resolver for DANE TLSA records. Stub crate.**
//!
//! Fetches TLSA records via DNS with DNSSEC validation and returns
//! them in the form expected by [`pkix-dane`]'s matching API. This is
//! the std-only companion to the `no_std`-friendly `pkix-dane` crate:
//! `pkix-dane` parses and evaluates TLSA records; this crate fetches
//! them from the network.
//!
//! Planned support:
//! - Synchronous and async resolver backends
//! - DNSSEC chain-of-trust validation (AD bit is not sufficient;
//!   the resolver validates signatures itself)
//! - `_port._proto.hostname` TLSA owner-name construction per
//!   RFC 6698 §3
//!
//! ## Status
//!
//! Stub crate — namespace reservation. The substantive content (resolver
//! integration, DNSSEC validation, TLSA owner-name construction) is
//! planned for a future release.
//!
//! [`pkix-dane`]: https://docs.rs/pkix-dane

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
