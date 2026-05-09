//! Reference [`crate::RevocationFetcher`] implementations.
//!
//! Each submodule is gated behind a `client-*` feature so consumers pull
//! in only the HTTP backend they want. Available reference impls:
//!
//! | Module | Feature | Underlying crate |
//! |---|---|---|
//! | [`ureq`] | `client-ureq` | `ureq` 3.x (sync, rustls-backed HTTPS) |
//!
//! Future backends (e.g. an async reqwest implementation tracked under
//! PKIX-a1yc.10) will live as sibling submodules.

#[cfg(feature = "client-ureq")]
#[cfg_attr(docsrs, doc(cfg(feature = "client-ureq")))]
pub mod ureq;
