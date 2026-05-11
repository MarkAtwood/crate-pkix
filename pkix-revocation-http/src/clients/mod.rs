//! Reference [`crate::RevocationFetcher`] / [`crate::AsyncRevocationFetcher`]
//! implementations.
//!
//! Each submodule is gated behind a `client-*` feature so consumers pull
//! in only the HTTP backend they want. Available reference impls:
//!
//! | Module | Feature | Trait family | Underlying crate |
//! |---|---|---|---|
//! | [`ureq`]    | `client-ureq`         | sync  | `ureq` 3.x (rustls HTTPS) |
//! | [`reqwest`] | `client-reqwest-async` | async | `reqwest` 0.12 (rustls HTTPS) |

#[cfg(feature = "client-ureq")]
#[cfg_attr(docsrs, doc(cfg(feature = "client-ureq")))]
pub mod ureq;

#[cfg(feature = "client-reqwest-async")]
#[cfg_attr(docsrs, doc(cfg(feature = "client-reqwest-async")))]
pub mod reqwest;
