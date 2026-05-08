//! Oracle implementations.
//!
//! An "oracle" is anything that can answer `(chain) -> Verdict`. The harness
//! runs a chain through each oracle in parallel and classifies the resulting
//! verdict tuple (PKIX-7nsf.5).
//!
//! v0.1 status:
//! - `pkix_path`: implemented (PKIX-7nsf.1).
//! - `openssl`:   implemented (PKIX-7nsf.2).
//! - `pyca`:      stubbed; PKIX-7nsf.3.

pub mod openssl;
pub mod pkix_path;
