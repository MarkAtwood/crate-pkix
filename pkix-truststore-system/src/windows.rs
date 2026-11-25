//! CryptoAPI certificate-store backend for Windows.
//!
//! # UNVERIFIED
//!
//! **This file has never been compiled.** It was written against the
//! real signatures of `schannel` 0.1.30, read from the crate source
//! rather than recalled, but no Windows target was available to build or
//! run it. Treat it as a reviewed draft. See the crate documentation's
//! "Unverified backends" section.
//!
//! # What it reads
//!
//! The `ROOT` system store, from both the local-machine and
//! current-user hives. Windows presents trust as the union of the two:
//! the machine store holds what Microsoft ships and what an
//! administrator or Group Policy installed, the user store holds what
//! the logged-in user added. A client that read only one would disagree
//! with the rest of the system about which roots are trusted.
//!
//! # What it does not do
//!
//! Windows has no equivalent of reading a flat trusted-root list and
//! being done. Two real gaps are worth naming rather than hiding:
//!
//! - **The `DISALLOWED` store is not consulted.** Windows records
//!   explicitly distrusted certificates separately, and this backend
//!   does not subtract them, so a root an administrator distrusted
//!   without removing would still be returned. That is the same class
//!   of mistake the Apple backend avoids by honouring `Deny`, and it is
//!   unimplemented here only because it needs a second store read whose
//!   behaviour I cannot observe. A deployment that relies on
//!   `DISALLOWED` should not use this backend yet.
//! - **Auto-update roots are not fetched.** Modern Windows ships a
//!   small root set and pulls the rest on demand when a chain needs
//!   them. A root that has never been needed on this machine is not in
//!   the store, so a chain that Windows itself would complete may fail
//!   here. There is no supported way to trigger that fetch from outside
//!   CryptoAPI's own chain engine.
//!
//! Both are reasons the portable bundle reader remains the fallback
//! rather than being skipped on Windows.

use schannel::cert_store::CertStore;

use crate::Found;

/// Read anchors from the Windows `ROOT` stores.
///
/// Returns `None` when neither hive could be opened, so the caller falls
/// through to the portable reader rather than failing.
pub(crate) fn load() -> Option<Found> {
    let mut anchors = Vec::new();
    let mut skipped = 0usize;
    let mut any_store_opened = false;

    // Machine store first, then user: same ordering rationale as the
    // Apple backend, and it puts the administrator-controlled set ahead
    // of the per-user one.
    let stores = [
        CertStore::open_local_machine("ROOT"),
        CertStore::open_current_user("ROOT"),
    ];

    for store in stores.into_iter().flatten() {
        any_store_opened = true;
        for cert in store.certs() {
            match pkix_truststore::from_der(cert.to_der()) {
                Ok(anchor) => anchors.push(anchor),
                Err(_) => skipped += 1,
            }
        }
    }

    if !any_store_opened {
        return None;
    }
    Some(Found { anchors, skipped })
}
