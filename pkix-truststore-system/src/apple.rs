//! Keychain backend for macOS and iOS.
//!
//! # Verification
//!
//! Compiled and run on a `macos-latest` runner on every change to this
//! crate: `from_system` reports `Source::Native(MacosKeychain)` there
//! and returns a non-empty anchor set, so the Keychain calls work and
//! not merely type-check. How many anchors a given Mac yields, in what
//! order, and which it rejects is unmeasured — a runner's trust
//! settings are not a user's.
//!
//! iOS is a different matter: it shares this file but not its
//! entitlements, and no runner exists for it, so nothing here has been
//! compiled or run for an iOS target. See the crate documentation's
//! "Platform backend status" section.
//!
//! # What it reads
//!
//! Trust settings from all three domains — `System` (the shipped root
//! store), `Admin` (installed machine-wide) and `User` (installed for
//! the logged-in user) — because a certificate an administrator or the
//! user added is as much part of this machine's trust as Apple's own
//! roots, and a tool that ignored them would disagree with every other
//! client on the system.
//!
//! # Distrust is honoured
//!
//! `SecTrustSettings` records distrust as well as trust: a user can mark
//! a root `Deny` without removing it from the Keychain. Those are
//! excluded here. Getting this wrong is the one way this backend could
//! be actively dangerous rather than merely incomplete — it would hand
//! back an anchor the operator had explicitly revoked, and the
//! revocation would appear to have silently failed.
//!
//! Every other setting — `TrustRoot`, `TrustAsRoot`, `Unspecified`,
//! `Invalid`, or no settings recorded at all — is taken as trusted.
//! `Unspecified` and absent settings are the normal state of a shipped
//! Apple root: they mean "no override has been applied", and the
//! default for a certificate in these domains is to trust it.

use security_framework::trust_settings::{Domain, TrustSettings, TrustSettingsForCertificate};

use crate::Found;

/// Read anchors from the Keychain's trust settings.
///
/// Returns `None` when no domain could be read at all, which is how a
/// sandboxed process without Keychain entitlements presents. The caller
/// then falls through to the portable file reader rather than failing,
/// because such a process may still have a bundle it can read.
pub(crate) fn load() -> Option<Found> {
    let mut anchors = Vec::new();
    let mut skipped = 0usize;
    let mut any_domain_read = false;

    // Deliberately System first, then Admin, then User: a later domain
    // may legitimately hold the same certificate, and `pkix-truststore`
    // does not deduplicate, so the ordering is what decides which copy
    // is kept when they differ in encoding.
    for domain in [Domain::System, Domain::Admin, Domain::User] {
        let settings = TrustSettings::new(domain);
        let Ok(iter) = settings.iter() else {
            // A domain that cannot be enumerated is not fatal: User is
            // absent for a daemon with no logged-in session, and that
            // must not cost us the System roots.
            continue;
        };
        any_domain_read = true;

        for cert in iter {
            // `Ok(None)` means no trust settings are recorded for this
            // certificate, which for these domains is the ordinary case
            // and means trusted. `Err` means the query failed; treat it
            // the same way rather than dropping a root over a
            // transient API failure.
            let decision = settings
                .tls_trust_settings_for_certificate(&cert)
                .unwrap_or(None);
            if matches!(decision, Some(TrustSettingsForCertificate::Deny)) {
                // Explicitly distrusted by the operator. Excluded, and
                // not counted as skipped: skipping is for entries we
                // failed to handle, and this one was handled correctly.
                continue;
            }

            match pkix_truststore::from_der(&cert.to_der()) {
                Ok(anchor) => anchors.push(anchor),
                Err(_) => skipped += 1,
            }
        }
    }

    if !any_domain_read {
        return None;
    }
    Some(Found { anchors, skipped })
}
