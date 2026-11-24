//! Google's Certificate Transparency log-list signing key, as data.
//!
//! No validation, no network access, no filesystem access, no dependencies.
//! This crate is one public key plus the machinery to regenerate it, so that
//! a consumer verifying Google's signature over Google's CT log list can be
//! handed the key rather than having to go and find it.
//!
//! ```
//! use pkix_ct_google::GOOGLE;
//!
//! // Pass to pkix_ct::CtLogList::from_google_log_list_json_verified, which
//! // takes the key as DER SubjectPublicKeyInfo.
//! let spki: &[u8] = GOOGLE.spki;
//! assert!(!spki.is_empty());
//! ```
//!
//! # A key is a fact
//!
//! This crate ships a number. Verifying a signature with a published public
//! key is checking arithmetic, and the shape of this crate reflects that:
//! there is no builder, no policy, and no configuration. A caller who has
//! their own key does not need this crate at all, because
//! `pkix-ct` takes `&[u8]` directly.
//!
//! That the key is a fact is also why shipping it is not the same kind of act
//! as shipping a log list. **The list is policy** — it encodes which logs
//! Google's program has decided to trust, and it changes weekly. **The key is
//! not**; it merely says who signed. Nothing here commits a consumer to
//! Google's inclusion criteria. It commits them only to being able to tell
//! whether a list they fetched is the one Google published.
//!
//! # Google's acceptable-use policy, and what it binds
//!
//! Chrome's log-list documentation offers the lists for certificate
//! submitters such as certification authorities and for CT monitors and
//! auditors, and says they
//!
//! > may not be used to facilitate CT enforcement in TLS clients other than
//! > Chrome without explicit written permission from Chrome's CT team.
//!
//! Recorded here so a reader knows it exists. It is not a licence term on
//! this crate and does not travel with these bytes. Three structural points,
//! so the reader can weigh it themselves:
//!
//! - An acceptable-use policy takes its force from a service agreement —
//!   something accepted as a condition of access to a service. Retrieving an
//!   unauthenticated public URL accepts nothing and forms no such agreement.
//! - A public key is a number. Where a rightsholder has copyright or
//!   trademark to assert, they assert it. A policy statement doing that work
//!   instead tends to indicate neither reaches the artifact.
//! - It restricts a *use* in any case, not the key — and this crate's only
//!   use is determining who signed a document, which is not among the uses
//!   it names.
//!
//! None of that is legal advice, and an operator with counsel should ask
//! them rather than a crate's documentation.
//!
//! ## The warning inside it is worth keeping
//!
//! Google's stated reason — that unauthorized reliance "endangers not just
//! your users, but Chrome users and the CT ecosystem as a whole" — points at
//! something real, independent of who may permit what.
//!
//! A client that pins Chrome's *log list* inherits Chrome's inclusion and
//! retirement decisions, on Chrome's schedule, with no notice. Chrome retires
//! logs for reasons particular to its own program. A client holding a stale
//! copy then either rejects certificates that are perfectly good, because the
//! log is newer than its list, or believes it is enforcing CT while checking
//! against a set that no longer describes the ecosystem. Neither failure
//! announces itself.
//!
//! That is a strong argument for knowing where your log list comes from and
//! how it is refreshed — the same argument against baking in anchors
//! generally. It is not an argument against being able to check a signature,
//! which is all this crate enables, and which is precisely what makes a
//! fetched list safe to refresh often.
//!
//! # Provenance, and its limits
//!
//! This is weaker than [`pkix-dnssec-anchor`][pda], and the difference
//! matters enough to state rather than gloss.
//!
//! IANA signs its trust-anchor file, so that crate's generator verifies a
//! detached signature and fails closed. **Google does not sign this key, and
//! publishes no out-of-band copy of it** — no fingerprint in a signed
//! artifact, no copy in an independently distributed source tree. Chrome does
//! not even use this path; it receives log lists through the component
//! updater's PKI Metadata component. The `gstatic.com` key and signature
//! exist for third parties.
//!
//! So the chain terminates at HTTPS to `gstatic.com` — which is to say in the
//! Web PKI, the thing Certificate Transparency exists to police. That
//! circularity is inherent to bootstrapping CT from the network, and no
//! amount of care in this crate removes it.
//!
//! What `gen.sh` does instead is a cross-check that is still worth something:
//! it fetches the key, the log list and Google's detached signature over that
//! list, and verifies the signature *using the fetched key*. A key that
//! verifies Google's current published list is Google's current signing key,
//! or all three artifacts were substituted together. That rules out a stale
//! key, a truncated or corrupted fetch, a wrong file at the URL, and a key
//! belonging to some other Google program. The crate's tests re-run that same
//! check against the committed sample list, so it is a property of every
//! release and not just of the day the key was captured.
//!
//! [pda]: https://docs.rs/pkix-dnssec-anchor
//!
//! # Keeping it current
//!
//! The key rotates rarely — far more rarely than the list it signs, which is
//! the reason this split is practical at all. But when it does rotate, a
//! consumer pinning the old key sees signature verification fail on a list
//! that is in fact genuine, which is a confusing failure to debug.
//!
//! `./gen.sh --check` fetches Google's key and reports drift against the
//! committed one without writing anything, and
//! `.github/workflows/external-anchors.yml` runs it on a schedule. A rotation
//! means releasing this crate alone: consumers pick it up with `cargo update`,
//! `pkix-ct` needs no change, and nothing waits on a `pkix-ct` release.

#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod generated;

pub use generated::{GOOGLE, GOOGLE_SPKI_SHA256_HEX};

/// A Certificate Transparency log-list signing key, with its provenance.
///
/// The provenance fields are not used in verification. They are here so a
/// release can be audited by reading it — where the key came from and when it
/// was captured — without consulting the generator or the git history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct LogListKey {
    /// The key as a DER `SubjectPublicKeyInfo`.
    ///
    /// This is what `pkix-ct`'s verified log-list constructor expects, and
    /// what `openssl pkey -pubin -outform DER` emits from the published PEM.
    pub spki: &'static [u8],

    /// The URL this key was retrieved from.
    pub source: &'static str,

    /// The date it was retrieved, `YYYY-MM-DD`, UTC.
    ///
    /// Not an expiry and not consulted by anything. It bounds how stale a
    /// release can silently be: a consumer comparing it against the current
    /// date learns how long ago this snapshot was taken, which is the
    /// question a stale pinned key raises.
    pub retrieved: &'static str,
}

// Non-negotiable #6: result types stay cache-friendly and inspectable.
const _: () = {
    const fn assert_copy<T: Copy>() {}
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_copy::<LogListKey>();
    assert_send_sync::<LogListKey>();
};
