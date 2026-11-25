//! SMTP DANE verification — the entry point for RFC 7672 delivery.
//!
//! [`verify_smtp_server_dane`] takes a [`DeliveryTarget`] from
//! [`pkix_dane::smtp_lookup`] discovery plus the chain the server presented,
//! and reports what DANE concluded.
//!
//! # It reports; it does not decide
//!
//! The function returns [`SmtpDaneVerdict`] and every outcome is `Ok`,
//! including authentication failure. There is no failure-policy parameter and
//! no setting that turns a failure into a success. The verdict is an input to
//! the MTA's own decision — tag the message, route it to a different queue,
//! defer it, bounce it, or deliver it anyway — because that decision depends
//! on the deployment, and a library cannot make it.
//!
//! Three outcomes, and the distinction between the last two is the whole
//! point of this type:
//!
//! | Verdict | Meaning |
//! |---|---|
//! | [`Authenticated`](SmtpDaneVerdict::Authenticated) | the server proved it holds a key the domain published |
//! | [`NotApplicable`](SmtpDaneVerdict::NotApplicable) | the domain published nothing usable; DANE had nothing to say |
//! | [`Failed`](SmtpDaneVerdict::Failed) | the domain published usable records and the server did **not** match them |
//!
//! `NotApplicable` and `Failed` must never be collapsed. The first is an
//! ordinary pre-DANE connection. The second means the server presented a
//! certificate the domain's own DNS contradicts.
//!
//! # What RFC 7672 says about delivering after a failure
//!
//! §3.2 is unambiguous:
//!
//! > When at least one usable "secure" TLSA record is found, the SMTP client
//! > MUST use TLSA records to authenticate the SMTP server. Messages MUST NOT
//! > be delivered via the SMTP server if authentication fails.
//!
//! [`SmtpDaneVerdict::rfc7672_permits_delivery`] is that rule as a predicate,
//! so a conforming MTA is one line away and a non-conforming one has to
//! visibly ignore it.
//!
//! The reason behind the MUST NOT is worth knowing before overriding it. A
//! DANE failure where usable "secure" records exist means either the
//! receiving server is misconfigured **or the connection is being
//! intercepted**, and a sending client cannot tell which. Delivering anyway
//! in the second case hands the message to whoever is intercepting it. The
//! rule is not pedantry; it is the one place in opportunistic DANE where
//! something is actually known to be wrong.
//!
//! That said, delivering with the failure recorded is a coherent policy for
//! deployments the RFC was not written for — a staged rollout measuring DANE
//! before enforcing it, in the manner of DMARC `p=none`, or an MTA whose own
//! policy engine decides per-destination. This module supports that by
//! reporting precisely rather than by offering a switch that hides the
//! difference.

use x509_cert::Certificate;

use crate::Error;

use pkix_dane::smtp::{verify_smtp_name, SmtpNameCheck, SmtpNameError};
use pkix_dane::smtp_lookup::DeliveryTarget;
use pkix_dane::{DaneError, PresentedCert, TlsaRecord, TlsaUsage};
use pkix_path::{SignatureVerifier, ValidatedPath};

use pkix_aia::AiaFetcher;
use pkix_profiles::Profile;
use pkix_revocation::RevocationChecker;

/// What DANE concluded about an SMTP server.
///
/// See the [module documentation](self) for why failure is a verdict rather
/// than an error.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum SmtpDaneVerdict {
    /// The server authenticated against the domain's TLSA records.
    Authenticated {
        /// Which usage matched: DANE-EE(3) or DANE-TA(2).
        usage: TlsaUsage,
        /// The record that matched.
        record: TlsaRecord,
        /// For DANE-TA(2), the validated path to the synthesized anchor.
        ///
        /// `None` for DANE-EE(3), which authenticates the leaf directly and
        /// builds no path — RFC 7671 §5.1.
        path: Option<ValidatedPath>,
        /// Which reference identifier the certificate matched, when a name
        /// check was performed.
        ///
        /// `None` for DANE-EE(3), where RFC 7672 §3.2.1 forbids the check.
        /// Recorded because §2.2.1 requires delivery logs to distinguish
        /// secure delivery to the intended next-hop domain from
        /// authentication via an insecurely determined MX host.
        matched_identity: Option<String>,
    },

    /// The domain published no usable "secure" TLSA records for this server.
    ///
    /// An ordinary pre-DANE opportunistic TLS connection, or cleartext. DANE
    /// had nothing to say, and nothing is known to be wrong.
    NotApplicable,

    /// Usable "secure" TLSA records exist and the server did not match them.
    ///
    /// **Something is wrong.** Either the receiving server is misconfigured or
    /// the connection is being intercepted, and this side cannot tell which.
    /// See the [module documentation](self) before deciding to deliver.
    Failed(SmtpDaneFailure),
}

impl SmtpDaneVerdict {
    /// Whether RFC 7672 §3.2 permits delivering a message over this
    /// connection.
    ///
    /// `false` only for [`Failed`](Self::Failed). An MTA that wants RFC 7672
    /// conformance can gate on this; one with its own policy has the full
    /// verdict to work from.
    #[must_use]
    pub const fn rfc7672_permits_delivery(&self) -> bool {
        !matches!(self, Self::Failed(_))
    }

    /// Whether DANE authenticated the server.
    ///
    /// Distinct from [`rfc7672_permits_delivery`](Self::rfc7672_permits_delivery),
    /// which is also true for [`NotApplicable`](Self::NotApplicable). A log
    /// line claiming an authenticated channel needs this one.
    #[must_use]
    pub const fn is_authenticated(&self) -> bool {
        matches!(self, Self::Authenticated { .. })
    }
}

/// Why DANE authentication failed.
///
/// Each variant is a different operational problem at the receiving end, which
/// is why they are not collapsed: an MTA reporting to a postmaster, or tagging
/// a message for later analysis, wants to say which.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum SmtpDaneFailure {
    /// No usable record matched the presented certificate or chain.
    ///
    /// The receiving domain's TLSA records do not describe the certificate its
    /// server is serving — a stale record after a key rotation is the common
    /// cause, and interception is the one that matters.
    NoRecordMatched(DaneError),

    /// A DANE-TA(2) record identified a trust anchor, but the chain did not
    /// validate to it.
    PathValidationFailed(Error),

    /// The chain matched a DANE-TA(2) record but failed the RFC 7672 §3.2.2
    /// name check.
    NameCheckFailed(SmtpNameError),

    /// Only PKIX-TA(0) or PKIX-EE(1) records were published.
    ///
    /// RFC 7672 §3.1.3 leaves client treatment of these undefined and permits
    /// treating them as unusable, which this profile does. The receiving
    /// domain has published records that cannot authenticate an SMTP
    /// connection, which is worth telling its postmaster.
    OnlyPkixUsages,
}

/// Verify an SMTP server against the TLSA records discovery found for it.
///
/// `target` comes from [`pkix_dane::smtp_lookup`]. `chain` is what the server
/// presented, leaf first, and `chain_der` the same certificates as received —
/// **not** re-encoded, since RFC 6698 §2.1.2 matching digests the octets on
/// the wire and a round trip through a DER encoder can change them.
///
/// # Use `BasicSmtpMtaProfile`, not a TLS profile
///
/// Pass [`pkix_profiles::BasicSmtpMtaProfile`], which is plain RFC 5280 with
/// no SubjectAltName requirement and no EKU requirement.
///
/// `BasicTlsProfile` is the wrong choice and fails in a way that points
/// nowhere near the profile. It requires a SAN, correctly for the Web PKI;
/// RFC 7672 §3.2.3 consults the Subject DN `commonName` precisely because
/// MTA-to-MTA certificates frequently carry their name only there. Such a
/// certificate is rejected during **path validation**, before any name check
/// runs, and surfaces as `Failed(PathValidationFailed(Path(MissingSan)))` on a
/// server whose certificate RFC 7672 accepts without reservation. It also
/// requires `id-kp-serverAuth`, which an EKU-less self-managed certificate
/// does not satisfy.
///
/// This affects DANE-TA(2) only. DANE-EE(3) validates no path, so the profile
/// is never consulted for it.
///
/// What the profile does **not** relax: validity dates and name checks both
/// apply for DANE-TA(2). RFC 7671 §5.2 grants no relaxation, and §5.2.3
/// expects a chain that "has not expired... including leaf certificate name
/// checks". Only DANE-EE(3) skips those, by validating no path at all.
///
/// [`pkix_profiles::BasicSmtpMtaProfile`]: https://docs.rs/pkix-profiles
///
/// # There is no trust-store parameter, deliberately
///
/// DANE-EE(3) authenticates the leaf directly and validates no path.
/// DANE-TA(2) validates to the anchor its own record supplies, and to that
/// anchor **alone** — merging it with a caller's trust store would implement
/// "DANE-TA or any CA", which is weaker than either. And PKIX-TA(0) and
/// PKIX-EE(1), the two usages that would consult a trust store, are treated
/// as unusable here per RFC 7672 §3.1.3.
///
/// So no path in this function reads a caller's anchors, and the signature
/// says so rather than accepting a parameter it ignores.
///
/// # Returns
///
/// A [`SmtpDaneVerdict`]. Authentication failure is a verdict, not an error —
/// see the [module documentation](self).
///
/// # Errors
///
/// Only for inputs this function cannot interpret: `chain` and `chain_der`
/// disagreeing in length, or an empty chain. A server that presented nothing
/// usable is an error rather than a verdict because no DANE conclusion can be
/// drawn about a chain that was never received.
// Eight parameters, one over the threshold. Kept because this function
// deliberately mirrors `verify_tls_server_dane`'s shape — a caller moving
// between the HTTPS and SMTP entry points should not have to learn a
// different calling convention — and bundling them into a config struct here
// while the sibling takes them positionally would make the pair harder to
// read, not easier.
//
// `expect` rather than `allow`, per PKIX-g3ra: if the parameter list ever
// shrinks below the threshold this becomes a warning instead of silently
// outliving its reason.
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors verify_tls_server_dane's parameter list deliberately"
)]
pub fn verify_smtp_server_dane<V, P, R, A>(
    target: &DeliveryTarget,
    chain: &[Certificate],
    chain_der: &[&[u8]],
    profile: &P,
    now_unix: u64,
    verifier: &V,
    revocation: &R,
    aia: &A,
) -> crate::Result<SmtpDaneVerdict>
where
    V: SignatureVerifier,
    P: Profile,
    R: RevocationChecker,
    A: AiaFetcher,
{
    if chain.is_empty() {
        return Err(Error::Dane(DaneError::ResolutionFailed(
            "empty certificate chain".into(),
        )));
    }
    if chain.len() != chain_der.len() {
        return Err(Error::Dane(DaneError::ResolutionFailed(format!(
            "chain_der has {} entries for a {}-certificate chain; they must \
                 be index-aligned",
            chain_der.len(),
            chain.len()
        ))));
    }

    let Some(response) = target.tlsa_response() else {
        return Ok(SmtpDaneVerdict::NotApplicable);
    };

    let presented: Vec<PresentedCert<'_>> = chain
        .iter()
        .zip(chain_der.iter())
        .map(|(parsed, der)| PresentedCert::new(der, parsed))
        .collect();
    let leaf = &presented[0];

    // RFC 7672 §3.2.1: DANE-EE(3) authenticates the leaf directly and takes
    // no name check and no path. Tried first because it is both the common
    // deployment and the cheapest.
    match pkix_dane::verify_dane_ee(leaf, &response) {
        Ok(record) => {
            return Ok(SmtpDaneVerdict::Authenticated {
                usage: TlsaUsage::DaneEe,
                record: record.clone(),
                path: None,
                matched_identity: None,
            })
        }
        Err(DaneError::NoRecordsForUsage { .. }) => {}
        Err(other) => {
            // Usage-3 records existed and none matched. Not fatal on its own:
            // the domain may also publish usage-2 records, which are tried
            // below. The error is kept only if nothing else succeeds.
            if !has_usage(&response, TlsaUsage::DaneTa) {
                return Ok(SmtpDaneVerdict::Failed(SmtpDaneFailure::NoRecordMatched(
                    other,
                )));
            }
        }
    }

    // RFC 7672 §3.2.2: DANE-TA(2) requires a path to the synthesized anchor
    // and a name check against the reference identifier set.
    match pkix_dane::verify_dane_ta(&presented, &response) {
        Ok(dane_anchor) => {
            let record = dane_anchor.record().clone();
            let anchor = dane_anchor.into_anchor();

            // To the DANE anchor alone. Not merged with any caller trust
            // store — see the note on this function.
            let policy = profile.policy(now_unix);
            let path = match crate::verify_chain(
                chain,
                core::slice::from_ref(&anchor),
                &policy,
                verifier,
                revocation,
                aia,
            ) {
                Ok(path) => path,
                Err(e) => {
                    return Ok(SmtpDaneVerdict::Failed(
                        SmtpDaneFailure::PathValidationFailed(e),
                    ))
                }
            };

            // §3.2.2 / §3.2.3. The identity set is narrower when the MX RRset
            // was insecure; DeliveryTarget has already applied that.
            let identities = target
                .identities()
                .expect("identities accompany records, and records are present here");
            match verify_smtp_name(TlsaUsage::DaneTa, &chain[0], &identities) {
                Ok(SmtpNameCheck::Matched(identity)) => Ok(SmtpDaneVerdict::Authenticated {
                    usage: TlsaUsage::DaneTa,
                    record,
                    path: Some(path),
                    matched_identity: Some(identity.to_string()),
                }),
                // Unreachable for usage 2, which §3.2.2 requires a check for.
                Ok(SmtpNameCheck::NotRequired) => Ok(SmtpDaneVerdict::Authenticated {
                    usage: TlsaUsage::DaneTa,
                    record,
                    path: Some(path),
                    matched_identity: None,
                }),
                Err(e) => Ok(SmtpDaneVerdict::Failed(SmtpDaneFailure::NameCheckFailed(e))),
            }
        }
        Err(DaneError::NoRecordsForUsage { .. }) => {
            // Neither usage 2 nor usage 3 is present. If the domain published
            // only PKIX usages, say so: that is a misconfiguration worth
            // reporting rather than an absence of DANE.
            if has_usage(&response, TlsaUsage::PkixTa) || has_usage(&response, TlsaUsage::PkixEe) {
                Ok(SmtpDaneVerdict::Failed(SmtpDaneFailure::OnlyPkixUsages))
            } else {
                Ok(SmtpDaneVerdict::NotApplicable)
            }
        }
        Err(other) => Ok(SmtpDaneVerdict::Failed(SmtpDaneFailure::NoRecordMatched(
            other,
        ))),
    }
}

/// Whether the response carries at least one usable record of `usage`.
fn has_usage(response: &pkix_dane::TlsaResponse, usage: TlsaUsage) -> bool {
    response
        .records()
        .iter()
        .any(|r| r.usage() == usage && r.is_usable())
}

// ---------------------------------------------------------------------------
// Combining DANE with MTA-STS (RFC 8461 §2)
// ---------------------------------------------------------------------------

/// Why delivery to a host is forbidden.
#[cfg(feature = "mta-sts")]
#[cfg_attr(docsrs, doc(cfg(feature = "mta-sts")))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SmtpTransportDenial {
    /// DANE validation failed.
    ///
    /// RFC 8461 §2 makes this final: no MTA-STS result may override it, so a
    /// matching MTA-STS policy does not rescue the delivery.
    DaneFailed,

    /// DANE did not apply, and an MTA-STS policy in `enforce` mode rejected
    /// the host.
    ///
    /// RFC 8461 §5: "Sending MTAs MUST NOT deliver the message to hosts that
    /// fail MX matching or certificate validation or that do not support
    /// STARTTLS."
    MtaStsEnforceFailed,
}

/// What authenticated an SMTP connection, or why it may not proceed.
///
/// The combined verdict from both of SMTP's transport-security mechanisms.
/// A sender that implements only one does not need this.
#[cfg(feature = "mta-sts")]
#[cfg_attr(docsrs, doc(cfg(feature = "mta-sts")))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SmtpTransportSecurity {
    /// DANE authenticated the connection.
    ///
    /// The strongest outcome, and not weakened by any MTA-STS result: §2's
    /// precedence runs one way, so a failing MTA-STS policy does not
    /// downgrade a successful DANE validation either.
    DaneAuthenticated,

    /// DANE did not apply, and an MTA-STS policy permitted the host.
    ///
    /// Weaker than [`DaneAuthenticated`](Self::DaneAuthenticated): the policy
    /// is authenticated by the Web PKI plus an unsigned TXT record, so first
    /// contact is trust-on-first-use. Distinguished from DANE precisely so a
    /// consumer can tell which mechanism was used rather than reading both as
    /// equivalent.
    MtaStsMatched,

    /// Neither mechanism applied.
    ///
    /// Delivery may proceed over opportunistic TLS or in the clear. Reported
    /// rather than folded into a failure because the overwhelming majority of
    /// SMTP has no transport-security policy at all, and treating that as an
    /// error would make the type useless.
    Unprotected,

    /// Delivery must not proceed.
    Forbidden(SmtpTransportDenial),
}

#[cfg(feature = "mta-sts")]
impl SmtpTransportSecurity {
    /// Whether delivery may proceed.
    ///
    /// False only for [`Forbidden`](Self::Forbidden). An unprotected
    /// connection is permitted — see that variant.
    #[must_use]
    pub const fn permits_delivery(&self) -> bool {
        !matches!(self, Self::Forbidden(_))
    }

    /// Whether a transport-security mechanism authenticated the peer.
    ///
    /// True for DANE and for a matched MTA-STS policy. A consumer that needs
    /// to tell those apart should match on the variant, because they are not
    /// equally strong.
    #[must_use]
    pub const fn is_authenticated(&self) -> bool {
        matches!(self, Self::DaneAuthenticated | Self::MtaStsMatched)
    }
}

/// Combine a DANE verdict with an MTA-STS outcome, enforcing RFC 8461 §2.
///
/// §2, verbatim:
///
/// > senders who implement MTA-STS validation MUST NOT allow MTA-STS Policy
/// > validation to override a failing DANE validation.
///
/// So a failing DANE verdict decides the question before MTA-STS is consulted
/// at all. This function exists to make that ordering impossible to get
/// wrong: the alternative is every caller rediscovering it from the RFC, and
/// the failure mode is silent — a matching MTA-STS policy would quietly
/// rescue a delivery that DANE had already refused, which is precisely the
/// downgrade DANE was deployed to prevent.
///
/// `mta_sts` is `None` when no policy was fetched, which is the common case:
/// most domains publish none.
///
/// # What this does not do
///
/// It combines verdicts. It does not fetch a policy, validate a certificate
/// or check STARTTLS support — RFC 8461 §4.2 and §5 are the caller's, and a
/// [`pkix_mta_sts::PolicyOutcome::Matched`] says only that MX matching
/// passed.
#[cfg(feature = "mta-sts")]
#[cfg_attr(docsrs, doc(cfg(feature = "mta-sts")))]
#[must_use]
pub fn combine_smtp_transport_security(
    dane: &SmtpDaneVerdict,
    mta_sts: Option<pkix_mta_sts::PolicyOutcome>,
) -> SmtpTransportSecurity {
    use pkix_mta_sts::PolicyOutcome;

    // §2 first, and unconditionally. Deliberately before any look at
    // `mta_sts`, so no MTA-STS result can reach the decision.
    if let SmtpDaneVerdict::Failed(_) = dane {
        return SmtpTransportSecurity::Forbidden(SmtpTransportDenial::DaneFailed);
    }

    // A successful DANE validation is likewise not weakened by MTA-STS. §2's
    // precedence is one-directional: it protects DANE's verdict, and nothing
    // in RFC 8461 lets a policy failure downgrade an authenticated channel.
    if dane.is_authenticated() {
        return SmtpTransportSecurity::DaneAuthenticated;
    }

    let Some(outcome) = mta_sts else {
        return SmtpTransportSecurity::Unprotected;
    };

    // The delivery decision comes from the predicate, not from the variant.
    // `PolicyOutcome` is non-exhaustive, so a variant added later that
    // forbids delivery must still forbid it here; matching variant by variant
    // would silently permit it.
    if !outcome.mta_sts_permits_delivery() {
        return SmtpTransportSecurity::Forbidden(SmtpTransportDenial::MtaStsEnforceFailed);
    }

    if outcome == PolicyOutcome::Matched {
        SmtpTransportSecurity::MtaStsMatched
    } else {
        // A `testing` failure delivers as though there were no failure (§5),
        // `none` means no active policy, and an outcome this version does not
        // know cannot be claimed to have authenticated anything. All three
        // permit delivery without protection.
        SmtpTransportSecurity::Unprotected
    }
}
