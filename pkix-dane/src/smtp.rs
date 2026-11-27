//! SMTP DANE name checks — RFC 7672 §3.2.
//!
//! RFC 7672 profiles DANE for MTA-to-MTA SMTP, and its name checks differ
//! from the HTTPS path in ways that are not optional. This module implements
//! that profile's §3.2 and nothing else: it performs no DNS lookups, no MX
//! resolution and no TLSA matching. Those belong to the resolver and to
//! [`verify_dane_ta`](crate::verify_dane_ta) respectively.
//!
//! # Why a separate entry point
//!
//! Three differences, in descending order of how badly a shared code path
//! would get them wrong.
//!
//! 1. **The reference identity is a *set*, not one hostname.** For
//!    DANE-TA(2), RFC 7672 §3.2.2 requires the TLSA base domain as the
//!    primary identifier *plus* the original next-hop domain and its
//!    CNAME expansion, with membership depending on how the base domain was
//!    reached. [`SmtpIdentities`] is that set.
//!
//! 2. **The CN is consulted when no DNS-ID is present.** RFC 7672 §3.2.3
//!    keeps the CN-ID fallback that RFC 6125 §6.4.4 deprecated for the Web
//!    PKI, because MTA certificates are frequently old and self-managed and
//!    there is no user to prompt. That rule lives in
//!    [`pkix_identity::verify_dns_name_with_cn_fallback`], never on the
//!    default path.
//!
//! 3. **DANE-EE(3) skips name checks entirely**, per §3.2.1 — a MUST NOT, not
//!    an optimization. [`verify_smtp_name`] takes the usage so this cannot be
//!    forgotten by a caller.
//!
//! # The CN-ID rule outruns `dNSName` name constraints
//!
//! For DANE-TA(2) there is a certification path, and that path's `dNSName`
//! name constraints do not reach the CN this module may match on. RFC 5280
//! §4.2.1.10 applies them "only to the corresponding name type in
//! subjectAltName", so a leaf with no SAN passes them vacuously, and rule 2
//! above then consults its CN. An intermediate constrained to one subtree
//! can therefore vouch for a name outside it by putting that name only in
//! the CN.
//!
//! This module cannot fix it: it is handed a certificate and a set of
//! reference identifiers, never the path. RFC 5280's answer for a CA is to
//! use `directoryName` constraints, which do apply to the subject field.
//! A relying party that needs more has to refuse a no-SAN leaf itself.
//! PKIX-skxt.
//!
//! # What this module deliberately does not decide
//!
//! Whether DANE applies at all, whether the MX lookup was secure, and which
//! MX host to try next are lookup-time questions answered against DNS
//! answers, not against a certificate. They are the caller's, and the
//! `MxOrigin` passed to [`SmtpIdentities`] is where the answer enters here.

use x509_cert::Certificate;

use crate::record::TlsaUsage;

/// The reference identifiers a server certificate may satisfy, per RFC 7672
/// §3.2.2.
///
/// Construct with the constructor matching how the TLSA base domain was
/// reached; the set differs between them, and using the wrong one either
/// rejects a legitimate server or — in the insecure-MX case — accepts a name
/// the lookup never authenticated.
///
/// The primary identifier is always first, which is the order §3.2.2 states
/// ("the TLSA base domain as the primary reference identifier") and the order
/// a log line should prefer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmtpIdentities<'a> {
    // At most three: base domain, next-hop, CNAME-expanded next-hop.
    // A fixed array keeps this allocation-free, which matters because this
    // crate is no_std and a sending MTA builds one of these per delivery
    // attempt per MX host.
    ids: [Option<&'a str>; 3],
}

impl<'a> SmtpIdentities<'a> {
    /// RFC 7672 §3.2.2, "TLSA records for MX hostnames", reached by a
    /// **"secure" MX lookup**.
    ///
    /// - `base_domain` — the TLSA base domain, i.e. the MX hostname, possibly
    ///   CNAME-expanded. The primary identifier.
    /// - `next_hop` — the original next-hop domain used in the MX lookup.
    ///   Required as a second identifier.
    /// - `cname_expanded_next_hop` — the CNAME-expanded original next-hop
    ///   domain, included as a third identifier **if different** from
    ///   `next_hop`. Pass `None` when the next-hop domain was not a CNAME.
    ///
    /// Equal values are collapsed rather than repeated, so a caller that
    /// cannot easily tell whether the expansion differs may pass it anyway.
    #[must_use]
    pub fn secure_mx(
        base_domain: &'a str,
        next_hop: &'a str,
        cname_expanded_next_hop: Option<&'a str>,
    ) -> Self {
        let mut this = Self {
            ids: [Some(base_domain), None, None],
        };
        this.push(next_hop);
        if let Some(expanded) = cname_expanded_next_hop {
            this.push(expanded);
        }
        this
    }

    /// RFC 7672 §3.2.2: DANE TLS used **despite "insecure" MX redirection**.
    ///
    /// > When the client MTA is employing DANE TLS security despite
    /// > "insecure" MX redirection, the MX hostname is the only reference
    /// > identifier.
    ///
    /// The next-hop domain is excluded deliberately and its exclusion is the
    /// point: an attacker who can tamper with an unsigned MX RRset chooses
    /// the MX hostname, so a certificate matching the *next-hop* domain would
    /// prove nothing about having reached the intended destination. Accepting
    /// it would let a successful authentication be recorded as secure
    /// delivery to a domain that was never authenticated — which §2.2.1
    /// forbids in as many words.
    #[must_use]
    pub fn insecure_mx(mx_hostname: &'a str) -> Self {
        Self {
            ids: [Some(mx_hostname), None, None],
        }
    }

    /// RFC 7672 §3.2.2, "TLSA records for non-MX hostnames".
    ///
    /// Covers a destination with no MX records (the domain is its own SMTP
    /// server) and an administrator-configured relay not subject to MX
    /// resolution.
    ///
    /// - `base_domain` — the TLSA base domain. The primary identifier.
    /// - `original_next_hop` — required as a second identifier when
    ///   `base_domain` is the *CNAME-expanded* original next-hop domain.
    ///   Pass `None` when no CNAME was involved, in which case the two are
    ///   the same name and there is nothing to add.
    #[must_use]
    pub fn non_mx(base_domain: &'a str, original_next_hop: Option<&'a str>) -> Self {
        let mut this = Self {
            ids: [Some(base_domain), None, None],
        };
        if let Some(next_hop) = original_next_hop {
            this.push(next_hop);
        }
        this
    }

    /// Append `name` unless it is already present or the set is full.
    fn push(&mut self, name: &'a str) {
        if self
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(name))
        {
            return;
        }
        for slot in &mut self.ids {
            if slot.is_none() {
                *slot = Some(name);
                return;
            }
        }
    }

    /// The primary reference identifier — the TLSA base domain.
    #[must_use]
    pub fn primary(&self) -> &'a str {
        self.ids[0].expect("slot 0 is populated by every constructor")
    }

    /// Every reference identifier, primary first.
    pub fn iter(&self) -> impl Iterator<Item = &'a str> + '_ {
        self.ids.iter().filter_map(|slot| *slot)
    }

    /// How many identifiers are in the set: 1, 2 or 3.
    #[must_use]
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    /// Always `false`; every constructor populates the primary identifier.
    ///
    /// Present because clippy asks for it alongside [`len`](Self::len), and
    /// because a caller generic over collections should not have to special-
    /// case this type.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }
}

/// The outcome of an SMTP DANE name check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmtpNameCheck<'a> {
    /// No name check was performed, as RFC 7672 §3.2.1 requires for
    /// DANE-EE(3).
    ///
    /// This is a success. The TLSA record itself binds the certificate, so
    /// the server's name is not in question and checking it would reject
    /// working configurations for no security gain.
    NotRequired,

    /// The certificate matched this reference identifier.
    ///
    /// Which one matched is reported rather than discarded because RFC 7672
    /// §2.2.1 requires delivery logs to distinguish secure delivery to the
    /// intended next-hop domain from authentication via an insecurely
    /// determined MX host. A log line naming the matched identifier can make
    /// that distinction; a bare boolean cannot.
    Matched(&'a str),
}

/// Why an SMTP DANE name check did not succeed.
///
/// Separate from [`crate::DaneError`] because these are name-check outcomes
/// rather than TLSA record outcomes, and because `PkixUsageUnusable` is a
/// decision this profile makes that the base DANE paths do not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SmtpNameError {
    /// PKIX-TA(0) or PKIX-EE(1), which this profile treats as unusable.
    ///
    /// RFC 7672 §3.1.3 says server operators SHOULD NOT publish these for
    /// port 25, leaves client treatment **undefined**, and permits clients to
    /// treat them as unusable:
    ///
    /// > SMTP client treatment of TLSA RRs with certificate usages
    /// > PKIX-TA(0) or PKIX-EE(1) is undefined. As with any other unsupported
    /// > certificate usage, SMTP clients MAY treat such records as
    /// > "unusable".
    ///
    /// This profile takes that MAY. It is a choice, not a conformance
    /// requirement, and the reasoning is the RFC's: PKIX usages cannot aid
    /// SMTP TLS security, because an attacker able to compromise DNSSEC can
    /// substitute a record bearing any convenient non-PKIX usage, and MTAs
    /// have neither an agreed CA set nor a user to approve an exception.
    PkixUsageUnusable {
        /// The usage found in the record.
        usage: TlsaUsage,
    },

    /// An unrecognized or private-use certificate usage.
    UsageUnsupported {
        /// The usage octet found in the record.
        usage: TlsaUsage,
    },

    /// The certificate presented a name, but none matched any reference
    /// identifier.
    ///
    /// The server is not the one that was being connected to, so under
    /// RFC 7672 §3.2 the message must not be delivered over this connection.
    NoIdentityMatch,

    /// The certificate presented no usable name at all: no SAN `dNSName` and
    /// no `commonName`.
    ///
    /// Distinguished from [`NoIdentityMatch`](Self::NoIdentityMatch) because
    /// the two suggest different causes — a certificate that names nothing is
    /// likely misissued, whereas one naming the wrong host suggests the
    /// connection went somewhere unintended.
    NoPresentedIdentity,

    /// A Subject Alternative Name extension was present but could not be
    /// parsed.
    ///
    /// Treated as a failure rather than as an absent SAN: whether a DNS-ID is
    /// present selects between two different matching rules in RFC 7672
    /// §3.2.3, and a malformed extension leaves that unanswerable.
    MalformedSan,
}

impl core::fmt::Display for SmtpNameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PkixUsageUnusable { usage } => write!(
                f,
                "certificate usage {} is treated as unusable for SMTP (RFC 7672 §3.1.3)",
                usage.to_octet()
            ),
            Self::UsageUnsupported { usage } => {
                write!(f, "unsupported certificate usage {}", usage.to_octet())
            }
            Self::NoIdentityMatch => {
                f.write_str("no reference identifier matched the server certificate")
            }
            Self::NoPresentedIdentity => {
                f.write_str("the server certificate presents no DNS-ID and no commonName")
            }
            Self::MalformedSan => f.write_str("the subjectAltName extension could not be parsed"),
        }
    }
}

impl core::error::Error for SmtpNameError {}

/// Perform the RFC 7672 §3.2 name check for a TLSA usage.
///
/// Takes the usage rather than assuming a name check is wanted, because
/// §3.2.1 makes skipping one a **MUST NOT perform** for DANE-EE(3) rather
/// than a choice. A caller that forgot would reject every DANE-EE deployment
/// whose certificate does not happen to carry its hostname.
///
/// | Usage | Behaviour |
/// |---|---|
/// | DANE-EE(3) | [`SmtpNameCheck::NotRequired`] — §3.2.1 forbids the check |
/// | DANE-TA(2) | §3.2.2 / §3.2.3 matching against `identities` |
/// | PKIX-TA(0), PKIX-EE(1) | [`SmtpNameError::PkixUsageUnusable`] — §3.1.3 |
/// | anything else | [`SmtpNameError::UsageUnsupported`] |
///
/// Matching follows §3.2.3: only DNS-IDs are considered when the certificate
/// presents any, and the `commonName` is consulted only when it presents
/// none. Wildcards are honoured in either, restricted to a single leftmost
/// label matching exactly one label — §3.2.3's default, not its
/// local-policy MAY.
///
/// This checks the **name** only. It does not verify that the certificate
/// matches a TLSA record, nor that the record came from a "secure" lookup.
/// Both are prerequisites, and both belong to the caller.
///
/// # Errors
///
/// See [`SmtpNameError`]. Every variant means the message must not be
/// delivered over this connection.
pub fn verify_smtp_name<'a>(
    usage: TlsaUsage,
    cert: &Certificate,
    identities: &SmtpIdentities<'a>,
) -> Result<SmtpNameCheck<'a>, SmtpNameError> {
    match usage {
        // RFC 7672 §3.2.1: "The SMTP client MUST NOT perform certificate
        // name checks with certificate usage DANE-EE(3)."
        TlsaUsage::DaneEe => return Ok(SmtpNameCheck::NotRequired),

        // RFC 7672 §3.2.2: name checks are required, against the set below.
        TlsaUsage::DaneTa => {}

        // RFC 7672 §3.1.3, taking the MAY. See PkixUsageUnusable.
        TlsaUsage::PkixTa | TlsaUsage::PkixEe => {
            return Err(SmtpNameError::PkixUsageUnusable { usage })
        }

        other => return Err(SmtpNameError::UsageUnsupported { usage: other }),
    }

    // §3.2.3 matching, applied to each identifier in §3.2.2's set. Any match
    // suffices: "The server certificate is considered matched when one of its
    // presented identifiers matches any of the client's reference
    // identifiers."
    //
    // The error from the last attempt is not what we report. A set where one
    // identifier fails to match and another is absent from the certificate
    // should report NoIdentityMatch, because a name *was* presented; only a
    // certificate presenting nothing at all yields NoPresentedIdentity.
    let mut saw_a_presented_name = false;

    for identity in identities.iter() {
        let Ok(name) = pkix_identity::ServerName::dns_name(identity) else {
            // A reference identifier that is not a valid DNS name cannot be
            // matched by any certificate. Skipped rather than failed, so one
            // malformed entry in the set does not mask a legitimate match on
            // another — a caller assembling the set from DNS answers may have
            // been handed something strange for the next-hop domain.
            continue;
        };

        match pkix_identity::verify_dns_name_with_cn_fallback(cert, &name) {
            Ok(()) => return Ok(SmtpNameCheck::Matched(identity)),
            Err(pkix_identity::IdentityError::NoMatchingSan) => saw_a_presented_name = true,
            Err(pkix_identity::IdentityError::MissingSan) => {}
            Err(pkix_identity::IdentityError::MalformedSan) => {
                return Err(SmtpNameError::MalformedSan)
            }
            // IdentityError is #[non_exhaustive]; a variant added later is
            // treated as "this identifier did not match" rather than as a
            // presented name, which is the conservative reading: it cannot
            // turn into a spurious success, and it cannot upgrade
            // NoPresentedIdentity into NoIdentityMatch on no evidence.
            Err(_) => {}
        }
    }

    if saw_a_presented_name {
        Err(SmtpNameError::NoIdentityMatch)
    } else {
        Err(SmtpNameError::NoPresentedIdentity)
    }
}
