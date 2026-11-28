//! In-process oracle: `pkix_path::validate_path`.
//!
//! This is the system under test. The other oracles (`openssl`, `pyca`) exist
//! to compare against this one, so the convention here is "run pkix-path with
//! its default-feature build and a permissive `ValidationPolicy::new(now)`".
//!
//! Why permissive defaults? Because we want to catch verdict divergence on
//! chains that real-world implementations accept. Adding strictures (required
//! SAN, EKU allowlists, RSA key floor) would make pkix-path stricter than
//! every other oracle by construction — every chain that fails an extra
//! stricture would then be classified `StricterThanWild`, which is noise, not
//! signal.
//!
//! When PKIX-7nsf.5 lands the classifier, the policy will become a CLI flag
//! so the user can opt into stricter modes for targeted comparisons.
//!
//! # Revocation
//!
//! When `Chain.crls` is non-empty (PKIX-emf1.2), every cert in the chain is
//! checked against each supplied CRL via `pkix_revocation::CrlChecker`. The
//! first CRL that reports `Revoked` produces a `Verdict::Fail` whose reason
//! is taken from `pkix_revocation::Error::Display`. CRLs that do not apply
//! to a given cert (issuer mismatch, scope flag mismatch, signature failure,
//! …) are treated as "this CRL has no determination" and ignored — the diff
//! classifier's job is to surface where this oracle and OpenSSL / pyca
//! disagree, including on what counts as a valid CRL. Empty `Chain.crls`
//! preserves the prior no-revocation behaviour.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use der::Decode;
use pkix_path::{validate_path, DefaultVerifier, TrustAnchor, ValidationPolicy};
use pkix_revocation::{
    check_revocation_with_crls, crl_applies_to, CrlChecker, Error as RevError,
    RevocationChecker as _,
};
use x509_cert::crl::CertificateList;
use x509_cert::Certificate;

use crate::{Chain, Verdict};

/// Run `pkix_path::validate_path` over the chain.
///
/// The chain must end in the trust anchor (`Chain::root_in_chain == true`).
/// The last cert is split off and used as the only `TrustAnchor`; everything
/// before it is the leaf-first validation chain. `ValidationPolicy::new(now)`
/// is used with the current system time.
///
/// Returns:
/// - `Ok(Verdict::Pass)` on validation success.
/// - `Ok(Verdict::Fail { reason })` when validation fails — the reason is the
///   `Display` of `pkix_path::Error`.
/// - `Err(io::Error)` for *harness* failures: malformed chain, missing root,
///   etc. These must be surfaced separately so a chain that the harness can't
///   even feed to the oracle is not silently classified as a verdict.
pub fn verify(chain: &Chain) -> io::Result<Verdict> {
    if !chain.root_in_chain {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "pkix-path oracle requires the trust anchor to be present as the last cert; \
             root_in_chain = false is not supported (PKIX-7nsf.4 follow-up)",
        ));
    }
    if chain.certs_der.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "pkix-path oracle requires at least 2 certs (leaf + root); single-cert \
             chains have no path to validate",
        ));
    }

    // Parse all certs from DER. Failures here are harness errors (malformed
    // input), not verdicts.
    let mut certs: Vec<Certificate> = Vec::with_capacity(chain.certs_der.len());
    for (i, der) in chain.certs_der.iter().enumerate() {
        let cert = Certificate::from_der(der).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "cert at index {i} in chain {:?} failed to parse: {e}",
                    chain.label
                ),
            )
        })?;
        certs.push(cert);
    }

    // The last cert is the trust anchor; everything before is the validation
    // chain. We use direct indexing (rather than `.split_last().expect(...)`)
    // because the `len < 2` early return above proves the indices are valid;
    // splicing rather than expect-ing keeps the function panic-free even if
    // a future refactor weakens the precondition check.
    let last = certs.len() - 1;
    let anchor_cert = certs[last].clone();
    let anchors = [TrustAnchor::from_cert(certs[last].clone())];
    let validation_chain: Vec<Certificate> = certs.into_iter().take(last).collect();

    // Choose validation time: pinned per-chain value if the corpus loader
    // supplied one (limbo's `validation_time`), else fall back to the system
    // clock. Wall-clock fallback is appropriate for PKITS / PEM-tree, where
    // notBefore/notAfter divergences relative to the current clock are
    // themselves a real signal the harness should surface (clock-skew
    // tolerance varies between oracles).
    let now = chain.validation_time_unix.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    });
    // RFC 5280 §6.1.1 initial inputs. A corpus that does not vary them
    // supplies the defaults, so this is unconditional: `anyPolicy` alone
    // with the flags clear is what `ValidationPolicy::new` already means.
    let inputs = &chain.initial_policy_inputs;
    let mut policy = ValidationPolicy::new(now);
    policy.initial_policy_set.clone_from(&inputs.policy_set);
    policy.initial_policy_mapping_inhibit = inputs.policy_mapping_inhibit;
    policy.initial_explicit_policy = inputs.explicit_policy;
    policy.initial_any_policy_inhibit = inputs.any_policy_inhibit;

    match validate_path(&validation_chain, &anchors, &policy, &DefaultVerifier) {
        Ok(_) => {}
        Err(e) => {
            return Ok(Verdict::Fail {
                reason: format!("{e}"),
            });
        }
    }

    // Path is valid. If the chain ships CRLs, run revocation per cert.
    if !chain.crls.is_empty() {
        // Every certificate available as a CRL signer: the chain, the anchor,
        // and whatever path building left out — which for several vectors is
        // the CA's dedicated CRL-signing certificate.
        let mut bundle = validation_chain.clone();
        bundle.push(anchor_cert.clone());
        for der in &chain.aux_certs_der {
            if let Ok(c) = Certificate::from_der(der) {
                bundle.push(c);
            }
        }
        // A CRL signed by a revoked certificate must not be trusted.
        let bundle = drop_revoked(&bundle, &chain.crls);
        if let Some(rev_reason) =
            check_revocation(&validation_chain, &anchors[0], &bundle, &chain.crls, now)
        {
            return Ok(Verdict::Fail { reason: rev_reason });
        }
    }

    Ok(Verdict::Pass)
}

/// Walk the chain leaf-to-anchor, trying each supplied CRL against each
/// cert. Return `Some(reason)` when a certificate is revoked **or** when its
/// revocation status cannot be determined; `None` only when every certificate
/// was cleared by some CRL.
///
/// Iteration order is determined first by chain position (leaf first, anchor
/// last) and second by CRL order in `crls`. Within a single cert, the first
/// CRL that reports `Revoked` wins.
///
/// # Per-CRL soft, per-certificate hard
///
/// A single CRL that does not apply to a certificate — issuer mismatch,
/// scope, signature failure, parse error, or a CRL rendered unusable by an
/// unrecognized critical extension (RFC 5280 §5.2 / §5.3) — carries no
/// determination, so the next CRL is tried. That part is unchanged and is
/// necessary: PKITS chains ship several CRLs of which only some apply.
///
/// What changed is the case where *no* CRL applies to a certificate. That
/// used to be reported as "not revoked", which is a fail-open: it claims a
/// clean bill of health from zero evidence. It now fails.
///
/// This mattered once `pkix-revocation` began correctly refusing CRLs with
/// unrecognized critical extensions. Those CRLs had previously been applied
/// and reported `Revoked`; afterwards they were refused, every error was
/// ignored, and three PKITS chains that NIST classes **invalid** started
/// passing — 4.15.4, 4.4.8 and 4.4.9. The library was right and this oracle
/// was modelling a validator nobody would ship.
///
/// It now matches what `pkix_chain::verify_chain` does, which propagates
/// every revocation error with `?` and has no soft-fail mode. The difference
/// is only that this oracle is handed a pool of CRLs and so tries them all
/// before concluding, where `verify_chain` holds one checker and fails on
/// first error.
///
/// Callers with no CRLs at all are unaffected: the caller skips this function
/// entirely when `chain.crls` is empty, which preserves the no-revocation
/// behaviour for the bulk of the corpus.
/// Drop certificates that a supplied CRL says are revoked.
///
/// A CRL signed by a revoked certificate must not be trusted, so a revoked
/// certificate must not be offered to signer discovery.
/// `new_with_signer_discovery` enforces `cRLSign` (§6.3.3(f)) and requires the
/// signer to chain to a self-signed certificate, but it does not ask whether
/// the signer is still valid — nothing in its inputs would let it.
///
/// PKITS 4.4.21 is the vector that turns on this. It is structurally
/// identical to 4.4.19 — same topology, CRL-signing certificate a sibling of
/// the chain, empty CRL — and NIST classes it invalid for one reason: the
/// CRL signer's certificate, serial 68, is revoked by `TrustAnchorRootCRL`.
/// Trusting that CRL leaves the end entity's status undetermined, so a
/// conformant validator fails closed.
///
/// The check is a direct serial lookup against CRLs issued by the
/// certificate's own issuer, not full path validation of each bundle member.
/// That is enough for the question being asked — "has this candidate signer
/// been revoked by its own CA" — and avoids recursing into revocation
/// checking while in the middle of a revocation check.
fn drop_revoked(bundle: &[Certificate], crls: &[Vec<u8>]) -> Vec<Certificate> {
    let parsed: Vec<CertificateList<x509_cert::certificate::Rfc5280>> = crls
        .iter()
        .filter_map(|c| CertificateList::from_der(c).ok())
        .collect();

    bundle
        .iter()
        .filter(|cert| {
            let serial = cert.tbs_certificate().serial_number();
            let issuer = cert.tbs_certificate().issuer();
            !parsed.iter().any(|crl| {
                &crl.tbs_cert_list.issuer == issuer
                    && crl
                        .tbs_cert_list
                        .revoked_certificates
                        .as_deref()
                        .unwrap_or(&[])
                        .iter()
                        .any(|e| &e.serial_number == serial)
            })
        })
        .cloned()
        .collect()
}

/// RFC 5280 §5.2.4 `id-ce-deltaCRLIndicator`.
const OID_DELTA_CRL_INDICATOR: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.27");

/// Whether this CRL is a delta CRL.
///
/// Presence of the OID is the marker, not whether its value decodes: a
/// malformed value still makes the CRL a delta and still must stop it being
/// used as a base. `pkix-revocation` has the same predicate internally but
/// does not export it; a one-OID presence test is cheap to restate here, and
/// unlike the matching logic it guards nothing security-critical.
fn is_delta_crl(crl_der: &[u8]) -> bool {
    let Ok(crl) = CertificateList::<x509_cert::certificate::Rfc5280>::from_der(crl_der) else {
        return false;
    };
    crl.tbs_cert_list
        .crl_extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .any(|e| e.extn_id == OID_DELTA_CRL_INDICATOR)
}

/// Build every checker the supplied CRLs can support, pairing deltas with
/// their bases.
///
/// # Why pairing is required
///
/// A delta CRL is only meaningful alongside the base it extends. Handed one on
/// its own, `pkix-revocation` correctly refuses it with `DeltaCrlAsComplete`
/// (RFC 5280 §5.2.4, §6.3.3) — treating it as complete would let an on-path
/// attacker serve a validly signed delta to un-revoke anything listed only in
/// the base.
///
/// This oracle used to construct one `CrlChecker::new` per CRL and never call
/// `with_delta`, so a certificate revoked *only in a delta* was never seen as
/// revoked: the base cleared it and the delta was refused. PKITS 4.15.4 is
/// exactly that shape — serial 3, `KeyCompromise`, listed only in
/// `deltaCRLCA1deltaCRL`. Before `pkix-revocation` gained the standalone-delta
/// check, the delta was accepted as complete and the chain failed for the wrong
/// reason, which is why the committed baseline records a correct verdict.
///
/// # Pairing strategy
///
/// Every (base, delta) combination is offered to `with_delta`, which enforces
/// the real rules itself: the base must not be a delta (§5.2.4), the delta's
/// `IssuingDistributionPoint` must match the base's (§6.3.3(c)), and the CRL
/// numbers must be consistent. A pairing that does not belong fails to
/// construct and is dropped, so offering candidates is safe and keeps the
/// matching rules in the library rather than restated here.
///
/// A base is kept unpaired only when no delta paired with it. Offering both
/// the pairing and the bare base defeats the pairing: a base CRL and its delta
/// are not two opinions to be weighed, the delta supersedes the base, and this
/// loop fails closed on the first checker that reports a revocation. So the
/// bare base always won and `removeFromCRL` could never take effect.
///
/// PKITS 4.15.5 is exactly that shape — serial 4 held by
/// `deltaCRLCA1CRL` and released by `deltaCRLCA1deltaCRL` with
/// `removeFromCRL` (§5.3.1). NIST says validate and OpenSSL agrees;
/// this oracle reported `certificateHold` from the base it should no
/// longer have been consulting. `pkix-revocation` had the rule right the
/// whole time: its own `pkits_4_15_5_valid_delta_remove_from_crl`
/// passes, and 26 of 26 PKITS CRL vectors pass at that layer. The
/// disagreement with NIST was manufactured here.
///
/// Dropping the bare base is safe because a delta does not erase the
/// base's entries, it amends them: anything revoked in the base stays
/// revoked unless the delta carries `removeFromCRL` for it. PKITS
/// 4.15.3 pins that direction — revoked in base, delta present, still
/// revoked.
///
/// Standalone deltas are deliberately not added: they can only ever return
/// `DeltaCrlAsComplete`, which carries no determination.
///
/// # Signer discovery
///
/// For each base this also offers a checker built by signer discovery, which
/// finds which `bundle` certificate actually signed the CRL. That is the
/// key-rollover and separate-CRL-signing-key case: one CA holding several
/// certificates, signing its CRL with one while having issued this certificate
/// from another, so the signature-chain issuer is the wrong signer to hand
/// over.
///
/// It is safe only because the caller has already restricted `crls` to the
/// ones this certificate points at. Discovery answers "who signed this CRL",
/// not "is this the right CRL" — offered the whole CRL set it will happily
/// authenticate a CRL the certificate never pointed at, which is how an
/// earlier attempt broke Invalid Wrong CRL and friends.
/// `new_with_signer_discovery` is self-validating beyond that: it enforces
/// cRLSign per §6.3.3(f) and requires the discovered signer to chain to a
/// self-signed certificate.
fn build_checkers(
    crls: &[Vec<u8>],
    bundle: &[Certificate],
    now_unix: u64,
) -> Vec<CrlChecker<DefaultVerifier>> {
    let (deltas, bases): (Vec<&Vec<u8>>, Vec<&Vec<u8>>) =
        crls.iter().partition(|c| is_delta_crl(c));

    let mut checkers = Vec::new();
    for base in &bases {
        let mut superseded = false;
        for delta in &deltas {
            if let Ok(c) = CrlChecker::with_delta(base, delta, now_unix, DefaultVerifier) {
                checkers.push(c);
                superseded = true;
            }
        }
        // A superseded base is not consulted alone by any route. A
        // pairing that does not belong fails to construct, so the
        // certificate revoked in a base with no applicable delta is
        // still covered here.
        if superseded {
            continue;
        }
        if let Ok(c) = CrlChecker::new((*base).clone(), now_unix, DefaultVerifier) {
            checkers.push(c);
        }
        // Signer discovery is built here, under the same supersession
        // guard, rather than alongside the call. Keeping it outside is
        // what made the first fix insufficient: the guard was added to
        // this function while a second site went on adding a bare
        // checker for every non-delta CRL, so the superseded base was
        // still consulted and still won.
        if let Ok(c) = CrlChecker::new_with_signer_discovery(
            (*base).clone(),
            bundle,
            now_unix,
            DefaultVerifier,
        ) {
            checkers.push(c);
        }
    }
    checkers
}

fn check_revocation(
    chain: &[Certificate],
    anchor: &TrustAnchor,
    bundle: &[Certificate],
    crls: &[Vec<u8>],
    now_unix: u64,
) -> Option<String> {
    for (i, cert) in chain.iter().enumerate() {
        let issuer_cert: Option<&Certificate> = chain.get(i + 1);

        // RFC 5280 §6.3.3(b): consider only CRLs this certificate points at.
        // Checkers are built per certificate because applicability is a
        // property of the (certificate, CRL) pair, not of the CRL alone.
        //
        // Without this the oracle asked whether ANY CRL it held produced a
        // verdict, which is not the RFC's procedure and cannot distinguish a
        // chain with no applicable CRL from one whose CRL merely happens to be
        // validly signed by somebody present. Several PKITS negative vectors
        // are built on exactly that difference.
        let applicable: Vec<Vec<u8>> = crls
            .iter()
            .filter(|c| crl_applies_to(cert, c).is_ok())
            .cloned()
            .collect();
        let checkers = build_checkers(&applicable, bundle, now_unix);

        // Did any CRL actually reach a verdict about this certificate?
        let mut cleared_by_some_crl = false;
        for checker in &checkers {
            let result = if let Some(issuer) = issuer_cert {
                checker.check_revocation(cert, issuer)
            } else {
                // Last cert in validation_chain is issued by the anchor.
                checker.check_revocation_against_anchor(cert, anchor)
            };
            match result {
                // This CRL applied and did not list the cert. Record that the
                // status is known, but keep going: a later CRL may still
                // revoke it, and stopping here would make the verdict depend
                // on CRL order.
                Ok(()) => cleared_by_some_crl = true,

                Err(e @ RevError::Revoked { .. }) => {
                    return Some(format!(
                        "pkix-path revocation: cert at chain index {i} revoked by CRL: {e}"
                    ));
                }

                // This CRL carries no determination about this certificate.
                // Try the next one; if none applies, the loop below fails.
                Err(_) => {}
            }
        }

        // Before failing as undetermined, try combining reason-partitioned
        // CRLs. A CRL carrying onlySomeReasons cannot clear a certificate by
        // itself, so the per-checker loop above reports nothing for a CA that
        // splits its CRL by reason — PKITS 4.14.18 and 4.14.19 are exactly
        // that shape. check_revocation_with_crls unions the reasons covered
        // and clears the certificate only when every reason is accounted for.
        if !cleared_by_some_crl {
            let refs: Vec<&[u8]> = applicable.iter().map(Vec::as_slice).collect();
            let combined = match issuer_cert {
                Some(iss) => {
                    check_revocation_with_crls(cert, iss, &refs, now_unix, &DefaultVerifier)
                }
                // The anchor-issued case has no issuer Certificate to pass;
                // the per-checker loop already covered it.
                None => Err(RevError::CrlIssuerMismatch),
            };
            match combined {
                Ok(()) => cleared_by_some_crl = true,
                Err(e @ RevError::Revoked { .. }) => {
                    return Some(format!(
                        "pkix-path revocation: cert at chain index {i} revoked by CRL: {e}"
                    ));
                }
                Err(_) => {}
            }
        }

        if !cleared_by_some_crl {
            // No supplied CRL could be applied to this certificate, so its
            // revocation status is unknown. Reporting "not revoked" here is
            // the fail-open this function used to have.
            return Some(format!(
                "pkix-path revocation: revocation status of cert at chain index {i} \
                 is undetermined — none of the {} checker(s) built from the {} \
                 applicable CRL(s) produced a verdict",
                checkers.len(),
                applicable.len()
            ));
        }
    }
    None
}
