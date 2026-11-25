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
use pkix_revocation::{CrlChecker, Error as RevError, RevocationChecker as _};
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
    let policy = ValidationPolicy::new(now);

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
        if let Some(rev_reason) = check_revocation(&validation_chain, &anchors[0], &chain.crls, now)
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
/// Each base is also kept unpaired, because a certificate revoked in the base
/// must still be caught when no delta applies.
///
/// Standalone deltas are deliberately not added: they can only ever return
/// `DeltaCrlAsComplete`, which carries no determination.
fn build_checkers(crls: &[Vec<u8>], now_unix: u64) -> Vec<CrlChecker<DefaultVerifier>> {
    let (deltas, bases): (Vec<&Vec<u8>>, Vec<&Vec<u8>>) =
        crls.iter().partition(|c| is_delta_crl(c));

    let mut checkers = Vec::new();
    for base in &bases {
        if let Ok(c) = CrlChecker::new((*base).clone(), now_unix, DefaultVerifier) {
            checkers.push(c);
        }
        for delta in &deltas {
            if let Ok(c) = CrlChecker::with_delta(base, delta, now_unix, DefaultVerifier) {
                checkers.push(c);
            }
        }
    }
    checkers
}

fn check_revocation(
    chain: &[Certificate],
    anchor: &TrustAnchor,
    crls: &[Vec<u8>],
    now_unix: u64,
) -> Option<String> {
    // Built once for the whole chain, with deltas paired to their bases.
    let checkers = build_checkers(crls, now_unix);

    for (i, cert) in chain.iter().enumerate() {
        let issuer_cert: Option<&Certificate> = chain.get(i + 1);
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

        if !cleared_by_some_crl {
            // No supplied CRL could be applied to this certificate, so its
            // revocation status is unknown. Reporting "not revoked" here is
            // the fail-open this function used to have.
            return Some(format!(
                "pkix-path revocation: revocation status of cert at chain index {i} \
                 is undetermined — none of the {} checker(s) built from {} supplied \
                 CRL(s) applied to it",
                checkers.len(),
                crls.len()
            ));
        }
    }
    None
}
