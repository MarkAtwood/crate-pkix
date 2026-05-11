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

    // Use system clock. The harness is run interactively or in CI; chains
    // with notBefore/notAfter outside the wall-clock window are themselves
    // a real divergence class (clock-skew tolerance varies between oracles)
    // and should be visible in the report rather than papered over here.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
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
/// cert. Return `Some(reason)` on the first revoked outcome; `None` when
/// no CRL reports any cert revoked.
///
/// Iteration order is determined first by chain position (leaf first, anchor
/// last) and second by CRL order in `crls`. Within a single cert, the first
/// CRL that reports `Revoked` wins. CRLs that don't apply (issuer mismatch,
/// scope, signature, parse) are ignored — this matches the "soft per-CRL"
/// policy documented at the module level.
fn check_revocation(
    chain: &[Certificate],
    anchor: &TrustAnchor,
    crls: &[Vec<u8>],
    now_unix: u64,
) -> Option<String> {
    for (i, cert) in chain.iter().enumerate() {
        let issuer_cert: Option<&Certificate> = chain.get(i + 1);
        for crl_der in crls {
            // Parse the CRL once per cert/CRL pair. This is wasteful — the
            // CrlChecker re-parses on every construction — but keeps the
            // function pure (no allocator state crossing iterations) and the
            // PKITS corpus is small enough that perf is not a concern. If a
            // larger corpus needs CRL caching, lift this into a Vec<CrlChecker>
            // built once before the per-cert loop.
            let Ok(checker) = CrlChecker::new(crl_der.clone(), now_unix, DefaultVerifier) else {
                continue;
            };
            let result = if let Some(issuer) = issuer_cert {
                checker.check_revocation(cert, issuer)
            } else {
                // Last cert in validation_chain is issued by the anchor.
                checker.check_revocation_against_anchor(cert, anchor)
            };
            // Only the Revoked case flips the verdict. Every other outcome —
            // including Ok (CRL applied, cert not on list) and Err (CRL did
            // not apply: mismatch / scope / parse / signature failure) — is
            // treated as "this CRL has no negative determination, try the
            // next". Importantly we do NOT stop on Ok: a later CRL may still
            // revoke this cert. The diff classifier treats divergence in
            // CRL-coverage policy as its own signal.
            if let Err(e @ RevError::Revoked { .. }) = result {
                return Some(format!(
                    "pkix-path revocation: cert at chain index {i} revoked by CRL: {e}"
                ));
            }
        }
    }
    None
}
