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

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use der::Decode;
use pkix_path::{validate_path, DefaultVerifier, TrustAnchor, ValidationPolicy};
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

    Ok(
        match validate_path(&validation_chain, &anchors, &policy, &DefaultVerifier) {
            Ok(_) => Verdict::Pass,
            Err(e) => Verdict::Fail {
                reason: format!("{e}"),
            },
        },
    )
}
