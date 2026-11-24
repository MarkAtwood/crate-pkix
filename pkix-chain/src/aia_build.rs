//! The I/O-free core of AIA-augmented chain reassembly.
//!
//! [`Verifier::build_with_aia`](crate::Verifier) is a loop around one network
//! call. Everything else it does — pooling certificates, deduplicating URIs,
//! counting fetches against the caps, checking the deadline, finding which
//! certificates still lack an issuer, parsing responses, filtering to CA
//! certificates — is pure bookkeeping.
//!
//! That bookkeeping lives here, once, driven by a caller that supplies the
//! fetches. A synchronous caller calls `batch_fetch`; an asynchronous one
//! awaits it. Neither owns a copy of the policy.
//!
//! # Why this is not a duplicated orchestration layer
//!
//! The obvious way to add an async verify path is a parallel `AsyncVerifier`
//! with async copies of `verify_one`, `build_with_aia`, `try_build` and
//! `run_revocation_checks` — the shape `pkix-revocation-http` used for its own
//! async family. The problem specific to this crate is that
//! `build_with_aia` is where the AIA bounds from `PKIX-zkjb.7` live: the
//! per-certificate URI cap, the total fetch cap and the deadline. Two copies
//! of a *bound* drifting is a security regression, not a maintenance
//! annoyance — one path would silently accept more fetches than the other.
//!
//! Extracting the bounds instead of copying them makes that drift
//! structurally impossible. What remains duplicated between the sync and
//! async paths is the loop that calls the fetcher, which holds no policy.

use std::collections::HashSet;
use std::time::Instant;

use pkix_aia::AiaError;
use pkix_path::{SignatureVerifier, TrustAnchor, ValidationPolicy};
use pkix_path_builder::CertPool;
use x509_cert::Certificate;

use crate::{aia_extract, aia_response, orphans_on_paths, AiaConfig, Error};

/// What the reassembly loop should do next.
#[derive(Debug)]
pub(crate) enum AiaStep {
    /// A complete chain was built; stop.
    Built(Vec<Certificate>),
    /// Fetch these URIs, then call [`AiaBuilder::absorb`] with the results.
    Fetch(Vec<String>),
    /// Reassembly cannot continue.
    Failed(Error),
}

/// Mutable progress of one reassembly.
pub(crate) struct AiaBuildState {
    pool: CertPool,
    /// Every URI visited, so each is fetched at most once across the whole
    /// reassembly rather than once per iteration.
    tried_uris: HashSet<String>,
    /// Remaining budget against [`AiaConfig::max_total_fetches`].
    fetches_left: usize,
    /// The most recent AIA failure, surfaced if reassembly ultimately fails.
    /// A fetch that failed is more informative to report than "no path
    /// found", which is what the path builder would otherwise say.
    last_aia_error: Option<AiaError>,
    started: Instant,
    iteration: usize,
}

impl AiaBuildState {
    /// Seeds the state with the caller-supplied chain.
    pub(crate) fn new(supplied_chain: &[Certificate], config: &AiaConfig) -> Self {
        Self {
            pool: supplied_chain.iter().cloned().collect(),
            tried_uris: HashSet::new(),
            fetches_left: config.max_total_fetches,
            last_aia_error: None,
            started: Instant::now(),
            iteration: 0,
        }
    }
}

/// The I/O-free half of reassembly.
///
/// Borrows what the bookkeeping needs and nothing else: notably not the
/// fetcher and not the revocation checker, which is what lets one copy serve
/// both the sync and async paths.
pub(crate) struct AiaBuilder<'a, V: SignatureVerifier> {
    pub(crate) anchors: &'a [TrustAnchor],
    pub(crate) sig_verifier: &'a V,
    pub(crate) policy: &'a ValidationPolicy,
    pub(crate) config: &'a AiaConfig,
}

impl<V: SignatureVerifier> AiaBuilder<'_, V> {
    /// Advances the reassembly to its next decision point.
    ///
    /// Returns [`AiaStep::Fetch`] when the caller must perform I/O; the caller
    /// then hands the results to [`absorb`](Self::absorb) and calls this
    /// again.
    pub(crate) fn next_step(&self, state: &mut AiaBuildState, leaf: &Certificate) -> AiaStep {
        // Past the depth cap: give the path builder one last attempt with the
        // fully-augmented pool before declaring depth exceeded. The final
        // iteration fetched certificates that the loop would otherwise never
        // try.
        if state.iteration >= self.config.max_depth {
            return match self.try_build(leaf, &state.pool) {
                Ok(Some(built)) => AiaStep::Built(built),
                Ok(None) | Err(_) => AiaStep::Failed(Error::AiaDepthExceeded),
            };
        }

        match self.try_build(leaf, &state.pool) {
            Ok(Some(built)) => return AiaStep::Built(built),
            Ok(None) => {}
            Err(e) => return AiaStep::Failed(e),
        }

        // Collect caIssuers URIs from certificates on candidate paths whose
        // issuer is still missing.
        let mut new_uris: Vec<String> = Vec::new();
        let mut over_limit = false;
        for cert in orphans_on_paths(leaf, &state.pool, self.anchors, self.sig_verifier) {
            for uri in aia_extract::ca_issuers_http_uris(cert).take(self.config.max_uris_per_cert) {
                if state.tried_uris.contains(&uri) {
                    continue;
                }
                if new_uris.len() == state.fetches_left {
                    over_limit = true;
                    break;
                }
                state.tried_uris.insert(uri.clone());
                new_uris.push(uri);
            }
        }

        if new_uris.is_empty() {
            if over_limit {
                return AiaStep::Failed(Error::AiaFetchLimitExceeded {
                    limit: self.config.max_total_fetches,
                });
            }
            // The path builder found nothing and there are no URIs left to
            // try. A previous fetch failure is the more informative signal;
            // otherwise the honest answer is that no path can be completed.
            return AiaStep::Failed(state.last_aia_error.clone().map_or(
                Error::PathBuild(pkix_path_builder::Error::NoPathFound),
                Error::Aia,
            ));
        }

        if self
            .config
            .deadline
            .is_some_and(|d| state.started.elapsed() >= d)
        {
            return AiaStep::Failed(Error::AiaDeadlineExceeded);
        }

        state.fetches_left -= new_uris.len();
        state.iteration += 1;
        AiaStep::Fetch(new_uris)
    }

    /// Folds fetch results into the pool.
    ///
    /// `results` is what the fetcher returned for the URIs
    /// [`next_step`](Self::next_step) handed over; `requested` is how many
    /// there were, so a fetcher that returns extra entries cannot inflate the
    /// work done.
    ///
    /// Returns `Some(error)` when the reassembly must stop: nothing usable
    /// arrived, so another iteration would repeat itself.
    pub(crate) fn absorb(
        &self,
        state: &mut AiaBuildState,
        results: Vec<Result<Vec<u8>, AiaError>>,
        requested: usize,
    ) -> Option<Error> {
        let mut added_any = false;
        for result in results.into_iter().take(requested) {
            let parsed = result.and_then(|bytes| {
                aia_response::parse_ca_issuers_response(&bytes, self.config.max_certs_per_response)
            });
            match parsed {
                Ok(certs) => {
                    for cert in certs {
                        // Only CA certificates can be issuers, and one
                        // already pooled adds nothing but search work.
                        let is_ca = pkix_path::cert_is_ca(&cert).unwrap_or(false);
                        if is_ca && !state.pool.iter().any(|c| *c == cert) {
                            state.pool.add(cert);
                            added_any = true;
                        }
                    }
                }
                Err(e) => state.last_aia_error = Some(e),
            }
        }

        if added_any {
            None
        } else {
            Some(Error::Aia(
                state
                    .last_aia_error
                    .clone()
                    .unwrap_or(AiaError::FetchingDisabled),
            ))
        }
    }

    /// Asks the path builder for a complete chain from the current pool.
    fn try_build(
        &self,
        leaf: &Certificate,
        pool: &CertPool,
    ) -> crate::Result<Option<Vec<Certificate>>> {
        match pkix_path_builder::build_first_valid_path(
            leaf,
            pool,
            self.anchors,
            self.policy,
            self.sig_verifier,
        ) {
            Ok(built) => Ok(Some(built)),
            Err(pkix_path_builder::Error::NoPathFound) => Ok(None),
            Err(pkix_path_builder::Error::NoValidPath { .. }) => Ok(Some(
                pkix_path_builder::build_path(leaf, pool, self.anchors)?,
            )),
            Err(e) => Err(Error::PathBuild(e)),
        }
    }
}
