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
use pkix_path::ValidatedPath;

/// What the path builder could make of the certificate pool as it stands.
///
/// Crate-private: the three cases exist to decide whether another AIA
/// fetch could help, which is the reassembly loop's business and not a
/// caller's.
enum PoolVerdict {
    /// A chain that validates against the anchors and policy.
    Validated(Vec<Certificate>),
    /// Topologically complete candidates exist and none validates. The
    /// pool holds a certificate whose subject DN matches the issuer a
    /// child names but whose key did not sign it, so a fetch may still
    /// supply the one that did.
    OnlyUnvalidated,
    /// No candidate chain at all — an issuer is missing outright.
    Nothing,
}

/// What the reassembly loop should do next.
#[derive(Debug)]
pub enum BuildStep {
    /// A complete chain was built; stop.
    Built(Vec<Certificate>),
    /// Fetch these URIs, then call [`ChainBuilder::absorb`] with the results.
    Fetch(Vec<String>),
    /// Reassembly cannot continue.
    Failed(Error),
}

/// Mutable progress of one reassembly.
pub struct ChainBuildState {
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

impl ChainBuildState {
    /// Seeds the state with the caller-supplied chain.
    pub fn new(supplied_chain: &[Certificate], config: &AiaConfig) -> Self {
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
pub struct ChainBuilder<'a, V: SignatureVerifier> {
    /// Trust anchors the reassembled chain must reach.
    pub anchors: &'a [TrustAnchor],
    /// Signature verification backend, used while building to reject links
    /// that do not actually verify.
    pub sig_verifier: &'a V,
    /// Validation policy the path builder applies to candidate paths.
    pub policy: &'a ValidationPolicy,
    /// The bounds on fetching: per-certificate URI cap, total fetch cap,
    /// per-response certificate cap, depth and deadline.
    pub config: &'a AiaConfig,
}

impl<V: SignatureVerifier> ChainBuilder<'_, V> {
    /// Advances the reassembly to its next decision point.
    ///
    /// Returns [`BuildStep::Fetch`] when the caller must perform I/O; the caller
    /// then hands the results to [`absorb`](Self::absorb) and calls this
    /// again.
    pub fn next_step(&self, state: &mut ChainBuildState, leaf: &Certificate) -> BuildStep {
        // Past the depth cap: give the path builder one last attempt with the
        // fully-augmented pool before declaring depth exceeded. The final
        // iteration fetched certificates that the loop would otherwise never
        // try.
        if state.iteration >= self.config.max_depth {
            return match self.try_build(leaf, &state.pool) {
                Ok(PoolVerdict::Validated(built)) => BuildStep::Built(built),
                // At the cap, a pool that only fails validation is still
                // worth assembling: the caller learns what is wrong with
                // the certificates rather than that we ran out of fetches.
                Ok(PoolVerdict::OnlyUnvalidated) => self
                    .assemble_unvalidated(leaf, &state.pool)
                    .map_or(BuildStep::Failed(Error::AiaDepthExceeded), BuildStep::Built),
                Ok(PoolVerdict::Nothing) | Err(_) => BuildStep::Failed(Error::AiaDepthExceeded),
            };
        }

        // `OnlyUnvalidated` falls through to the fetch below rather than
        // ending the loop. The pool holds something whose subject DN
        // matches the issuer the child names, and whose key did not sign
        // it: a stale intermediate from the wrong CA generation, say, or
        // one half of a cross-signed pair. An AIA fetch can supply the
        // certificate that does sign it, which is exactly the recovery
        // `is_aia_recoverable` admits `SignatureInvalid` for. Returning
        // here instead meant that recovery never ran.
        let verdict = match self.try_build(leaf, &state.pool) {
            Ok(PoolVerdict::Validated(built)) => return BuildStep::Built(built),
            Ok(unresolved) => unresolved,
            Err(e) => return BuildStep::Failed(e),
        };

        // Collect caIssuers URIs from certificates on candidate paths whose
        // issuer is still missing.
        let mut new_uris: Vec<String> = Vec::new();
        let mut over_limit = false;
        // A caIssuers URI this crate declined for its scheme, kept so the
        // failure can name it instead of reporting a bare "no path found".
        let mut excluded_uri: Option<String> = None;
        for cert in orphans_on_paths(leaf, &state.pool, self.anchors, self.sig_verifier) {
            if excluded_uri.is_none() {
                excluded_uri = aia_extract::ca_issuers_unsupported_uris(cert).next();
            }
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
                return BuildStep::Failed(Error::AiaFetchLimitExceeded {
                    limit: self.config.max_total_fetches,
                });
            }
            // Nothing left to fetch. If the pool does hold a complete
            // candidate and it merely fails to validate, hand it over so
            // the caller sees the real defect instead of "no path found".
            if matches!(verdict, PoolVerdict::OnlyUnvalidated) {
                return match self.assemble_unvalidated(leaf, &state.pool) {
                    Ok(built) => BuildStep::Built(built),
                    Err(e) => BuildStep::Failed(e),
                };
            }
            // The path builder found nothing and there are no URIs left to
            // try. A previous fetch failure is the more informative signal;
            // otherwise the honest answer is that no path can be completed.
            // Prefer a real failure over the diagnostic: a fetch that was
            // attempted and failed says more than a URI that was never
            // tried. Only when nothing was attempted does an excluded URI
            // become the most informative thing known — and it beats
            // `NoPathFound`, which would leave a caller whose fetcher
            // handles the scheme with no indication that a URI existed at
            // all, let alone that this crate dropped it.
            if state.last_aia_error.is_none() {
                if let Some(uri) = excluded_uri {
                    return BuildStep::Failed(Error::Aia(AiaError::UriUnsupported(uri)));
                }
            }
            return BuildStep::Failed(state.last_aia_error.clone().map_or(
                Error::PathBuild(pkix_path_builder::Error::NoPathFound),
                Error::Aia,
            ));
        }

        if self
            .config
            .deadline
            .is_some_and(|d| state.started.elapsed() >= d)
        {
            return BuildStep::Failed(Error::AiaDeadlineExceeded);
        }

        state.fetches_left -= new_uris.len();
        state.iteration += 1;
        BuildStep::Fetch(new_uris)
    }

    /// Folds fetch results into the pool.
    ///
    /// `results` is what the fetcher returned for the URIs
    /// [`next_step`](Self::next_step) handed over; `requested` is how many
    /// there were.
    ///
    /// Returns `Some(error)` when the reassembly must stop: nothing usable
    /// arrived, so another iteration would repeat itself.
    ///
    /// # If the fetcher returns the wrong number of results
    ///
    /// [`AiaFetcher::batch_fetch`](pkix_aia::AiaFetcher::batch_fetch)
    /// promises one result per URI, index-aligned, but it is an overridable
    /// trait method and nothing can make a consumer's implementation keep
    /// that promise.
    ///
    /// Either direction is a bug worth knowing about, so any mismatch trips
    /// a `debug_assert`. Too few results is the lossy case: the unanswered
    /// URIs are already in the tried set, so they are never requested again
    /// and the chain can fail to build where a correct fetcher would have
    /// completed it. Too many matters because the promise is *index*
    /// alignment — a fetcher returning the wrong count has lost track of
    /// which result belongs to which URI, and the entries that are absorbed
    /// may be answers to URIs other than the ones they are taken for.
    ///
    /// Release builds continue regardless: extra entries are ignored, so an
    /// implementation cannot inflate the work this does, and missing ones
    /// count as URIs that produced nothing, with the reassembly stopping on
    /// an error rather than looping if nothing usable arrived.
    ///
    /// It is deliberately not a hard assertion. The condition is a bug in
    /// the consumer's own fetcher, and turning it into a panic would take
    /// down path validation in production for a fault that degrades
    /// gracefully; a reachable panic inside certificate verification is a
    /// denial-of-service vector in its own right.
    pub fn absorb(
        &self,
        state: &mut ChainBuildState,
        results: Vec<Result<Vec<u8>, AiaError>>,
        requested: usize,
    ) -> Option<Error> {
        debug_assert_eq!(
            results.len(),
            requested,
            "AiaFetcher::batch_fetch must return exactly one result per URI, \
             index-aligned; returning {} for {requested} URIs drops or \
             invents results",
            results.len(),
        );
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

    /// Asks the path builder what it can make of the current pool.
    fn try_build(&self, leaf: &Certificate, pool: &CertPool) -> crate::Result<PoolVerdict> {
        match pkix_path_builder::build_first_valid_path(
            leaf,
            pool,
            self.anchors,
            self.policy,
            self.sig_verifier,
        ) {
            Ok(built) => Ok(PoolVerdict::Validated(built)),
            Err(pkix_path_builder::Error::NoPathFound) => Ok(PoolVerdict::Nothing),
            Err(pkix_path_builder::Error::NoValidPath { .. }) => Ok(PoolVerdict::OnlyUnvalidated),
            Err(e) => Err(Error::PathBuild(e)),
        }
    }

    /// Assembles the best topology-only chain from `pool`.
    ///
    /// Used when the pool cannot produce a validating chain and there is
    /// nothing left to fetch. Handing the caller a chain it will reject
    /// gets the concrete `validate_path` failure in front of them — "bad
    /// signature at index 0" — instead of a bare "no path found", which
    /// says nothing about what is wrong with the certificates they
    /// supplied.
    fn assemble_unvalidated(
        &self,
        leaf: &Certificate,
        pool: &CertPool,
    ) -> crate::Result<Vec<Certificate>> {
        pkix_path_builder::build_path(leaf, pool, self.anchors).map_err(Error::PathBuild)
    }
}

// ---------------------------------------------------------------------------
// Revocation, without owning the I/O either
// ---------------------------------------------------------------------------

/// One revocation check a caller must perform.
///
/// Produced by [`revocation_targets`]. The two variants exist because the
/// certificate at the top of a validated chain was issued by the trust anchor
/// rather than by another certificate in the chain, and
/// [`RevocationChecker`](pkix_revocation::RevocationChecker) has a separate
/// method for that case.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum RevocationTarget<'a> {
    /// Check `cert` against the certificate that issued it.
    Issuer {
        /// The certificate whose revocation status is in question.
        cert: &'a Certificate,
        /// Its issuer, the next certificate up the validated chain.
        issuer: &'a Certificate,
    },

    /// Check `cert`, which the trust anchor issued directly.
    ///
    /// Corresponds to
    /// [`RevocationChecker::check_revocation_against_anchor`](pkix_revocation::RevocationChecker::check_revocation_against_anchor).
    /// Note the security caveat recorded on that method: its default
    /// implementation returns `Ok(())`, so a checker that does not override it
    /// silently skips this certificate. A caller driving the checks itself
    /// does not inherit that default, and so does not inherit the footgun —
    /// this target is in the list and must be dealt with.
    Anchor {
        /// The certificate whose revocation status is in question.
        cert: &'a Certificate,
        /// The anchor that issued it.
        anchor: &'a TrustAnchor,
    },
}

/// The revocation checks a validated chain calls for.
///
/// Returned in chain order, leaf first. The caller performs them however it
/// likes — sequentially, concurrently, against a cache — and accepts the chain
/// only if every one reports not-revoked.
///
/// # Why this is a list rather than a callback
///
/// The synchronous
/// [`RevocationChecker`](pkix_revocation::RevocationChecker) seam checks one
/// certificate at a time and the orchestration loops over them, so an
/// implementation cannot overlap the fetches even when it has several
/// independent OCSP endpoints to ask. Handing the caller the whole list lets
/// it issue them together, which is the practical reason an async consumer
/// wants this surface and not merely an awaitable version of the old one.
///
/// # Panics
///
/// Panics if `validated.anchor_index` is out of bounds for `anchors`. That
/// index comes from a [`ValidatedPath`] this crate produced against these same
/// anchors, so reaching it means a `ValidatedPath` was paired with a different
/// anchor set than it was validated against — a caller error that cannot be
/// represented in the return type without making every correct call handle an
/// impossible case.
#[must_use]
pub fn revocation_targets<'a>(
    chain: &'a [Certificate],
    anchors: &'a [TrustAnchor],
    validated: &ValidatedPath,
) -> Vec<RevocationTarget<'a>> {
    let anchor = &anchors[validated.anchor_index];
    chain
        .iter()
        .enumerate()
        .map(|(i, cert)| {
            if i + 1 < chain.len() {
                RevocationTarget::Issuer {
                    cert,
                    issuer: &chain[i + 1],
                }
            } else {
                RevocationTarget::Anchor { cert, anchor }
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Convenience driver for callers who are synchronous anyway
// ---------------------------------------------------------------------------

impl<V: SignatureVerifier> ChainBuilder<'_, V> {
    /// Drives reassembly to completion, calling `fetch` for each round.
    ///
    /// The whole loop in one call, for a caller whose I/O is synchronous. An
    /// asynchronous caller writes the loop instead — a closure cannot return a
    /// future that borrows without boxing it, and a boxed future per round is
    /// a worse trade than ten lines at the call site:
    ///
    /// ```ignore
    /// let mut state = ChainBuildState::new(&chain, &config);
    /// let built = loop {
    ///     match builder.next_step(&mut state, leaf) {
    ///         BuildStep::Built(c) => break c,
    ///         BuildStep::Failed(e) => return Err(e),
    ///         BuildStep::Fetch(uris) => {
    ///             let results = my_async_client.get_all(&uris).await;
    ///             if let Some(e) = builder.absorb(&mut state, results, uris.len()) {
    ///                 return Err(e);
    ///             }
    ///         }
    ///     }
    /// };
    /// ```
    ///
    /// # Errors
    ///
    /// Whatever reassembly failed with: [`Error::AiaDepthExceeded`],
    /// [`Error::AiaFetchLimitExceeded`], [`Error::AiaDeadlineExceeded`],
    /// [`Error::Aia`] or [`Error::PathBuild`].
    pub fn build_with<F>(
        &self,
        supplied_chain: &[Certificate],
        mut fetch: F,
    ) -> crate::Result<Vec<Certificate>>
    where
        F: FnMut(&[&str]) -> Vec<Result<Vec<u8>, AiaError>>,
    {
        let leaf = supplied_chain
            .first()
            .ok_or(Error::PathBuild(pkix_path_builder::Error::NoPathFound))?;
        let mut state = ChainBuildState::new(supplied_chain, self.config);

        loop {
            match self.next_step(&mut state, leaf) {
                BuildStep::Built(built) => return Ok(built),
                BuildStep::Failed(e) => return Err(e),
                BuildStep::Fetch(uris) => {
                    let refs: Vec<&str> = uris.iter().map(String::as_str).collect();
                    let results = fetch(&refs);
                    if let Some(e) = self.absorb(&mut state, results, uris.len()) {
                        return Err(e);
                    }
                }
            }
        }
    }
}
