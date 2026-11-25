//! Policy discovery: the `_mta-sts` TXT record (§3.1) and the cache rules
//! that decide when to fetch (§3.3, §5.1).
//!
//! No DNS and no HTTP here either. A caller performs the TXT lookup and the
//! HTTPS GET; this module decides what to look up, whether a fetch is needed,
//! and which policy to apply afterwards.
//!
//! # The cache is the security mechanism, not an optimisation
//!
//! Worth stating plainly, because it inverts the usual reading of a cache.
//! The `_mta-sts` TXT record is **unsigned** and the policy arrives over
//! ordinary HTTPS, so first contact is trust-on-first-use: an attacker
//! present at that moment wins. Everything MTA-STS protects comes from
//! having cached a policy *before* the attacker arrived, for up to a year
//! (§3.2 `max_age`).
//!
//! Two consequences the rules below encode, both easy to get backwards:
//!
//! - A missing or broken TXT record **does not** drop a cached policy. §3.1:
//!   "the absence of a usable TXT record is not by itself sufficient to
//!   remove a sender's previously cached policy". Otherwise suppressing one
//!   DNS answer would strip a year of protection.
//! - A failed fetch **does not** drop one either. §3.3: "if no 'live' policy
//!   can be discovered via DNS or fetched via HTTPS, but a valid
//!   (non-expired) policy exists in the sender's cache, the sender MUST apply
//!   that cached policy."
//!
//! So a discovery layer that fetches correctly but caches sloppily provides
//! approximately nothing while appearing to work.

use alloc::string::String;
use alloc::vec::Vec;

use crate::StsPolicy;

/// Maximum length of a policy id, per §3.1's `1*32(ALPHA / DIGIT)`.
pub const MAX_POLICY_ID_LEN: usize = 32;

/// The DNS label prefixed to a policy domain to find the TXT record (§3.1).
///
/// For `example.com`, query `_mta-sts.example.com`.
pub const TXT_PREFIX: &str = "_mta-sts";

/// The DNS label prefixed to a policy domain to reach the policy host (§3.2).
///
/// For `example.com`, fetch from `mta-sts.example.com`.
pub const POLICY_HOST_PREFIX: &str = "mta-sts";

/// The fixed well-known path the policy is served from (§3.2).
pub const WELL_KNOWN_PATH: &str = "/.well-known/mta-sts.txt";

/// Suggested maximum policy body size, in bytes (§3.3).
///
/// "a suggested maximum policy size is 64 kilobytes". A limit, not a
/// requirement — §3.3 leaves it to the sender — but a caller fetching
/// without one is exposed to resource exhaustion by a hostile policy host.
pub const SUGGESTED_MAX_POLICY_BYTES: usize = 64 * 1024;

/// Suggested HTTPS GET timeout, in seconds (§3.3).
pub const SUGGESTED_FETCH_TIMEOUT_SECS: u64 = 60;

/// Suggested minimum interval between fetch attempts after a failure, in
/// seconds (§3.3).
///
/// "implementers SHOULD limit further attempts to a period of five minutes or
/// longer per version ID, to avoid overwhelming resource-constrained
/// recipients with cascading failures."
pub const SUGGESTED_FETCH_BACKOFF_SECS: u64 = 300;

/// Suggested proactive refresh interval, in seconds (§3.3).
///
/// "MTAs SHOULD proactively refresh cached policies before they expire; a
/// suggested refresh frequency is once per day." §10 explains why: an
/// attacker who can block policy refresh indefinitely eventually outlasts
/// any cached policy, so refreshing early shrinks the window they need to
/// control.
pub const SUGGESTED_REFRESH_INTERVAL_SECS: u64 = 86_400;

/// Why a `_mta-sts` TXT record is not usable.
///
/// §3.1 treats every one of these the same way: "senders MUST assume the
/// recipient domain does not have an available MTA-STS Policy and skip the
/// remaining steps of policy discovery". The distinction is for diagnostics,
/// not for control flow.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TxtError {
    /// No record began with the version tag, so none is an MTA-STS record.
    NoStsRecord,

    /// More than one record began with the version tag.
    ///
    /// §3.1: "If the number of resulting records is not one... senders MUST
    /// assume the recipient domain does not have an available MTA-STS
    /// Policy". Ambiguity is not resolved by picking one.
    MultipleStsRecords(usize),

    /// No `id` field, which §3.1 requires.
    MissingId,

    /// The `id` is empty, longer than [`MAX_POLICY_ID_LEN`], or contains
    /// something other than ASCII letters and digits.
    ///
    /// §3.1: `sts-id = %s"id=" 1*32(ALPHA / DIGIT)`.
    InvalidId(String),

    /// A field is neither the version tag nor `key=value`.
    MalformedField(String),
}

impl core::fmt::Display for TxtError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoStsRecord => f.write_str("no TXT record begins with v=STSv1"),
            Self::MultipleStsRecords(n) => write!(
                f,
                "{n} TXT records begin with v=STSv1, which is ambiguous; §3.1 \
                 requires exactly one"
            ),
            Self::MissingId => f.write_str("TXT record has no id field"),
            Self::InvalidId(id) => write!(
                f,
                "policy id {id:?} is not 1 to {MAX_POLICY_ID_LEN} ASCII \
                 letters and digits"
            ),
            Self::MalformedField(field) => {
                write!(f, "TXT field is not key=value: {field:?}")
            }
        }
    }
}

impl core::error::Error for TxtError {}

/// A parsed `_mta-sts` TXT record (§3.1).
///
/// Carries the policy id, which is the whole point of the record: an opaque
/// token that changes when the policy changes, letting a sender tell a stale
/// cache from a current one without refetching the policy body.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StsTxtRecord {
    id: String,
}

impl StsTxtRecord {
    /// Parse one TXT record's text.
    ///
    /// Use [`select`](Self::select) instead when the resolver returned more
    /// than one record, which is the normal case for a domain that publishes
    /// other TXT records at the same name.
    ///
    /// # Format
    ///
    /// Semicolon-separated `key=value` pairs beginning with the version tag:
    /// `v=STSv1; id=20160831085700Z;`. A trailing semicolon is permitted by
    /// the ABNF and ignored. Unknown fields are extensions and are ignored,
    /// since §3.1's ABNF admits `sts-extension`.
    ///
    /// # Errors
    ///
    /// See [`TxtError`]. §3.1 has a sender treat every one of them as "no
    /// available MTA-STS Policy" — but see [`plan`], because that is not the
    /// same as dropping a cached policy.
    pub fn parse(text: &str) -> Result<Self, TxtError> {
        if !begins_with_version_tag(text) {
            return Err(TxtError::NoStsRecord);
        }

        let mut id: Option<&str> = None;
        for raw in text.split(';') {
            let field = raw.trim();
            if field.is_empty() {
                continue;
            }
            let Some((key, value)) = field.split_once('=') else {
                return Err(TxtError::MalformedField(String::from(field)));
            };
            let key = key.trim();
            let value = value.trim();
            if key.eq_ignore_ascii_case("v") {
                continue; // already checked by begins_with_version_tag
            }
            if key.eq_ignore_ascii_case("id") {
                id = Some(value);
            }
            // Anything else is an extension field. Ignored, per the ABNF.
        }

        let id = id.ok_or(TxtError::MissingId)?;
        if id.is_empty()
            || id.len() > MAX_POLICY_ID_LEN
            || !id.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            return Err(TxtError::InvalidId(String::from(id)));
        }

        Ok(Self {
            id: String::from(id),
        })
    }

    /// Parse one TXT record given as its separate character-strings (§3.1).
    ///
    /// "If the resulting TXT record contains multiple strings, then the
    /// record MUST be treated as if those strings are concatenated without
    /// adding spaces."
    ///
    /// A DNS TXT record is a sequence of length-prefixed character-strings,
    /// each at most 255 bytes, so a record longer than that arrives split —
    /// and an MTA-STS record with a long extension field can. Joining with a
    /// space, which is the intuitive thing and what a careless
    /// implementation does, would corrupt the field that straddles the
    /// boundary.
    ///
    /// # Errors
    ///
    /// [`TxtError::NoStsRecord`] if the joined bytes are not UTF-8, since a
    /// non-ASCII record cannot be a conforming one — §3.1 requires US-ASCII
    /// — and §3.1 treats an unusable record as no policy. Otherwise whatever
    /// [`parse`](Self::parse) reports.
    pub fn from_txt_strings(strings: &[&[u8]]) -> Result<Self, TxtError> {
        let mut joined = Vec::with_capacity(strings.iter().map(|s| s.len()).sum());
        for s in strings {
            joined.extend_from_slice(s);
        }
        let text = core::str::from_utf8(&joined).map_err(|_| TxtError::NoStsRecord)?;
        Self::parse(text)
    }

    /// Whether these character-strings, joined, look like an MTA-STS record.
    ///
    /// The §3.1 discard test, for a caller filtering a resolver's answer
    /// before deciding how many records it has.
    #[must_use]
    pub fn is_sts_txt_strings(strings: &[&[u8]]) -> bool {
        let mut joined = Vec::with_capacity(strings.iter().map(|s| s.len()).sum());
        for s in strings {
            joined.extend_from_slice(s);
        }
        core::str::from_utf8(&joined).is_ok_and(begins_with_version_tag)
    }

    /// Select the single MTA-STS record from a resolver's answer (§3.1).
    ///
    /// "If multiple TXT records for `_mta-sts` are returned by the resolver,
    /// records that do not begin with `v=STSv1;` are discarded. If the number
    /// of resulting records is not one... senders MUST assume the recipient
    /// domain does not have an available MTA-STS Policy."
    ///
    /// So a domain may publish other TXT records at `_mta-sts` without
    /// breaking MTA-STS, but publishing two MTA-STS records breaks it. This
    /// does not pick one: ambiguity about which policy is current is exactly
    /// what the id exists to prevent.
    ///
    /// # Errors
    ///
    /// [`TxtError::NoStsRecord`] or [`TxtError::MultipleStsRecords`] when the
    /// count after discarding is not one, else whatever [`parse`](Self::parse)
    /// reports for the single surviving record.
    pub fn select<'a, I>(records: I) -> Result<Self, TxtError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let candidates: Vec<&str> = records
            .into_iter()
            .filter(|r| begins_with_version_tag(r))
            .collect();
        match candidates.as_slice() {
            [] => Err(TxtError::NoStsRecord),
            [one] => Self::parse(one),
            many => Err(TxtError::MultipleStsRecords(many.len())),
        }
    }

    /// The policy id.
    ///
    /// An opaque token. §3.1: "There is no implied ordering of `id` fields
    /// between revisions", so compare for equality and never for order — a
    /// sender that treated a lexically smaller id as older would be wrong on
    /// a domain that uses random ids.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// Whether `record` begins with the version tag, per §3.1's discard rule.
///
/// Matched case-insensitively although §3.1's ABNF writes `%s"v=STSv1"`,
/// which is case-sensitive. Same reasoning as the policy parser, and the
/// realistic failure decides it: a single miscased record would otherwise be
/// discarded, leaving zero records and no protection at all, where accepting
/// it protects the mail. The contrived case it costs — one correct record
/// alongside one miscased one, which becomes ambiguous rather than usable —
/// is far less likely than one domain miscasing its only record.
fn begins_with_version_tag(record: &str) -> bool {
    let rest = record.trim_start();
    let Some(rest) = rest
        .get(..6)
        .filter(|p| p.eq_ignore_ascii_case("v=STSv"))
        .map(|_| &rest[6..])
    else {
        return false;
    };
    // `v=STSv1` must be followed by the field delimiter or end of record.
    let mut chars = rest.chars();
    if chars.next() != Some('1') {
        return false;
    }
    matches!(chars.as_str().trim_start().chars().next(), None | Some(';'))
}

/// A policy held in a sender's cache, with what is needed to judge it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CachedPolicy {
    policy: StsPolicy,
    id: String,
    fetched_at_unix: u64,
}

impl CachedPolicy {
    /// Record a freshly fetched policy.
    ///
    /// `fetched_at_unix` is when the body was retrieved, because §3.2 runs
    /// `max_age` "from the last policy fetch time" — not from when the policy
    /// was authored, and not from when it was written to storage.
    #[must_use]
    pub const fn new(policy: StsPolicy, id: String, fetched_at_unix: u64) -> Self {
        Self {
            policy,
            id,
            fetched_at_unix,
        }
    }

    /// The cached policy.
    #[must_use]
    pub const fn policy(&self) -> &StsPolicy {
        &self.policy
    }

    /// The id of the TXT record this policy was fetched for.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// When the policy body was fetched.
    #[must_use]
    pub const fn fetched_at_unix(&self) -> u64 {
        self.fetched_at_unix
    }

    /// Whether the policy is still within its `max_age` at `now_unix`.
    #[must_use]
    pub const fn is_live_at(&self, now_unix: u64) -> bool {
        self.policy.is_live_at(self.fetched_at_unix, now_unix)
    }

    /// Whether the policy is old enough to refresh proactively (§3.3).
    ///
    /// True once `interval_secs` has elapsed since the fetch, whether or not
    /// the policy has expired. §3.3 suggests once per day; §10 gives the
    /// reason, which is that an attacker able to block refresh indefinitely
    /// eventually outlasts any cached policy, so refreshing early shrinks the
    /// window they must control.
    ///
    /// Separate from [`is_live_at`](Self::is_live_at) because they answer
    /// different questions: whether to *apply* the policy, and whether to
    /// *refresh* it. A policy can be both live and due for refresh, which is
    /// the state proactive refresh exists to act on.
    #[must_use]
    pub const fn is_due_for_refresh_at(&self, now_unix: u64, interval_secs: u64) -> bool {
        match now_unix.checked_sub(self.fetched_at_unix) {
            Some(age) => age >= interval_secs,
            // A clock behind the fetch time: refresh rather than trust an
            // unmeasurable age, which is the cheap direction to be wrong.
            None => true,
        }
    }
}

/// What to do next in policy discovery.
///
/// Returned by [`plan`], which applies §3.3's and §5.1's cache rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DiscoveryPlan {
    /// Fetch the policy over HTTPS, then cache it against the TXT id.
    ///
    /// Either there is no cached policy, or the TXT id differs from the
    /// cached one, or the cached policy has expired.
    Fetch,

    /// Fetch, but a usable cached policy exists to fall back on.
    ///
    /// §3.3's proactive refresh: the cached policy is live and should still
    /// be applied if the fetch fails, but it is old enough to refresh. A
    /// caller that cannot fetch asynchronously may apply the cached policy
    /// and skip the fetch without being non-conformant.
    RefreshButUseCachedIfUnavailable,

    /// Apply the cached policy without fetching.
    UseCached,

    /// The domain has no MTA-STS policy a sender can apply.
    NoPolicy,
}

/// Decide what to do, given a cache and a TXT lookup result (§3.3, §5.1).
///
/// `txt` is the outcome of looking up `_mta-sts.<policy-domain>`:
/// `Ok` with the record, or `Err` for every unusable case — absent, malformed,
/// or ambiguous — which §3.1 treats alike.
///
/// `refresh_interval_secs` is when to start refreshing proactively;
/// [`SUGGESTED_REFRESH_INTERVAL_SECS`] is §3.3's suggestion. Pass `u64::MAX`
/// to disable proactive refresh, which is conformant but leaves the §10
/// window as wide as `max_age`.
///
/// # The two rules this exists to get right
///
/// An unusable TXT record does **not** discard a live cached policy (§3.1),
/// and neither does a failed fetch (§3.3). Both would otherwise let an
/// attacker strip a year of protection by suppressing one DNS answer or one
/// HTTPS response — which is the downgrade MTA-STS is deployed to prevent, so
/// an implementation that got this backwards would be worse than none.
///
/// This function therefore returns [`DiscoveryPlan::UseCached`], not
/// [`DiscoveryPlan::NoPolicy`], when the lookup failed but the cache is live.
#[must_use]
pub fn plan(
    cached: Option<&CachedPolicy>,
    txt: Result<&StsTxtRecord, &TxtError>,
    now_unix: u64,
    refresh_interval_secs: u64,
) -> DiscoveryPlan {
    let live_cache = cached.filter(|c| c.is_live_at(now_unix));

    let Ok(record) = txt else {
        // §3.1: "the absence of a usable TXT record is not by itself
        // sufficient to remove a sender's previously cached policy".
        return match live_cache {
            Some(_) => DiscoveryPlan::UseCached,
            None => DiscoveryPlan::NoPolicy,
        };
    };

    let Some(cache) = live_cache else {
        // A usable TXT record and no live cache: fetch. If that fails,
        // §3.3 has the sender continue "as though the domain has not
        // implemented MTA-STS" — see `policy_to_apply`.
        return DiscoveryPlan::Fetch;
    };

    if cache.id() != record.id() {
        // The id changed, so the cached body is stale whatever its age.
        return DiscoveryPlan::Fetch;
    }

    if cache.is_due_for_refresh_at(now_unix, refresh_interval_secs) {
        DiscoveryPlan::RefreshButUseCachedIfUnavailable
    } else {
        DiscoveryPlan::UseCached
    }
}

/// Which policy to apply after a fetch attempt (§3.3).
///
/// `fetched` is the freshly retrieved policy, or `None` if the fetch failed
/// for any reason — a connection error, a non-200 status, a refused redirect,
/// a body that would not parse.
///
/// §3.3 settles both directions:
///
/// > If a valid TXT record is found but no policy can be fetched via HTTPS
/// > (for any reason), and there is no valid (non-expired) previously cached
/// > policy, senders MUST continue with delivery as though the domain has not
/// > implemented MTA-STS.
///
/// > Conversely, if no "live" policy can be discovered via DNS or fetched via
/// > HTTPS, but a valid (non-expired) policy exists in the sender's cache,
/// > the sender MUST apply that cached policy.
///
/// Returns `None` only when there is neither a fetched policy nor a live
/// cached one, which means "proceed as though MTA-STS is not implemented" —
/// not "refuse delivery".
#[must_use]
pub fn policy_to_apply<'a>(
    fetched: Option<&'a StsPolicy>,
    cached: Option<&'a CachedPolicy>,
    now_unix: u64,
) -> Option<&'a StsPolicy> {
    fetched.or_else(|| {
        cached
            .filter(|c| c.is_live_at(now_unix))
            .map(CachedPolicy::policy)
    })
}

/// The DNS name to query for the TXT record (§3.1).
///
/// `_mta-sts.example.com` for `example.com`. §3.1 permits a CNAME here, which
/// a resolver must follow — used for policy delegation (§8.2).
///
/// §3.4: when sending to a subdomain, a sender "MUST NOT attempt to fetch a
/// policy from the parent zone", so the policy domain is passed through
/// unchanged and never shortened.
#[must_use]
pub fn txt_name(policy_domain: &str) -> String {
    let mut s = String::with_capacity(TXT_PREFIX.len() + 1 + policy_domain.len());
    s.push_str(TXT_PREFIX);
    s.push('.');
    s.push_str(policy_domain.trim_end_matches('.'));
    s
}

/// The HTTPS URL the policy is fetched from (§3.2).
///
/// `https://mta-sts.example.com/.well-known/mta-sts.txt` for `example.com`.
///
/// The host is what the certificate must be valid for (§3.3), and it is
/// derived from a caller-supplied domain, so a caller must treat the fetch as
/// reaching an attacker-influenced host. See the crate documentation on SSRF.
#[must_use]
pub fn policy_url(policy_domain: &str) -> String {
    let domain = policy_domain.trim_end_matches('.');
    let mut s = String::with_capacity(
        8 + POLICY_HOST_PREFIX.len() + 1 + domain.len() + WELL_KNOWN_PATH.len(),
    );
    s.push_str("https://");
    s.push_str(POLICY_HOST_PREFIX);
    s.push('.');
    s.push_str(domain);
    s.push_str(WELL_KNOWN_PATH);
    s
}

/// The DNS name the policy host's certificate must be valid for (§3.3).
///
/// `mta-sts.example.com` for `example.com`. §3.3 restricts matching to
/// DNS-IDs and permits a wildcard as the complete left-most label, which is
/// what [`pkix_identity::dns_name_matches_pattern`] implements.
#[must_use]
pub fn policy_host(policy_domain: &str) -> String {
    let domain = policy_domain.trim_end_matches('.');
    let mut s = String::with_capacity(POLICY_HOST_PREFIX.len() + 1 + domain.len());
    s.push_str(POLICY_HOST_PREFIX);
    s.push('.');
    s.push_str(domain);
    s
}
