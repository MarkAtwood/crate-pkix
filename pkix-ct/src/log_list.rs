//! Certificate Transparency log list — `CtLog` / `CtLogList`.
//!
//! A `CtLogList` is the trust anchor set for SCT verification: it
//! maps each log's `log_id` (the SHA-256 of the log's
//! `SubjectPublicKeyInfo` per RFC 6962 §3.2) to the log's verifying
//! key, along with descriptive metadata used to time-bound
//! verification (RFC 6962 §3.5 / §6.2: a log's `usable` window).
//!
//! pkix-ct ships no built-in log list. Consumers populate the list
//! from a source they trust. The Chrome / Google log_list.json schema
//! is parsed by [`CtLogList::from_google_log_list_json`] under the
//! `log-list-json` feature; other sources (Apple, browser-specific
//! lists, a private monitoring list) can be ingested by constructing
//! `CtLog` values and calling [`CtLogList::insert`] directly.
//!
//! # Google's log list carries an acceptable-use policy
//!
//! Chrome's log-list documentation offers the lists for certificate
//! submitters such as certification authorities and for CT monitors and
//! auditors, and says they "may not be used to facilitate CT enforcement in
//! TLS clients other than Chrome without explicit written permission from
//! Chrome's CT team."
//!
//! Quoted so a consumer knows it exists. It is Google's policy statement, not
//! a licence term on this crate, and it binds nothing here: an
//! acceptable-use policy draws its force from a service agreement accepted as
//! a condition of access, and fetching an unauthenticated public URL accepts
//! nothing. This crate supplies the mechanism, states the fact, and leaves
//! the judgement to the operator, who is better placed to make it.
//!
//! The warning inside the policy is worth more than its framing, though, and
//! applies whoever has permission. **A client that pins Google's log list
//! inherits Chrome's inclusion and retirement decisions on Chrome's
//! schedule.** Holding a stale copy means either rejecting good certificates
//! whose log is newer than the list, or believing CT is being enforced while
//! checking against a set that no longer describes the ecosystem. Neither
//! announces itself, which is why
//! [`from_google_log_list_json_verified`](CtLogList::from_google_log_list_json_verified)
//! exists: a list cheap to re-fetch and verify is a list that can be kept
//! current, and pinning a snapshot is the thing to avoid.
//!
//! Nothing here depends on Google's list. A private, vendor-specific or
//! self-operated list goes in through [`CtLogList::insert`] or the schema
//! parser, and no source is privileged over another.
//!
//! # Not every published list is signed
//!
//! Google publishes `log_list.json`, a detached `log_list.sig`, and the
//! signing key, so a fetched list can be authenticated — see
//! [`CtLogList::from_google_log_list_json_verified`].
//!
//! Apple's list, at `https://valid.apple.com/ct/log_list/current_log_list.json`,
//! is **not** signed: there is no detached signature published alongside it
//! and no signature field within it. A consumer ingesting it is trusting
//! HTTPS to Apple and nothing further. That is a materially weaker position
//! than the Google path offers, and worth knowing before treating the two
//! as interchangeable sources.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// When a CT log became usable, as far as the log list records it.
///
/// This replaced an `Option<u64>` that could not distinguish two
/// states needing opposite answers: a log that never became usable, so
/// every SCT it signed must be rejected, and a log whose usable
/// timestamp the list simply does not carry, where imposing a lower
/// bound would reject historical SCTs for want of metadata. `None`
/// meant the first; `Some(0)` was pressed into service for the second,
/// which only worked because no timestamp precedes the Unix epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum UsableFrom {
    /// The log became usable at this timestamp, in milliseconds since
    /// the Unix epoch.
    ///
    /// An SCT older than this is not trustworthy even though the
    /// signature really is the log's.
    At(u64),
    /// The log is usable, or once was, and the list does not say when.
    ///
    /// No lower bound is imposed. Google's v3 schema records only a
    /// log's *current* state, so a readonly or retired log carries no
    /// usable timestamp while having certainly had one.
    Unrecorded,
    /// The log never reached the usable state.
    ///
    /// Every SCT it signed is rejected, whatever the timestamp. A
    /// `qualified` log sits here: accepted into the program, not yet
    /// trusted to vouch for anything.
    Never,
}

/// Metadata for one CT log.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct CtLog {
    /// Log identifier — SHA-256 of `key_der` per RFC 6962 §3.2.
    pub log_id: [u8; 32],
    /// The log's verifying key, encoded as a `SubjectPublicKeyInfo`
    /// DER blob. Typical CT logs use ECDSA P-256 keys; pkix-ct does
    /// not constrain the algorithm at this layer (the signature
    /// verifier — PKIX-baac.3 — does that via the
    /// [`pkix_path::SignatureVerifier`] trait).
    pub key_der: Vec<u8>,
    /// Human-readable description, typically the log's name (e.g.
    /// `"Google 'Argon2026h1' log"`).
    pub description: String,
    /// Submission base URL of the log. RFC 6962 §3 / §4 paths
    /// (`ct/v1/add-chain`, `ct/v1/get-proof-by-hash`, etc.) are
    /// resolved relative to this URL.
    pub url: String,
    /// When the log became usable — see [`UsableFrom`] for the three
    /// states and what each means for the window check.
    pub usable_from: UsableFrom,
    /// Moment after which the log should not be relied on for new
    /// SCTs, in milliseconds since the Unix epoch. `None` means the
    /// log has not been retired. SCTs issued before this point are
    /// still valid; SCTs issued at or after it should be treated as
    /// untrusted.
    pub retired_at_ms: Option<u64>,
}

impl CtLog {
    /// Construct a `CtLog` from its constituent fields.
    ///
    /// No validation is performed here — callers using
    /// [`CtLogList::insert`] get `log_id == SHA-256(key_der)`
    /// consistency checked at insertion time.
    #[must_use]
    pub fn new(
        log_id: [u8; 32],
        key_der: Vec<u8>,
        description: String,
        url: String,
        usable_from: UsableFrom,
        retired_at_ms: Option<u64>,
    ) -> Self {
        Self {
            log_id,
            key_der,
            description,
            url,
            usable_from,
            retired_at_ms,
        }
    }
}

/// A set of trusted CT logs indexed by `log_id`.
#[derive(Clone, Debug, Default)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(into = "alloc::vec::Vec<CtLog>", try_from = "alloc::vec::Vec<CtLog>")
)]
pub struct CtLogList {
    logs: BTreeMap<[u8; 32], CtLog>,
}

impl CtLogList {
    /// Create an empty log list.
    #[must_use]
    pub fn new() -> Self {
        Self {
            logs: BTreeMap::new(),
        }
    }

    /// Insert a log into the list.
    ///
    /// Verifies that `log.log_id == SHA-256(log.key_der)` per RFC 6962
    /// §3.2. A mismatched `log_id` indicates a corrupted log-list
    /// source and is rejected. Inserting a log with a `log_id` already
    /// present overwrites the previous entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParseError`] if the consistency check fails.
    pub fn insert(&mut self, log: CtLog) -> Result<()> {
        let expected: [u8; 32] = Sha256::digest(&log.key_der).into();
        if expected != log.log_id {
            return Err(Error::ParseError);
        }
        self.logs.insert(log.log_id, log);
        Ok(())
    }

    /// Look up a log by its `log_id`.
    #[must_use]
    pub fn get(&self, log_id: &[u8; 32]) -> Option<&CtLog> {
        self.logs.get(log_id)
    }

    /// Number of logs in the list.
    #[must_use]
    pub fn len(&self) -> usize {
        self.logs.len()
    }

    /// Whether the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.logs.is_empty()
    }

    /// Iterate over the logs in `log_id` order.
    pub fn iter(&self) -> impl Iterator<Item = &CtLog> {
        self.logs.values()
    }
}

// --- Google / Chrome log_list.json schema --------------------------------
//
// Behind feature `log-list-json` so the core CtLogList type is free of
// serde and JSON deps for embedded / no-alloc-extra consumers.

#[cfg(feature = "log-list-json")]
#[cfg_attr(docsrs, doc(cfg(feature = "log-list-json")))]
mod google_schema {
    use super::{CtLog, CtLogList, UsableFrom};
    use crate::{Error, Result};
    use alloc::vec::Vec;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use serde::Deserialize;

    /// Top-level shape of <https://www.gstatic.com/ct/log_list/v3/log_list.json>.
    ///
    /// Schema documentation:
    /// <https://www.gstatic.com/ct/log_list/v3/log_list_schema.json>.
    /// Only the fields pkix-ct actually consumes are bound; everything
    /// else is permitted via serde's default behaviour of ignoring
    /// unknown fields.
    #[derive(Deserialize)]
    struct LogListJson {
        operators: Vec<OperatorJson>,
    }

    #[derive(Deserialize)]
    struct OperatorJson {
        logs: Vec<LogJson>,
    }

    #[derive(Deserialize)]
    struct LogJson {
        description: alloc::string::String,
        /// base64 SHA-256 of `key` (32 bytes once decoded).
        log_id: alloc::string::String,
        /// base64 DER-encoded SubjectPublicKeyInfo.
        key: alloc::string::String,
        /// Submission base URL.
        url: alloc::string::String,
        #[serde(default)]
        state: Option<LogStateJson>,
    }

    /// `state` is an object with exactly one of `pending`, `qualified`,
    /// `usable`, `readonly`, `retired`, or `rejected` as its key. We
    /// deserialize all six to determine which state the log is in and
    /// to extract timestamps from the active variant.
    #[derive(Deserialize, Default)]
    struct LogStateJson {
        #[serde(default)]
        pending: Option<StateEntryJson>,
        #[serde(default)]
        #[allow(dead_code)] // deserialized by serde to distinguish from rejected/pending
        qualified: Option<StateEntryJson>,
        #[serde(default)]
        usable: Option<StateEntryJson>,
        #[serde(default)]
        readonly: Option<StateEntryJson>,
        #[serde(default)]
        retired: Option<StateEntryJson>,
        #[serde(default)]
        rejected: Option<StateEntryJson>,
    }

    impl LogStateJson {
        /// Returns `true` if the log is in a state that should be
        /// excluded from the trusted log list (`rejected` or `pending`).
        fn is_excluded(&self) -> bool {
            self.rejected.is_some() || self.pending.is_some()
        }
    }

    #[derive(Deserialize)]
    struct StateEntryJson {
        /// RFC 3339 timestamp the log entered this state, e.g.
        /// `"2024-03-04T19:00:00Z"`.
        timestamp: alloc::string::String,
    }

    impl CtLogList {
        /// Parse the Google / Chrome `log_list.json` schema v3.
        ///
        /// The expected shape is documented at
        /// <https://www.gstatic.com/ct/log_list/v3/log_list_schema.json>.
        /// Unknown top-level fields (such as `version`,
        /// `log_list_timestamp`, `operators[*].email`, etc.) are
        /// ignored. Each log's `log_id` is verified to equal
        /// `SHA-256(key)` before insertion; a mismatch causes the
        /// whole parse to fail.
        ///
        /// # State filtering
        ///
        /// Google's schema assigns each log exactly one state:
        /// `pending`, `qualified`, `usable`, `readonly`, `retired`, or
        /// `rejected`. This method **skips** logs in the `rejected` and
        /// `pending` states — they are not trustworthy for SCT
        /// verification. Logs in all other states are imported:
        ///
        /// * `usable` — actively trusted;
        ///   [`UsableFrom::At`] carries the timestamp.
        /// * `readonly` — no longer accepting submissions but still
        ///   trusted for existing SCTs; the readonly timestamp is
        ///   stored as `retired_at_ms`.
        /// * `retired` — no longer operated but historical SCTs remain
        ///   valid; `retired_at_ms` is set.
        /// * `qualified` — accepted into the program but pre-usable, so
        ///   [`UsableFrom::Never`]: nothing it signed is trusted yet.
        /// * Logs with no `state` field are imported as-is.
        ///
        /// The v3 schema records only the *current* state, so a
        /// readonly or retired log carries no record of when it became
        /// usable, though it necessarily passed through `usable`. Those
        /// import as [`UsableFrom::Unrecorded`], which imposes no lower
        /// bound. The alternative, dropping their historical SCTs
        /// because a timestamp is missing from the metadata, would be
        /// the wrong answer to a question about the log's signature.
        ///
        /// # Errors
        ///
        /// Returns [`Error::ParseError`] on JSON syntax errors,
        /// invalid base64 in `log_id` or `key`, malformed timestamps,
        /// or a `log_id` ⇔ `key` mismatch.
        ///
        /// # This does not check Google's signature
        ///
        /// Google publishes `log_list.sig` alongside the list, and nothing
        /// here looks at it. The bytes are parsed on trust.
        ///
        /// That is the right function for a list you reviewed and committed
        /// yourself, or for one that reached you over a channel you already
        /// trust. For a list that was **fetched** — which is the normal case,
        /// since logs are added and retired continuously and deployments
        /// refetch on the order of weeks — use
        /// [`from_google_log_list_json_verified`](Self::from_google_log_list_json_verified)
        /// instead. A substituted list cannot forge an SCT for a log already
        /// in it, because a `log_id` is SHA-256 over the log's SPKI; what it
        /// can do is add a log the attacker controls, whose SCTs then verify.
        pub fn from_google_log_list_json(json: &str) -> Result<Self> {
            let parsed: LogListJson = serde_json::from_str(json).map_err(|_| Error::ParseError)?;
            let mut out = Self::new();
            for op in parsed.operators {
                for log in op.logs {
                    // Skip logs in excluded states (rejected, pending).
                    if log.state.as_ref().is_some_and(|s| s.is_excluded()) {
                        continue;
                    }

                    let log_id_bytes = BASE64.decode(&log.log_id).map_err(|_| Error::ParseError)?;
                    let log_id: [u8; 32] = log_id_bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::ParseError)?;
                    let key_der = BASE64.decode(&log.key).map_err(|_| Error::ParseError)?;
                    let usable_at = log
                        .state
                        .as_ref()
                        .and_then(|s| s.usable.as_ref())
                        .map(|e| parse_rfc3339_to_unix_ms(&e.timestamp))
                        .transpose()?;
                    // A readonly log has stopped accepting submissions;
                    // treat its timestamp the same as a retirement date.
                    // If both retired and readonly are somehow present,
                    // retired takes precedence.
                    let retired_at_ms = log
                        .state
                        .as_ref()
                        .and_then(|s| s.retired.as_ref().or(s.readonly.as_ref()))
                        .map(|e| parse_rfc3339_to_unix_ms(&e.timestamp))
                        .transpose()?;
                    // A readonly or retired log was usable before it
                    // reached that state, but the schema does not
                    // record when, so say that rather than inventing a
                    // timestamp: `Unrecorded` imposes no lower bound
                    // and SCTs issued before `retired_at_ms` still
                    // verify. This used to be `Some(0)`, which worked
                    // only because nothing predates the Unix epoch.
                    let usable_from = match (usable_at, retired_at_ms) {
                        (Some(ts), _) => UsableFrom::At(ts),
                        (None, Some(_)) => UsableFrom::Unrecorded,
                        // No usable timestamp and not retired: the log
                        // has not been trusted yet. `qualified` is the
                        // state that lands here.
                        (None, None) => UsableFrom::Never,
                    };
                    out.insert(CtLog {
                        log_id,
                        key_der,
                        description: log.description,
                        url: log.url,
                        usable_from,
                        retired_at_ms,
                    })?;
                }
            }
            Ok(out)
        }

        /// Verifies Google's detached signature over `json`, then parses it.
        ///
        /// Google publishes the log list as three artifacts under
        /// `https://www.gstatic.com/ct/log_list/v3/`:
        ///
        /// | File | What it is |
        /// |--|--|
        /// | `log_list.json` | the list, passed here as `json` |
        /// | `log_list.sig` | a detached signature over those exact bytes |
        /// | `log_list_pubkey.pem` | the key that signs it |
        ///
        /// [`from_google_log_list_json`](Self::from_google_log_list_json)
        /// parses the first and ignores the other two. Prefer this function
        /// wherever the list was fetched rather than reviewed by hand.
        ///
        /// # Why this matters more than it looks
        ///
        /// A `log_id` is SHA-256 over the log's SPKI, which
        /// [`CtLogList`] checks. So a substituted list **cannot** forge an
        /// SCT for a log already in it. What a substituted list can do is
        /// **add a log the attacker controls**, after which SCTs from that
        /// log verify — which defeats the point of requiring SCTs at all.
        ///
        /// Unlike a DNSSEC root key, this list is not a long-lived constant:
        /// logs are added, frozen and retired continuously, so a deployment
        /// refetches on the order of weeks. Every one of those fetches is a
        /// chance to be handed a different list, which is why the signature
        /// is worth checking on each one rather than once at review time.
        ///
        /// # The key is yours to supply
        ///
        /// `signing_key_spki` is DER `SubjectPublicKeyInfo` — what
        /// `openssl pkey -pubin -outform DER` emits from the published PEM.
        /// This crate ships no key, for the same reason it ships no log
        /// list and `pkix-path` ships no root certificates: the trust
        /// decision is the caller's. Google's log-list signing key rotates
        /// far more rarely than the list it signs, so pinning it as data on
        /// your side is practical in a way pinning the list is not.
        ///
        /// [`pkix-ct-google`](https://docs.rs/pkix-ct-google) ships Google's
        /// current key as data for callers who would otherwise go and fetch
        /// it, with a generator that cross-checks it against Google's
        /// published list and a scheduled check for rotation.
        ///
        /// Note that Google publishes no out-of-band verification of
        /// the key itself — no fingerprint in a signed artifact, no copy in
        /// an independently distributed source tree. Its authenticity rests
        /// on HTTPS to `gstatic.com`, which is to say on the Web PKI that
        /// Certificate Transparency exists to police. The strongest check
        /// available is that a candidate key verifies Google's currently
        /// published list, which is worth doing when pinning one.
        ///
        /// # The algorithm is fixed, deliberately
        ///
        /// Verification is RSA PKCS#1 v1.5 with SHA-256, which is what
        /// Google signs with, and it is not a parameter. Letting a caller
        /// choose would let anything able to influence that choice downgrade
        /// the check; a change on Google's side is a format change that
        /// should require a visible code change here.
        ///
        /// # Errors
        ///
        /// - [`Error::InvalidSignature`] if the signature does not verify
        ///   over `json`, if `signing_key_spki` does not parse, or if the
        ///   verifier cannot handle an RSA/SHA-256 signature. These are one
        ///   variant on purpose: to a caller they all mean "do not trust
        ///   this list", and distinguishing them would invite treating some
        ///   as recoverable.
        /// - [`Error::ParseError`] if `json` is not UTF-8, or whatever
        ///   [`from_google_log_list_json`](Self::from_google_log_list_json)
        ///   reports once the signature has been accepted.
        ///
        /// Note the order: nothing is parsed until the signature verifies,
        /// so malformed JSON from an unverified source is reported as a
        /// signature failure rather than a parse failure.
        pub fn from_google_log_list_json_verified<V>(
            json: &[u8],
            detached_signature: &[u8],
            signing_key_spki: &[u8],
            verifier: &V,
        ) -> Result<Self>
        where
            V: pkix_path::SignatureVerifier,
        {
            use der::{Decode as _, Encode as _};

            /// `sha256WithRSAEncryption` (RFC 4055 §5).
            const SHA256_WITH_RSA: der::asn1::ObjectIdentifier =
                der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

            let spki = spki::SubjectPublicKeyInfoRef::from_der(signing_key_spki)
                .map_err(|_| Error::InvalidSignature)?;

            // RFC 4055 §5: the parameters field MUST be present and NULL for
            // this OID. Encoding it explicitly rather than passing None keeps
            // the AlgorithmIdentifier the same shape a certificate carries.
            let null = der::asn1::Null
                .to_der()
                .map_err(|_| Error::InvalidSignature)?;
            let algorithm = spki::AlgorithmIdentifierRef {
                oid: SHA256_WITH_RSA,
                parameters: Some(
                    der::asn1::AnyRef::from_der(&null).map_err(|_| Error::InvalidSignature)?,
                ),
            };

            verifier
                .verify_signature(algorithm, spki, json, detached_signature)
                .map_err(|_| Error::InvalidSignature)?;

            let text = core::str::from_utf8(json).map_err(|_| Error::ParseError)?;
            Self::from_google_log_list_json(text)
        }
    }

    /// Convert an RFC 3339 / ISO 8601 timestamp to milliseconds since
    /// the Unix epoch.
    ///
    /// The Google log_list.json schema documents the timestamp as RFC
    /// 3339 (e.g. `"2024-03-04T19:00:00Z"`). The schema enforces it.
    /// We accept ms-precision `.fff` if present (some test fixtures
    /// have non-zero fractional seconds).
    fn parse_rfc3339_to_unix_ms(s: &str) -> Result<u64> {
        // Expected shape: "YYYY-MM-DDTHH:MM:SSZ" or "YYYY-MM-DDTHH:MM:SS.fffZ".
        // No bespoke chrono dep — this is a tightly-constrained format from
        // a known producer, parsed inline.
        let bytes = s.as_bytes();
        if bytes.len() < 20 || bytes[10] != b'T' || !s.ends_with('Z') {
            return Err(Error::ParseError);
        }
        // The separators, not just the digits. Without this,
        // "2024:03:04T19:00:00Z" parsed happily: every digit pair sits
        // where it should, so nothing downstream notices that the date
        // separators are wrong.
        if bytes[4] != b'-' || bytes[7] != b'-' || bytes[13] != b':' || bytes[16] != b':' {
            return Err(Error::ParseError);
        }
        let year: i32 = parse_digits(&bytes[0..4])? as i32;
        let month: u32 = parse_digits(&bytes[5..7])?;
        let day: u32 = parse_digits(&bytes[8..10])?;
        let hour: u32 = parse_digits(&bytes[11..13])?;
        let min: u32 = parse_digits(&bytes[14..16])?;
        let sec: u32 = parse_digits(&bytes[17..19])?;

        // `parse_digits` checks that they are digits, not that they are
        // times. "2024-03-04T99:99:99Z" used to parse: the bogus fields
        // added 99*3600 + 99*60 + 99 seconds, about four days, and came
        // back as a perfectly ordinary timestamp four days after the
        // date it encoded. Silently wrong is worse here than refused,
        // because the value lands in a log's usable window and decides
        // whether an SCT is inside it.
        //
        // `sec == 60` is allowed: RFC 3339 §5.6 permits it for a leap
        // second. It rolls into the following minute, which is what
        // treating UTC as 86400 seconds a day costs and is the same
        // choice every other parser here makes.
        if hour > 23 || min > 59 || sec > 60 {
            return Err(Error::ParseError);
        }

        // Optional fractional seconds — find them between offset 19 and the trailing 'Z'.
        let frac_ms: u32 = if bytes[19] == b'.' {
            let frac_str = &s[20..s.len() - 1]; // strip trailing Z
            if frac_str.is_empty() || frac_str.len() > 6 {
                return Err(Error::ParseError);
            }
            let mut padded = [b'0'; 3];
            for (i, b) in frac_str.bytes().take(3).enumerate() {
                padded[i] = b;
            }
            parse_digits(&padded)?
        } else if bytes[19] != b'Z' {
            return Err(Error::ParseError);
        } else {
            0
        };

        let days = days_from_civil(year, month, day)?;
        let secs = days * 86400 + (hour as i64) * 3600 + (min as i64) * 60 + sec as i64;
        if secs < 0 {
            return Err(Error::ParseError);
        }
        Ok(secs as u64 * 1000 + frac_ms as u64)
    }

    fn parse_digits(bytes: &[u8]) -> Result<u32> {
        let mut out: u32 = 0;
        for &b in bytes {
            if !b.is_ascii_digit() {
                return Err(Error::ParseError);
            }
            out = out
                .checked_mul(10)
                .and_then(|v| v.checked_add((b - b'0') as u32))
                .ok_or(Error::ParseError)?;
        }
        Ok(out)
    }

    /// Howard Hinnant's "days from civil" — translates a (year, month,
    /// day) civil date in the proleptic Gregorian calendar to days since
    /// 1970-01-01. Reference: <https://howardhinnant.github.io/date_algorithms.html#days_from_civil>.
    /// CC0 / public domain.
    fn days_from_civil(year: i32, month: u32, day: u32) -> Result<i64> {
        if !(1..=12).contains(&month) {
            return Err(Error::ParseError);
        }
        // Days in *this* month, not 31 for all of them. The looser check
        // accepted 2024-02-31 and turned it into 2024-03-02, since the
        // day count is computed arithmetically and never consulted a
        // calendar.
        let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        let days_in_month = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if leap => 29,
            2 => 28,
            // Unreachable: month is 1..=12 by the check above.
            _ => return Err(Error::ParseError),
        };
        if !(1..=days_in_month).contains(&day) {
            return Err(Error::ParseError);
        }
        let y = if month <= 2 { year - 1 } else { year };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = (y - era * 400) as u32; // [0, 399]
        let m = month;
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day - 1; // [0, 365]
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
        Ok((era as i64) * 146097 + doe as i64 - 719468)
    }

    #[cfg(test)]
    mod schema_tests {
        use super::*;

        /// Digits in the right places are not a timestamp.
        ///
        /// Oracle: RFC 3339 §5.6 — `time-hour` is 00-23, `time-minute`
        /// 00-59, `time-second` 00-60 with 60 reserved for a leap
        /// second. Cross-checked against Python, which refuses every
        /// one of these:
        /// `datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")`.
        ///
        /// The first case is the one that was reported. It used to
        /// parse: 99 hours, 99 minutes and 99 seconds added about four
        /// days, and the function returned an ordinary-looking
        /// timestamp four days after the date in the string. The value
        /// feeds a log's usable window, which decides whether an SCT
        /// falls inside it, so being quietly four days out is worse
        /// than being refused.
        #[test]
        fn rfc3339_refuses_out_of_range_fields() {
            for s in [
                "2024-03-04T99:99:99Z", // the reported input
                "2024-03-04T24:00:00Z", // hour 24 is tomorrow's 00
                "2024-03-04T19:60:00Z", // minute 60
                "2024-03-04T19:00:61Z", // second 61: 60 is a leap second, 61 is not
                "2024-13-04T19:00:00Z", // month 13
                "2024-00-04T19:00:00Z", // month 0
                "2024-03-00T19:00:00Z", // day 0
                "2024-02-31T19:00:00Z", // February has no 31st
                "2023-02-29T19:00:00Z", // nor a 29th in a common year
                "2024-04-31T19:00:00Z", // April has 30 days
                "2024:03:04T19:00:00Z", // ':' where '-' belongs
                "2024-03-04T19-00-00Z", // '-' where ':' belongs
            ] {
                assert!(
                    parse_rfc3339_to_unix_ms(s).is_err(),
                    "{s} must be refused, not reinterpreted"
                );
            }
        }

        /// And the forms RFC 3339 does allow must still parse, so the
        /// checks above cannot have been made by refusing everything.
        ///
        /// Oracle for the leap second: RFC 3339 §5.6 permits
        /// `time-second` 60. It rolls into the following minute here,
        /// which is what treating every UTC day as 86400 seconds costs.
        #[test]
        fn rfc3339_still_accepts_what_the_grammar_allows() {
            // Boundaries of each field.
            assert!(parse_rfc3339_to_unix_ms("2024-03-04T00:00:00Z").is_ok());
            assert!(parse_rfc3339_to_unix_ms("2024-03-04T23:59:59Z").is_ok());
            // 2024 is a leap year, 2023 is not.
            assert!(parse_rfc3339_to_unix_ms("2024-02-29T19:00:00Z").is_ok());
            assert!(parse_rfc3339_to_unix_ms("2023-02-28T19:00:00Z").is_ok());
            // Month lengths that are not 31.
            assert!(parse_rfc3339_to_unix_ms("2024-04-30T19:00:00Z").is_ok());
            assert!(parse_rfc3339_to_unix_ms("2024-12-31T19:00:00Z").is_ok());

            // A leap second is accepted and lands on the next minute.
            assert_eq!(
                parse_rfc3339_to_unix_ms("2016-12-31T23:59:60Z").unwrap(),
                parse_rfc3339_to_unix_ms("2017-01-01T00:00:00Z").unwrap(),
                "second 60 rolls over; the point is that it is not refused"
            );
        }

        #[test]
        fn rfc3339_parses_with_fractional_seconds() {
            // 2024-03-04 19:00:00 UTC = 1709578800 sec = 1709578800000 ms
            assert_eq!(
                parse_rfc3339_to_unix_ms("2024-03-04T19:00:00Z").unwrap(),
                1_709_578_800_000
            );
            assert_eq!(
                parse_rfc3339_to_unix_ms("2024-03-04T19:00:00.500Z").unwrap(),
                1_709_578_800_500
            );
            // Independent oracle: python3 -c "import datetime; print(int(datetime.datetime(2024,3,4,19,0,0,tzinfo=datetime.timezone.utc).timestamp()*1000))"
        }

        #[test]
        fn rfc3339_rejects_garbage() {
            assert!(parse_rfc3339_to_unix_ms("not-a-date").is_err());
            assert!(parse_rfc3339_to_unix_ms("2024-13-01T00:00:00Z").is_err());
            assert!(parse_rfc3339_to_unix_ms("2024-03-04T19:00:00").is_err()); // no Z
        }

        #[test]
        fn days_from_civil_landmarks() {
            // 1970-01-01 → 0
            assert_eq!(days_from_civil(1970, 1, 1).unwrap(), 0);
            // 2000-01-01 → 10957 (verified independently: 30 years + 7 leap days)
            assert_eq!(days_from_civil(2000, 1, 1).unwrap(), 10957);
            // 2024-03-04 → 19786 (oracle: python datetime)
            assert_eq!(days_from_civil(2024, 3, 4).unwrap(), 19786);
        }

        /// Helper: build a minimal Google log_list.json with one log per
        /// state. Each "key" is a distinct byte string whose SHA-256 we
        /// pre-compute and encode as the `log_id`.
        fn synthetic_log_list_json() -> alloc::string::String {
            use sha2::{Digest, Sha256};

            /// Encode key bytes as a log entry with the given state object.
            fn entry(key: &[u8], desc: &str, state_json: &str) -> alloc::string::String {
                let key_b64 = BASE64.encode(key);
                let id_b64 = BASE64.encode(Sha256::digest(key));
                alloc::format!(
                    r#"{{"description":"{desc}","log_id":"{id_b64}","key":"{key_b64}","url":"https://example.com/{desc}/","state":{state_json}}}"#
                )
            }

            let usable = entry(
                b"key-usable",
                "usable-log",
                r#"{"usable":{"timestamp":"2024-01-01T00:00:00Z"}}"#,
            );
            let readonly = entry(
                b"key-readonly",
                "readonly-log",
                r#"{"readonly":{"timestamp":"2025-06-01T00:00:00Z"}}"#,
            );
            let retired = entry(
                b"key-retired",
                "retired-log",
                r#"{"retired":{"timestamp":"2025-03-01T00:00:00Z"}}"#,
            );
            let qualified = entry(
                b"key-qualified",
                "qualified-log",
                r#"{"qualified":{"timestamp":"2024-06-01T00:00:00Z"}}"#,
            );
            let pending = entry(
                b"key-pending",
                "pending-log",
                r#"{"pending":{"timestamp":"2024-02-01T00:00:00Z"}}"#,
            );
            let rejected = entry(
                b"key-rejected",
                "rejected-log",
                r#"{"rejected":{"timestamp":"2024-05-01T00:00:00Z"}}"#,
            );

            alloc::format!(
                r#"{{"operators":[{{"name":"test","logs":[{usable},{readonly},{retired},{qualified},{pending},{rejected}]}}]}}"#
            )
        }

        #[test]
        fn filters_rejected_and_pending_logs() {
            let json = synthetic_log_list_json();
            let list = CtLogList::from_google_log_list_json(&json).unwrap();
            // 6 logs in the JSON, but rejected + pending are filtered out → 4
            assert_eq!(list.len(), 4);

            // Verify the four expected logs are present by description.
            let descriptions: alloc::vec::Vec<_> =
                list.iter().map(|l| l.description.as_str()).collect();
            assert!(descriptions.contains(&"usable-log"));
            assert!(descriptions.contains(&"readonly-log"));
            assert!(descriptions.contains(&"retired-log"));
            assert!(descriptions.contains(&"qualified-log"));
            // Verify the two excluded logs are absent.
            assert!(!descriptions.contains(&"pending-log"));
            assert!(!descriptions.contains(&"rejected-log"));
        }

        #[test]
        fn readonly_timestamp_stored_as_retired_at_ms() {
            let json = synthetic_log_list_json();
            let list = CtLogList::from_google_log_list_json(&json).unwrap();
            let readonly_log = list
                .iter()
                .find(|l| l.description == "readonly-log")
                .unwrap();
            // 2025-06-01T00:00:00Z = 1748736000000 ms
            // Oracle: python3 -c "import datetime; print(int(datetime.datetime(2025,6,1,tzinfo=datetime.timezone.utc).timestamp()*1000))"
            assert_eq!(readonly_log.retired_at_ms, Some(1_748_736_000_000));
            // Lower bound is unknown (the schema carries only the
            // current state), so the window is open below.
            assert_eq!(readonly_log.usable_from, UsableFrom::Unrecorded);
        }

        #[test]
        fn retired_log_window_open_below_closed_at_retirement() {
            let json = synthetic_log_list_json();
            let list = CtLogList::from_google_log_list_json(&json).unwrap();
            let retired_log = list
                .iter()
                .find(|l| l.description == "retired-log")
                .unwrap();
            // 2025-03-01T00:00:00Z = 1740787200000 ms
            // Oracle: python3 -c "import datetime; print(int(datetime.datetime(2025,3,1,tzinfo=datetime.timezone.utc).timestamp()*1000))"
            assert_eq!(retired_log.retired_at_ms, Some(1_740_787_200_000));
            assert_eq!(retired_log.usable_from, UsableFrom::Unrecorded);
        }

        #[test]
        fn usable_log_has_usable_from_ms() {
            let json = synthetic_log_list_json();
            let list = CtLogList::from_google_log_list_json(&json).unwrap();
            let usable_log = list.iter().find(|l| l.description == "usable-log").unwrap();
            // 2024-01-01T00:00:00Z = 1704067200000 ms
            // Oracle: python3 -c "import datetime; print(int(datetime.datetime(2024,1,1,tzinfo=datetime.timezone.utc).timestamp()*1000))"
            assert_eq!(usable_log.usable_from, UsableFrom::At(1_704_067_200_000));
            assert_eq!(usable_log.retired_at_ms, None);
        }
    }
}

// ---------------------------------------------------------------------------
// serde for CtLogList
// ---------------------------------------------------------------------------

/// `CtLogList` serializes as a plain sequence of [`CtLog`], not as the map
/// it stores internally.
///
/// Two reasons, and the second is the one that matters.
///
/// The map key is redundant: it *is* `SHA-256(key_der)` of the value it is
/// filed under, so writing it would store the same bytes twice and invite
/// the two copies to disagree.
///
/// More importantly, the round trip has to re-run the check.
/// [`CtLogList::insert`] enforces RFC 6962 §3.2 — `log_id ==
/// SHA-256(key_der)` — and rejects a mismatch as a corrupted source. A
/// plain `#[derive(Deserialize)]` on the struct would fill the `BTreeMap`
/// field directly and walk straight past that. The result would be a list
/// whose entries are filed under keys that do not match them, and since
/// [`CtLogList::get`] is how a caller maps a parsed SCT back to a trusted
/// log key, that means verifying an SCT against the wrong key — exactly
/// what the check exists to prevent.
///
/// Persisting a log list and reloading it is the use case this serde
/// support is for, so it is also precisely the path where the check must
/// run again.
#[cfg(feature = "serde")]
impl From<CtLogList> for alloc::vec::Vec<CtLog> {
    fn from(list: CtLogList) -> Self {
        list.logs.into_values().collect()
    }
}

/// Rebuilds the list through [`CtLogList::insert`], so a deserialized list
/// is held to the same RFC 6962 §3.2 consistency check as one built by hand
/// or parsed from Google's log list JSON.
///
/// # Errors
///
/// Returns [`Error::ParseError`] if any entry's `log_id` does not match
/// `SHA-256(key_der)`.
#[cfg(feature = "serde")]
impl TryFrom<alloc::vec::Vec<CtLog>> for CtLogList {
    type Error = crate::Error;

    fn try_from(logs: alloc::vec::Vec<CtLog>) -> Result<Self> {
        let mut list = Self::new();
        for log in logs {
            list.insert(log)?;
        }
        Ok(list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-256 of a known SubjectPublicKeyInfo blob. We use a tiny made-up
    /// DER (not a real log key — these unit tests don't need a real one).
    /// The point is to exercise the consistency check.
    fn dummy_log(key_der: Vec<u8>) -> CtLog {
        let log_id: [u8; 32] = Sha256::digest(&key_der).into();
        CtLog {
            log_id,
            key_der,
            description: "test".into(),
            url: "http://example.com/ct/".into(),
            usable_from: UsableFrom::Never,
            retired_at_ms: None,
        }
    }

    #[test]
    fn insert_and_get() {
        let mut list = CtLogList::new();
        assert!(list.is_empty());
        let log = dummy_log(b"fake key der".to_vec());
        let log_id = log.log_id;
        list.insert(log.clone()).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list.get(&log_id), Some(&log));
        assert_eq!(list.get(&[0u8; 32]), None);
    }

    #[test]
    fn rejects_log_id_mismatch() {
        let mut list = CtLogList::new();
        let bad = CtLog {
            log_id: [0u8; 32], // not SHA-256 of key_der
            key_der: b"fake key der".to_vec(),
            description: "test".into(),
            url: "http://example.com/ct/".into(),
            usable_from: UsableFrom::Never,
            retired_at_ms: None,
        };
        assert_eq!(list.insert(bad), Err(Error::ParseError));
        assert!(list.is_empty());
    }

    #[test]
    fn iter_visits_all_in_log_id_order() {
        let mut list = CtLogList::new();
        list.insert(dummy_log(b"key1".to_vec())).unwrap();
        list.insert(dummy_log(b"key2".to_vec())).unwrap();
        list.insert(dummy_log(b"key3".to_vec())).unwrap();
        let collected: Vec<_> = list.iter().map(|l| l.key_der.clone()).collect();
        assert_eq!(collected.len(), 3);
        // Ordering is by log_id, which is unrelated to key_der content;
        // we just assert all three are present.
        assert!(collected.contains(&b"key1".to_vec()));
        assert!(collected.contains(&b"key2".to_vec()));
        assert!(collected.contains(&b"key3".to_vec()));
    }
}
