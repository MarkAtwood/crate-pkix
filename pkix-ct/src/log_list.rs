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

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// Metadata for one CT log.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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
    /// When the log became usable, if ever.
    ///
    /// - `Some(ts)` — the log became usable at timestamp `ts`
    ///   (milliseconds since the Unix epoch). SCTs with timestamps
    ///   before `ts` are not trustworthy even if signed by this
    ///   log's key.
    /// - `None` — the log has never reached the usable state. SCTs
    ///   from this log will fail the
    ///   [`usable_from_ms`, `retired_at_ms`) window check
    ///   unconditionally.
    pub usable_from_ms: Option<u64>,
    /// Moment after which the log should not be relied on for new
    /// SCTs, in milliseconds since the Unix epoch. `None` means the
    /// log has not been retired. SCTs issued before this point are
    /// still valid; SCTs issued at or after it should be treated as
    /// untrusted.
    pub retired_at_ms: Option<u64>,
}

/// A set of trusted CT logs indexed by `log_id`.
#[derive(Clone, Debug, Default)]
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
    use super::{CtLog, CtLogList};
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
        /// * `usable` — actively trusted; `usable_from_ms` is set.
        /// * `readonly` — no longer accepting submissions but still
        ///   trusted for existing SCTs; the readonly timestamp is
        ///   stored as `retired_at_ms`.
        /// * `retired` — no longer operated but historical SCTs remain
        ///   valid; `retired_at_ms` is set.
        /// * `qualified` — accepted into the program but pre-usable;
        ///   imported with `usable_from_ms = None`.
        /// * Logs with no `state` field are imported as-is.
        ///
        /// # Errors
        ///
        /// Returns [`Error::ParseError`] on JSON syntax errors,
        /// invalid base64 in `log_id` or `key`, malformed timestamps,
        /// or a `log_id` ⇔ `key` mismatch.
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
                    let usable_from_ms = log
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
                    out.insert(CtLog {
                        log_id,
                        key_der,
                        description: log.description,
                        url: log.url,
                        usable_from_ms,
                        retired_at_ms,
                    })?;
                }
            }
            Ok(out)
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
        let year: i32 = parse_digits(&bytes[0..4])? as i32;
        let month: u32 = parse_digits(&bytes[5..7])?;
        let day: u32 = parse_digits(&bytes[8..10])?;
        let hour: u32 = parse_digits(&bytes[11..13])?;
        let min: u32 = parse_digits(&bytes[14..16])?;
        let sec: u32 = parse_digits(&bytes[17..19])?;

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
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
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

            let usable = entry(b"key-usable", "usable-log",
                r#"{"usable":{"timestamp":"2024-01-01T00:00:00Z"}}"#);
            let readonly = entry(b"key-readonly", "readonly-log",
                r#"{"readonly":{"timestamp":"2025-06-01T00:00:00Z"}}"#);
            let retired = entry(b"key-retired", "retired-log",
                r#"{"retired":{"timestamp":"2025-03-01T00:00:00Z"}}"#);
            let qualified = entry(b"key-qualified", "qualified-log",
                r#"{"qualified":{"timestamp":"2024-06-01T00:00:00Z"}}"#);
            let pending = entry(b"key-pending", "pending-log",
                r#"{"pending":{"timestamp":"2024-02-01T00:00:00Z"}}"#);
            let rejected = entry(b"key-rejected", "rejected-log",
                r#"{"rejected":{"timestamp":"2024-05-01T00:00:00Z"}}"#);

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
            let readonly_log = list.iter().find(|l| l.description == "readonly-log").unwrap();
            // 2025-06-01T00:00:00Z = 1748736000000 ms
            // Oracle: python3 -c "import datetime; print(int(datetime.datetime(2025,6,1,tzinfo=datetime.timezone.utc).timestamp()*1000))"
            assert_eq!(readonly_log.retired_at_ms, Some(1_748_736_000_000));
            assert_eq!(readonly_log.usable_from_ms, None);
        }

        #[test]
        fn usable_log_has_usable_from_ms() {
            let json = synthetic_log_list_json();
            let list = CtLogList::from_google_log_list_json(&json).unwrap();
            let usable_log = list.iter().find(|l| l.description == "usable-log").unwrap();
            // 2024-01-01T00:00:00Z = 1704067200000 ms
            // Oracle: python3 -c "import datetime; print(int(datetime.datetime(2024,1,1,tzinfo=datetime.timezone.utc).timestamp()*1000))"
            assert_eq!(usable_log.usable_from_ms, Some(1_704_067_200_000));
            assert_eq!(usable_log.retired_at_ms, None);
        }
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
            usable_from_ms: None,
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
            usable_from_ms: None,
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
