//! x509-limbo corpus loader (PKIX-g9vc.2).
//!
//! Reads the [x509-limbo] `limbo.json` testsuite manifest (~40 MB, ~9.7k
//! testcases) and emits [`crate::corpus::CorpusItem`]s. The pyca-maintained
//! corpus is the project's Tier-2 differential coverage source, complementing
//! the Tier-1 PKITS pack.
//!
//! [x509-limbo]: https://github.com/C2SP/x509-limbo
//!
//! # Filter rationale
//!
//! `LimboCorpus::load` pre-filters testcases before yielding. Filtered-out
//! cases are dropped at load time, not at iteration time, so `iter()` only
//! sees in-scope work. The filter is intentionally RFC-5280-shaped (NOT
//! pedantic-webpki). A testcase is dropped when ANY of the following hold:
//!
//! * `validation_kind != Server` — drops 10 CLIENT cases. S/MIME validation
//!   (RFC 8550 etc.) is not yet wired into the harness.
//! * `!features.is_empty()` — drops 36 featured cases. The `Feature` taxonomy
//!   (has-crl, pedantic-*, name-constraint-dn, max-chain-depth,
//!   denial-of-service, has-policy-constraints, rfc5280-incompatible-with-webpki)
//!   covers behaviours that either rely on subsystems still in flight (CRLs,
//!   policy constraints) or are deliberately stricter than RFC 5280 baseline.
//! * `max_chain_depth.is_some()` — catches a single outlier
//!   (`pathological::intermediate-cycle-distinct-cas-max-depth`) that sets
//!   `max_chain_depth: 255` without the corresponding `max-chain-depth`
//!   feature tag.
//! * `!crls.is_empty()` — defensive. Redundant with the `has-crl` feature
//!   filter today, but keeps the loader honest if a future corpus update
//!   ships CRLs without the feature tag.
//!
//! Loosening this filter is the entry point for staging CRL / policy /
//! webpki-pedantic coverage as those subsystems land (PKIX-emf1 family
//! and adjacent epics).
//!
//! # `validation_time` handling
//!
//! Each testcase optionally carries an RFC 3339 `validation_time`. When
//! present, the loader parses it to Unix seconds and threads it into
//! [`crate::Chain::validation_time_unix`] via
//! [`crate::Chain::with_validation_time`] so every oracle pins to that
//! instant. When `null`, the loader uses a deterministic default
//! (`1_700_000_000` = 2023-11-14T22:13:20Z, "middle of the limbo era")
//! instead of `SystemTime::now()` — reproducibility over wall-clock-now.
//! Limbo testcases are calibrated to specific moments (cert validity
//! windows, name-constraints date math); pinning the default keeps the
//! corpus output stable across runs.
//!
//! # Limitations
//!
//! * `expected_peer_name` / `expected_peer_names` are deserialised but
//!   currently ignored. The harness has no SAN-matching oracle yet.
//! * `signature_algorithms`, `key_usage`, `extended_key_usage` are
//!   inert — the corpus does not exercise them as constraints today.
//! * `peer_certificate_key` (the EE's private key) is deserialised but
//!   ignored — the harness does no TLS handshake.
//! * Multi-anchor `trusted_certs` is not yet supported. If a testcase
//!   ships more than one trusted cert, only `trusted_certs[0]` is used.
//!   The full multi-anchor surface is tracked separately.

use std::fs;
use std::io;
use std::path::Path;

use der::Decode as _;
use pem_rfc7468 as pem;
use pkix_path::{DefaultVerifier, TrustAnchor, ValidationPolicy};
use pkix_path_builder::{build_first_valid_path, CertPool};
use serde::Deserialize;
use x509_cert::Certificate;

use crate::corpus::{Corpus, CorpusItem};
use crate::{Chain, Verdict};

/// Deterministic default validation time used when a testcase's
/// `validation_time` field is `null`. Unix seconds = 2023-11-14T22:13:20Z.
const DEFAULT_VALIDATION_TIME_UNIX: u64 = 1_700_000_000;

// ---------------------------------------------------------------------------
// JSON schema mirror
// ---------------------------------------------------------------------------

/// Top-level `limbo.json` shape: `{"version": ..., "testcases": [...]}`.
///
/// We do NOT use `#[serde(deny_unknown_fields)]`. The pyca-maintained corpus
/// has historically added new top-level keys (e.g. `version`); ignoring
/// unknown fields keeps us tolerant when that happens. The schema-defined
/// fields we DO consume are individually required to deserialise correctly.
#[derive(Debug, Deserialize)]
struct LimboManifest {
    testcases: Vec<Testcase>,
}

/// One testcase from `limbo.json`. Field set mirrors `limbo-schema.json`'s
/// `Testcase` definition 1:1. The 8 fields with schema-level defaults
/// (`conflicts_with`, `features`, `importance`, `peer_certificate_key`,
/// `validation_time`, `expected_peer_name`, `max_chain_depth`, `crls`) carry
/// `#[serde(default)]` here. `signature_algorithms` is marked required in
/// the schema but always serialised as an empty list by the renderer; we
/// keep `#[serde(default)]` defensively for the same tolerance reason.
#[derive(Debug, Deserialize)]
struct Testcase {
    id: String,
    #[allow(dead_code)] // human description, not used by the harness
    description: String,
    validation_kind: ValidationKind,
    trusted_certs: Vec<String>,
    untrusted_intermediates: Vec<String>,
    peer_certificate: String,
    #[serde(default)]
    #[allow(dead_code)] // private key, not consumed by the harness
    peer_certificate_key: Option<String>,
    #[serde(default)]
    validation_time: Option<String>,
    #[serde(default)]
    #[allow(dead_code)] // inert (no constraint oracle yet)
    signature_algorithms: Vec<SignatureAlgorithm>,
    #[serde(default)]
    #[allow(dead_code)] // inert (no constraint oracle yet)
    key_usage: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)] // inert (no constraint oracle yet)
    extended_key_usage: Vec<String>,
    expected_result: ExpectedResult,
    #[serde(default)]
    #[allow(dead_code)] // inert (no SAN oracle yet)
    expected_peer_name: Option<PeerName>,
    #[serde(default)]
    #[allow(dead_code)] // inert (no SAN oracle yet)
    expected_peer_names: Vec<PeerName>,
    #[serde(default)]
    max_chain_depth: Option<u32>,
    #[serde(default)]
    crls: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)] // metadata, not used by the harness
    importance: Option<String>,
    #[serde(default)]
    #[allow(dead_code)] // metadata, not used by the harness
    conflicts_with: Vec<String>,
    #[serde(default)]
    features: Vec<Feature>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
enum ValidationKind {
    Client,
    Server,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
enum ExpectedResult {
    Success,
    Failure,
}

/// Schema-defined feature tags. The harness's default filter drops any
/// testcase carrying *any* feature; we still enumerate every variant so
/// schema drift surfaces as a parse error rather than a silent skip.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[allow(dead_code)] // variants are matched structurally via `Vec::is_empty`
enum Feature {
    HasPolicyConstraints,
    HasCertPolicies,
    NoCertPolicies,
    PedanticPublicSuffixWildcard,
    NameConstraintDn,
    PedanticWebpkiSubscriberKey,
    PedanticWebpkiEku,
    PedanticSerialNumber,
    MaxChainDepth,
    PedanticRfc5280,
    Rfc5280IncompatibleWithWebpki,
    DenialOfService,
    HasCrl,
}

/// Signature algorithms enumerated in `limbo-schema.json`. Inert today — the
/// corpus never populates `signature_algorithms` — but spelt out fully so a
/// future schema update fails loudly at parse rather than silently widening.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[allow(dead_code)]
#[allow(clippy::upper_case_acronyms)]
enum SignatureAlgorithm {
    #[serde(rename = "RSA_WITH_MD5")]
    RsaWithMd5,
    #[serde(rename = "RSA_WITH_SHA1")]
    RsaWithSha1,
    #[serde(rename = "RSA_WITH_SHA224")]
    RsaWithSha224,
    #[serde(rename = "RSA_WITH_SHA256")]
    RsaWithSha256,
    #[serde(rename = "RSA_WITH_SHA384")]
    RsaWithSha384,
    #[serde(rename = "RSA_WITH_SHA512")]
    RsaWithSha512,
    #[serde(rename = "RSA_WITH_SHA3_224")]
    RsaWithSha3_224,
    #[serde(rename = "RSA_WITH_SHA3_256")]
    RsaWithSha3_256,
    #[serde(rename = "RSA_WITH_SHA3_384")]
    RsaWithSha3_384,
    #[serde(rename = "RSA_WITH_SHA3_512")]
    RsaWithSha3_512,
    #[serde(rename = "RSASSA_PSS")]
    RsassaPss,
    #[serde(rename = "ECDSA_WITH_SHA1")]
    EcdsaWithSha1,
    #[serde(rename = "ECDSA_WITH_SHA224")]
    EcdsaWithSha224,
    #[serde(rename = "ECDSA_WITH_SHA256")]
    EcdsaWithSha256,
    #[serde(rename = "ECDSA_WITH_SHA384")]
    EcdsaWithSha384,
    #[serde(rename = "ECDSA_WITH_SHA512")]
    EcdsaWithSha512,
    #[serde(rename = "ECDSA_WITH_SHA3_224")]
    EcdsaWithSha3_224,
    #[serde(rename = "ECDSA_WITH_SHA3_256")]
    EcdsaWithSha3_256,
    #[serde(rename = "ECDSA_WITH_SHA3_384")]
    EcdsaWithSha3_384,
    #[serde(rename = "ECDSA_WITH_SHA3_512")]
    EcdsaWithSha3_512,
    #[serde(rename = "DSA_WITH_SHA1")]
    DsaWithSha1,
    #[serde(rename = "DSA_WITH_SHA224")]
    DsaWithSha224,
    #[serde(rename = "DSA_WITH_SHA256")]
    DsaWithSha256,
    #[serde(rename = "DSA_WITH_SHA384")]
    DsaWithSha384,
    #[serde(rename = "DSA_WITH_SHA512")]
    DsaWithSha512,
    Ed25519,
    Ed448,
    #[serde(rename = "GOSTR3411_94_WITH_3410_2001")]
    Gostr3411_94With3410_2001,
    #[serde(rename = "GOSTR3410_2012_WITH_3411_2012_256")]
    Gostr3410_2012With3411_2012_256,
    #[serde(rename = "GOSTR3410_2012_WITH_3411_2012_512")]
    Gostr3410_2012With3411_2012_512,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // inert; no SAN oracle yet
struct PeerName {
    kind: String,
    value: String,
}

// ---------------------------------------------------------------------------
// LimboCorpus
// ---------------------------------------------------------------------------

/// Filtered testcase normalised into harness-ready form.
///
/// Pre-decoded into the exact shapes `Corpus::iter` needs so iteration is
/// cheap: PEM bytes still encoded (the iterator base64-decodes per item; no
/// point holding ~9700 × ~4 KB of DER in memory).
#[derive(Debug)]
struct FilteredTestcase {
    id: String,
    expected: Verdict,
    validation_time_unix: u64,
    peer_certificate_pem: String,
    intermediates_pem: Vec<String>,
    trusted_certs_pem: Vec<String>,
    // Intentionally no `crls` field: the default filter excludes
    // `has-crl` cases. Re-add when CRL coverage lands.
}

/// Loader for the x509-limbo corpus.
///
/// See the module-level docs for filter rationale, `validation_time` policy,
/// and known limitations.
#[derive(Debug)]
pub struct LimboCorpus {
    testcases: Vec<FilteredTestcase>,
}

impl LimboCorpus {
    /// Read and parse `limbo.json` from `manifest_path`, applying the
    /// default filter described in the module docs.
    pub fn load(manifest_path: &Path) -> io::Result<Self> {
        let bytes = fs::read(manifest_path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "limbo corpus: cannot read manifest at {}: {e}",
                    manifest_path.display()
                ),
            )
        })?;
        Self::load_from_bytes(&bytes)
    }

    /// Parse a `limbo.json` byte slice and apply the default filter.
    ///
    /// Same behaviour as [`Self::load`] but consuming the JSON from memory.
    /// Used by integration tests to assemble synthetic manifests without
    /// touching the filesystem; also useful for callers that fetch the
    /// corpus over HTTP.
    pub fn load_from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let manifest: LimboManifest = serde_json::from_slice(bytes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("limbo corpus: malformed JSON: {e}"),
            )
        })?;

        let mut filtered: Vec<FilteredTestcase> = Vec::with_capacity(manifest.testcases.len());
        for tc in manifest.testcases {
            // --- Filter clauses -------------------------------------------
            // CLIENT testcases are S/MIME-shaped and out of scope until the
            // harness grows an S/MIME oracle.
            if tc.validation_kind != ValidationKind::Server {
                continue;
            }
            // Any feature tag means the testcase exercises a non-baseline
            // subsystem (CRL, policy constraints, webpki pedantry, etc.).
            // Drop them all until those subsystems are wired up.
            if !tc.features.is_empty() {
                continue;
            }
            // Catches the one schema corner-case that sets max_chain_depth
            // without the corresponding feature tag.
            if tc.max_chain_depth.is_some() {
                continue;
            }
            // Defensive: redundant with `has-crl` feature filter today, but
            // keeps the loader honest if the corpus ever ships CRLs without
            // the feature tag.
            if !tc.crls.is_empty() {
                continue;
            }

            let validation_time_unix = match tc.validation_time {
                Some(ref s) => parse_rfc3339_to_unix(s).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "limbo corpus: testcase '{}' has unparseable validation_time \
                             {s:?}: {e}",
                            tc.id
                        ),
                    )
                })?,
                None => DEFAULT_VALIDATION_TIME_UNIX,
            };

            let expected = match tc.expected_result {
                ExpectedResult::Success => Verdict::Pass,
                // Ground truth does not standardise the failure reason —
                // only the outcome. Same pattern as `PkitsCorpus`.
                ExpectedResult::Failure => Verdict::Fail {
                    reason: String::new(),
                },
            };

            filtered.push(FilteredTestcase {
                id: tc.id,
                expected,
                validation_time_unix,
                peer_certificate_pem: tc.peer_certificate,
                intermediates_pem: tc.untrusted_intermediates,
                trusted_certs_pem: tc.trusted_certs,
            });
        }

        Ok(Self {
            testcases: filtered,
        })
    }

    /// Number of testcases retained after filtering.
    #[must_use]
    pub fn len(&self) -> usize {
        self.testcases.len()
    }

    /// Whether the filtered corpus is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.testcases.is_empty()
    }
}

impl Corpus for LimboCorpus {
    fn iter(&self) -> Box<dyn Iterator<Item = io::Result<CorpusItem>> + '_> {
        Box::new(self.testcases.iter().map(|tc| {
            build_item(tc)
                .map_err(|e| io::Error::new(e.kind(), format!("limbo '{}': {}", tc.id, e)))
        }))
    }
}

/// Decode a single PEM CERTIFICATE block into DER.
///
/// Rejects non-CERTIFICATE labels loudly: a testcase whose `peer_certificate`
/// is actually a private key is a corpus bug, not silent-drop material.
fn pem_to_der(pem_text: &str) -> io::Result<Vec<u8>> {
    let (label, der) = pem::decode_vec(pem_text.as_bytes()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("PEM decode failed: {e}"),
        )
    })?;
    if label != "CERTIFICATE" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected CERTIFICATE PEM block, got {label}"),
        ));
    }
    Ok(der)
}

/// Try to assemble the canonical leaf-first signature chain from a limbo
/// testcase's leaf-first DER bundle (peer at `[0]`, anchor at `[last]`,
/// intermediates in between) via
/// [`pkix_path_builder::build_first_valid_path`].
///
/// Returns `None` on any failure — parse error, no topological path found,
/// or every candidate rejected by [`pkix_path::validate_path`]. Callers
/// fall back to the testcase's positional ordering, which keeps the chain
/// bytes visible to every oracle for downstream classification.
///
/// **Why `build_first_valid_path` and not `build_path`?** PKIX-lwr9.4
/// (2026-05-11) found that `build_path` is single-shot: in cross-signed
/// pools containing intermediates whose signature algorithm
/// `DefaultVerifier` does not dispatch (e.g., the depth-6 `bettertls::tc60`
/// fixture with an `ecdsa-with-SHA1` cross-cert), the first DFS candidate
/// can fail signature verification while a valid alternative exists at a
/// later DFS position. `build_first_valid_path` iterates
/// `build_path_candidates` internally and returns the first chain that
/// also passes `validate_path` — exactly the build-then-validate retry
/// loop the limbo harness needs.
///
/// `now_unix` is the testcase's pinned `validation_time_unix`; threading
/// it through the builder ensures the validate step honors the same time
/// anchor the downstream oracles will use.
///
/// Empirical finding from PKIX-lwr9.1 (2026-05-11): of the 25
/// `bettertls::pathbuilding` fixtures sampled into
/// `pkix-path-builder/tests/bettertls.rs`, 23 of 25 pass end-to-end when
/// routed through the iterating helper. PKIX-lwr9.4.1 closes the tc60 gap
/// inside `pkix-difftest`. This mirrors PKITS's `pkits.rs::try_build_chain`,
/// but adapted for leaf-first input and the verifier-aware iteration.
fn try_build_chain(der_blocks: &[Vec<u8>], now_unix: u64) -> Option<Vec<Vec<u8>>> {
    if der_blocks.len() < 2 {
        return None;
    }

    let mut parsed: Vec<Certificate> = Vec::with_capacity(der_blocks.len());
    for bytes in der_blocks {
        parsed.push(Certificate::from_der(bytes).ok()?);
    }

    let ee_idx = 0;
    let anchor_idx = parsed.len() - 1;
    let ee = &parsed[ee_idx];
    let anchor = &parsed[anchor_idx];

    // Pool of candidates for path building: everything except the anchor.
    // Including the EE in the pool is harmless — the builder uses pool
    // only as a candidate source for intermediates and never tries to
    // re-add the target. Mirrors `pkits.rs::try_build_chain`.
    let pool: CertPool = parsed
        .iter()
        .enumerate()
        .filter(|&(i, _)| i != anchor_idx)
        .map(|(_, c)| c.clone())
        .collect();

    let trust_anchors = [TrustAnchor::from_cert(anchor.clone())];
    let policy = ValidationPolicy::new(now_unix);
    let built =
        build_first_valid_path(ee, &pool, &trust_anchors, &policy, &DefaultVerifier).ok()?;

    // Map each built-chain cert back to its source DER bytes. `Certificate`
    // derives `PartialEq` over its full ASN.1 content, so equality is the
    // right oracle.
    let mut chain_der: Vec<Vec<u8>> = Vec::with_capacity(built.len() + 1);
    for built_cert in &built {
        let idx = parsed.iter().position(|p| p == built_cert)?;
        chain_der.push(der_blocks[idx].clone());
    }
    // Append the anchor (the builder returns the chain up to anchor-issued
    // but not the anchor itself; the oracles' `root_in_chain == true`
    // contract requires the anchor at the end).
    chain_der.push(der_blocks[anchor_idx].clone());
    Some(chain_der)
}

/// Build the [`CorpusItem`] for a filtered testcase.
///
/// Chain ordering is leaf-first per the harness contract (`Chain::certs_der`
/// is documented as canonical leaf-first):
///   `[peer_certificate, ..untrusted_intermediates, trusted_certs[0]]`.
///
/// The leaf-first positional bundle is routed through
/// [`pkix_path_builder::build_path`] before classification (PKIX-lwr9.6).
/// The bundle is a path-builder input, not a pre-ordered signature chain:
/// `bettertls::pathbuilding` testcases in particular ship multiple
/// candidate intermediates and rely on the consumer to pick the right
/// one. Falling back to positional ordering on build failure preserves
/// baseline coverage for negative testcases whose bundles deliberately
/// violate a topological invariant. Mirrors PKITS's `pkits.rs::build_item`.
///
/// The trust anchor at the tail is required for `root_in_chain = true`. If
/// a testcase ships multiple `trusted_certs`, only the first is used — see
/// the module-level limitations note.
fn build_item(tc: &FilteredTestcase) -> io::Result<CorpusItem> {
    let trusted_pem = tc.trusted_certs_pem.first().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "trusted_certs is empty (need at least one anchor)",
        )
    })?;

    let mut positional_der: Vec<Vec<u8>> = Vec::with_capacity(2 + tc.intermediates_pem.len());

    positional_der.push(pem_to_der(&tc.peer_certificate_pem)?);
    for inter in &tc.intermediates_pem {
        positional_der.push(pem_to_der(inter)?);
    }
    positional_der.push(pem_to_der(trusted_pem)?);

    // Try the path-builder reorder; fall back to the testcase's positional
    // leaf-first ordering on any builder failure. See `try_build_chain`
    // rustdoc and the function-level docstring above for rationale.
    //
    // `tc.validation_time_unix` is threaded into the builder so the inner
    // `validate_path` step honors the testcase's pinned time anchor —
    // otherwise certs that are valid at limbo-pinned-time but expired at
    // wall-clock-now would be rejected by the builder and silently dropped
    // into the positional fallback.
    let certs_der =
        try_build_chain(&positional_der, tc.validation_time_unix).unwrap_or(positional_der);

    let chain = Chain {
        certs_der,
        crls: Vec::new(),
        root_in_chain: true,
        label: tc.id.clone(),
        validation_time_unix: None,
    }
    .with_validation_time(tc.validation_time_unix);

    Ok(CorpusItem {
        name: tc.id.clone(),
        expected: Some(tc.expected.clone()),
        chain,
    })
}

// ---------------------------------------------------------------------------
// RFC 3339 parser
// ---------------------------------------------------------------------------

/// Parse an RFC 3339 timestamp into Unix seconds.
///
/// Accepts the two shapes the limbo corpus actually uses today:
///
/// * `YYYY-MM-DDTHH:MM:SS+HH:MM` (the dominant form — all 33 unique
///   `validation_time` values currently end in `+00:00`).
/// * `YYYY-MM-DDTHH:MM:SSZ` (the canonical UTC suffix; accepted because
///   the schema explicitly permits `format: date-time`).
/// * Optional fractional seconds (`.fff` up to 6 digits) between the
///   `SS` and the offset, accepted but truncated to second precision
///   because [`Chain::validation_time_unix`] is `u64` seconds.
///
/// We do NOT pull in `chrono` / `time` — the format is tightly constrained
/// by a known producer (pyca's renderer), the parser is ~30 LOC, and the
/// harness already vendors an equivalent one in `pkix-ct/src/log_list.rs`
/// (see memory `pkix-baac-2-ct-log-list-google-json`).
fn parse_rfc3339_to_unix(s: &str) -> Result<u64, &'static str> {
    let bytes = s.as_bytes();
    // Minimum: 20 chars for `YYYY-MM-DDTHH:MM:SSZ`.
    if bytes.len() < 20 || bytes[10] != b'T' {
        return Err("too short or missing 'T'");
    }
    let year = i32::try_from(parse_digits(&bytes[0..4])?).map_err(|_| "year overflow")?;
    let month: u32 = parse_digits(&bytes[5..7])?;
    let day: u32 = parse_digits(&bytes[8..10])?;
    let hour: u32 = parse_digits(&bytes[11..13])?;
    let min: u32 = parse_digits(&bytes[14..16])?;
    let sec: u32 = parse_digits(&bytes[17..19])?;

    // Skip optional fractional seconds — we keep second precision only.
    let mut cursor = 19usize;
    if cursor < bytes.len() && bytes[cursor] == b'.' {
        cursor += 1;
        let mut count = 0;
        while cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
            cursor += 1;
            count += 1;
        }
        if count == 0 || count > 6 {
            return Err("bad fractional-seconds length");
        }
    }

    // Parse the timezone offset. Either `Z` or `±HH:MM`.
    let (off_sign, off_hour, off_min): (i64, i64, i64) = match bytes.get(cursor) {
        Some(b'Z') => {
            if cursor + 1 != bytes.len() {
                return Err("trailing bytes after 'Z'");
            }
            (1, 0, 0)
        }
        Some(b'+' | b'-') => {
            let sign: i64 = if bytes[cursor] == b'+' { 1 } else { -1 };
            // Need: HH:MM exactly (5 more bytes).
            if cursor + 6 != bytes.len() || bytes[cursor + 3] != b':' {
                return Err("bad offset shape");
            }
            let oh = i64::from(parse_digits(&bytes[cursor + 1..cursor + 3])?);
            let om = i64::from(parse_digits(&bytes[cursor + 4..cursor + 6])?);
            (sign, oh, om)
        }
        _ => return Err("missing timezone designator"),
    };

    if month == 0 || month > 12 || day == 0 || day > 31 {
        return Err("bad month/day");
    }
    if hour > 23 || min > 59 || sec > 60 {
        // 60 tolerated for leap-second pedantry, though limbo never uses it.
        return Err("bad time-of-day");
    }
    if off_hour > 23 || off_min > 59 {
        return Err("bad offset value");
    }

    let days = days_from_civil(year, month, day)?;
    let local_secs = days * 86400 + i64::from(hour) * 3600 + i64::from(min) * 60 + i64::from(sec);
    let offset_secs = off_sign * (off_hour * 3600 + off_min * 60);
    let utc_secs = local_secs - offset_secs;
    u64::try_from(utc_secs).map_err(|_| "date before Unix epoch")
}

fn parse_digits(bytes: &[u8]) -> Result<u32, &'static str> {
    let mut out: u32 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return Err("non-digit");
        }
        out = out
            .checked_mul(10)
            .and_then(|v| v.checked_add(u32::from(b - b'0')))
            .ok_or("overflow")?;
    }
    Ok(out)
}

/// Howard Hinnant's "days from civil" algorithm: maps a proleptic
/// Gregorian (year, month, day) to days since 1970-01-01. Public domain.
/// <https://howardhinnant.github.io/date_algorithms.html#days_from_civil>
fn days_from_civil(year: i32, month: u32, day: u32) -> Result<i64, &'static str> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err("bad month/day");
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    // `y - era * 400` is in [0, 399] by construction (era is floor-div by 400),
    // so the cast to u32 is sound. `try_from` here is just clippy hygiene; a
    // failure means the algebra above is wrong, not bad input.
    let yoe = u32::try_from(y - era * 400).map_err(|_| "yoe out of range")?;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Ok(i64::from(era) * 146_097 + i64::from(doe) - 719_468)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_parses_plus_zero_offset() {
        // 2024-01-01T00:00:00+00:00 → 1704067200
        assert_eq!(
            parse_rfc3339_to_unix("2024-01-01T00:00:00+00:00").unwrap(),
            1_704_067_200
        );
    }

    #[test]
    fn rfc3339_parses_z_suffix() {
        assert_eq!(
            parse_rfc3339_to_unix("2024-01-01T00:00:00Z").unwrap(),
            1_704_067_200
        );
    }

    #[test]
    fn rfc3339_parses_non_zero_offset() {
        // 2024-06-15T14:00:00+02:00 == 2024-06-15T12:00:00Z == 1718452800
        assert_eq!(
            parse_rfc3339_to_unix("2024-06-15T14:00:00+02:00").unwrap(),
            1_718_452_800
        );
    }

    #[test]
    fn rfc3339_parses_with_fractional_seconds() {
        // Fractional part is dropped (second precision).
        assert_eq!(
            parse_rfc3339_to_unix("2024-01-01T00:00:00.500+00:00").unwrap(),
            1_704_067_200
        );
    }

    #[test]
    fn rfc3339_parses_corpus_examples() {
        // Sampled from limbo.json's actual `validation_time` values.
        assert_eq!(
            parse_rfc3339_to_unix("1970-01-01T00:00:03+00:00").unwrap(),
            3
        );
        assert_eq!(
            parse_rfc3339_to_unix("2016-09-01T00:00:00+00:00").unwrap(),
            1_472_688_000
        );
    }

    #[test]
    fn rfc3339_rejects_garbage() {
        assert!(parse_rfc3339_to_unix("not-a-date").is_err());
        assert!(parse_rfc3339_to_unix("2024-01-01T00:00:00").is_err()); // no tz
        assert!(parse_rfc3339_to_unix("2024-13-01T00:00:00Z").is_err()); // bad month
        assert!(parse_rfc3339_to_unix("2024-01-01 00:00:00Z").is_err()); // space, no T
    }
}
