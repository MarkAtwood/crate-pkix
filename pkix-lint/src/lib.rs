#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! Lint engine for X.509 certificate chains — structured soft-fail and advisory results.
//!
//! # What this crate provides
//!
//! `pkix-path` returns `Result<ValidatedPath, Error>` — hard pass or fail.
//! That model cannot express "this certificate is RFC 5280 valid but violates
//! CA/B Forum BR §7.1.4.2" without aborting the chain entirely.
//!
//! `pkix-lint` adds an advisory layer:
//!
//! - [`Lint`] — the unit of evaluation. Each lint has a stable ID, a normative
//!   citation, a severity, a scope (certificate vs. full chain path), and a
//!   subject-kind filter (leaf, intermediate CA, etc.).
//! - [`LintResult`] — `Pass | NotApplicable | Warn | Error | Fatal`. `Warn`
//!   and `Error` carry a `&'static str` detail message. `Fatal` within
//!   `pkix-lint` means "stop evaluating further lints" — it is **not** a TLS
//!   hard-fail. See the advisory-only contract below.
//! - [`Finding`] — a lint ID paired with a [`LintResult`], optionally referencing
//!   the chain index of the offending certificate.
//! - [`LintRunner`] — evaluates a slice of `dyn Lint` objects against a certificate
//!   or validated path and returns `Vec<Finding>`.
//! - [`LintProfile`] — extends [`pkix_path::Profile`] with a `lints()` method so
//!   that a profile can bundle its own lint set.
//!
//! # Finding ID stability
//!
//! Finding IDs (returned by [`Lint::id`]) are part of the public API.
//! They MUST NOT change between crate versions without a semver-major bump.
//! Format convention: `<regime>.<section>.<noun>`, e.g.:
//! - `"cabf.br.tls.validity.max"`
//! - `"cabf.smime.san.type"`
//! - `"rfc5280.basic_constraints.ca_flag"`
//!
//! # Advisory-only contract
//!
//! **`pkix-lint` findings never cause a certificate to be rejected.** All runner
//! methods return `Vec<Finding>` — they never return `Result::Err` and they never
//! cause a TLS stack to abort a connection. Findings are advisory signals.
//!
//! Whether to act on a finding (reject a TLS connection, block a cert, alert an
//! operator) is the caller's decision, configured per finding-ID at the integration
//! layer (e.g., `pkix-chain` or a TLS stack binding). This design is intentional:
//!
//! - `pkix-lint` does not know whether you are in audit, monitoring, or enforcement
//!   context. The caller does.
//! - Spec ambiguity (CA/B Forum CPs, FPKI CPs, etc.) means some findings require
//!   human judgment before enforcement. Hard-fail by default would cause outages.
//! - The deviation/waiver mechanism (PKIX-jge) operates at this layer, not in
//!   `pkix-lint` core.
//!
//! The only in-engine effect of [`LintResult::Fatal`] is stopping further lint
//! evaluation for the current item — it does not escape as an error.
//!
//! # Design rationale
//!
//! Inspired by zlint and certlint but with several deliberate differences:
//!
//! - **Trait-based, not enum-based**: external crates can implement [`Lint`] and
//!   pass `Box<dyn Lint>` to [`LintRunner`] without modifying this crate.
//! - **Cow detail messages**: `LintResult::Warn`, `Error`, and `Fatal` carry
//!   `Cow<'static, str>` detail. Static string literals are zero-allocation
//!   (`Cow::Borrowed`); runtime-formatted strings such as `format!(...)` use
//!   `Cow::Owned` without leaking memory.
//! - **Temporality-aware**: [`LintRunner::run_cert`] takes `now_unix: u64` so lints
//!   can enforce rules that have effective dates (e.g., SC-081 validity caps).
//! - **Scope-separated**: certificate lints and path lints run in separate passes so
//!   path lints can see the full validated output.
//!
//! # Example
//!
//! ```rust,no_run
//! // `cert` and `now_unix` are obtained from the calling context (e.g., loaded
//! // from DER and current wall-clock time). They are not defined here so the
//! // example cannot be run in a doctest harness without external fixtures.
//! use pkix_lint::{Lint, LintResult, LintRunner, Scope, Severity, SubjectKind};
//! use x509_cert::Certificate;
//!
//! #[derive(Clone)]
//! struct MyLint;
//! impl Lint for MyLint {
//!     fn id(&self) -> &'static str { "example.my_lint" }
//!     fn citation(&self) -> &'static str { "Example Corp Policy §1.2" }
//!     fn severity(&self) -> Severity { Severity::Warn }
//!     fn scope(&self) -> Scope { Scope::Certificate }
//!     fn applies_to(&self) -> SubjectKind { SubjectKind::Leaf }
//!     fn check_cert(&self, cert: &Certificate, _kind: SubjectKind, _now_unix: u64) -> LintResult {
//!         if cert.tbs_certificate.subject.to_string().is_empty() {
//!             LintResult::warn("empty Subject DN")
//!         } else {
//!             LintResult::Pass
//!         }
//!     }
//! }
//!
//! let cert: Certificate = unimplemented!("load from DER");
//! let now_unix: u64 = unimplemented!("current Unix epoch seconds");
//! let runner = LintRunner::new(vec![Box::new(MyLint)]);
//! let findings = runner.run_cert(&cert, SubjectKind::Leaf, 0, now_unix);
//! for f in &findings {
//!     println!("{}: {:?}", f.lint_id, f.result);
//! }
//! ```
//!
//! # Limitations
//!
//! - **Framework, not a comprehensive rule set.** This crate ships the
//!   [`Lint`] trait, [`LintRunner`], and a small RFC-conformance lint set
//!   in the `rfc5280`, `rfc6125`, `rfc8398`, and `rfc8551` modules.
//!   Comprehensive industry-forum lint coverage is the job of policy
//!   adapter crates (`pkix-policy-zlint` for zlint's ~700 rules,
//!   `pkix-policy-pkilint` for pkilint's S/MIME BR + ETSI coverage).
//!   CA/B Forum reference lints live in the sibling `pkix-lint-cabf`
//!   crate; that crate is also explicitly small and curated.
//! - **Advisory-only.** Findings never cause a TLS rejection by themselves
//!   (see the contract above). Plumbing findings into hard-fail or
//!   waiver decisions is the integration layer's job.
//! - **OSCAL adapter is one supported output, not the canonical format.**
//!   The `oscal` feature emits OSCAL Assessment Results JSON and parses
//!   OSCAL Risk-based deviations back into [`deviation::DeviationStore`].
//!   The workspace does not prescribe OSCAL as a canonical inter-tool
//!   wire format (AGENTS.md non-negotiable #5, three-mode policy
//!   architecture); each policy-adapter crate consumes its upstream
//!   tool's natural format.
//! - **No site-local policy DSL.** Site-local policy is the deployer's
//!   responsibility; implement [`Lint`] (or load lints from any
//!   deployer-chosen format) and feed [`LintRunner`].

use std::borrow::Cow;
use x509_cert::Certificate;

// Re-export so callers only need to depend on pkix-lint, not pkix-path.
pub use pkix_path::{Profile, ValidatedPath, ValidationPolicy};

/// Compute SHA-256 of a DER-encoded certificate.
///
/// Used by [`LintRunner::run_cert`] to stamp [`Finding::cert_sha256`] for
/// evidence-pack provenance. `cert` is re-encoded to DER first so the
/// hash is over the canonical re-encoded form (matching what serialisers
/// downstream of pkix-lint would produce). For PKITS-style fixtures whose
/// DER round-trips losslessly through `x509-cert`, this equals the hash
/// of the original on-disk bytes.
///
/// Returns `None` when the certificate fails to re-encode to DER. This is
/// rare but not theoretical — `x509-cert` accepts some inputs through
/// `Decode` that its `Encode` impl cannot round-trip (DEFAULT-tagged
/// fields, BMPString edge cases). Returning `None` here is preferable to
/// silently stamping every finding with `SHA256(empty)`
/// (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`):
/// two distinct un-encodable certs would otherwise produce findings that
/// falsely claim identical provenance. Callers can distinguish
/// "provenance unavailable" (`None`) from a legitimate hash (`Some(_)`).
fn cert_sha256_of(cert: &Certificate) -> Option<[u8; 32]> {
    use der::Encode as _;
    use sha2::Digest as _;
    let der = cert.to_der().ok()?;
    let mut hasher = sha2::Sha256::new();
    hasher.update(&der);
    Some(hasher.finalize().into())
}

#[cfg(feature = "serde")]
mod serde_helpers {
    //! Serde adapters for fields that prefer a different on-wire form than
    //! their in-memory shape.

    /// Hex-string codec for `Option<[u8; 32]>` (Finding.cert_sha256).
    ///
    /// JSON: `Some([..])` ↔ `"<64 lowercase hex chars>"`, `None` ↔ `null`.
    /// Binary serde formats fall through to the natural `Option<[u8; 32]>`
    /// encoding because serializers like postcard treat `with =` modules as
    /// JSON-style overrides only when wired this way. To be precise about
    /// formats: this module emits a `String` for `Some` and a `None` for
    /// `None`, in every serde format. For binary formats that's a length-
    /// prefixed string carrying 64 hex chars — slightly less compact than
    /// raw bytes, but consistent across formats and trivially decodable.
    pub(crate) mod cert_sha256_hex {
        use serde::{Deserialize as _, Deserializer, Serializer};

        pub(crate) fn serialize<S: Serializer>(
            v: &Option<[u8; 32]>,
            s: S,
        ) -> Result<S::Ok, S::Error> {
            match v {
                Some(bytes) => {
                    let mut hex = String::with_capacity(64);
                    for b in bytes {
                        // Lowercase hex; no separators. Matches the digest
                        // conventions used by OSCAL Link / Prop hrefs and
                        // every Unix sha256sum tool.
                        hex.push(char::from_digit(u32::from(b >> 4), 16).expect("hex high nibble"));
                        hex.push(
                            char::from_digit(u32::from(b & 0x0f), 16).expect("hex low nibble"),
                        );
                    }
                    s.serialize_some(&hex)
                }
                None => s.serialize_none(),
            }
        }

        pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
            d: D,
        ) -> Result<Option<[u8; 32]>, D::Error> {
            let opt: Option<String> = Option::deserialize(d)?;
            let Some(hex) = opt else {
                return Ok(None);
            };
            // Operate on the byte view rather than `&str` slicing: the
            // `hex.len() == 64` check below is a byte-length check, so a
            // 64-byte string containing multi-byte UTF-8 (e.g., the JSON
            // input `"\u00fc\u00fc..."` whose UTF-8 encoding happens to be
            // 64 bytes) passes the length gate. `&hex[i..i+1]` on such an
            // input would panic at the non-char-boundary inside
            // `from_str_radix`. Iterate `hex.as_bytes()` instead and route
            // each byte through `nibble()`, which rejects every non-ASCII-
            // hex byte as a serde custom error rather than panicking.
            if hex.len() != 64 {
                return Err(serde::de::Error::invalid_length(
                    hex.len(),
                    &"64 lowercase hex chars (32-byte SHA-256)",
                ));
            }
            let bytes = hex.as_bytes();
            let mut out = [0u8; 32];
            for (i, byte) in out.iter_mut().enumerate() {
                let hi = nibble(bytes[i * 2])
                    .ok_or_else(|| serde::de::Error::custom("non-hex char in cert_sha256"))?;
                let lo = nibble(bytes[i * 2 + 1])
                    .ok_or_else(|| serde::de::Error::custom("non-hex char in cert_sha256"))?;
                *byte = (hi << 4) | lo;
            }
            Ok(Some(out))
        }

        /// Decode one ASCII hex byte to its 4-bit nibble value. Returns
        /// `None` for any non-hex input — including non-ASCII bytes from
        /// a multi-byte UTF-8 sequence, which is the panic surface this
        /// helper was introduced to close (PKIX-7f92.1).
        ///
        /// Duplicates the helper in [`crate::oscal::parse`]; the broader
        /// consolidation is tracked under PKIX-7f92.14.
        fn nibble(b: u8) -> Option<u8> {
            match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            }
        }
    }
}

/// Serde deserializer helper for `Cow<'static, str>` fields.
///
/// Deserializes any string input as an owned `String` wrapped in `Cow::Owned`.
/// This does not leak memory — the allocation is owned and freed when the
/// containing struct is dropped.
///
/// Used for `Finding.lint_id`, `Finding.citation`, and `DeviatedFinding` fields
/// that are `&'static str` at construction time (populated from lint metadata) but
/// need to round-trip through serde without leaking.
#[cfg(feature = "serde")]
pub(crate) fn de_cow_static<'de, D>(deserializer: D) -> Result<Cow<'static, str>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    let s = String::deserialize(deserializer)?;
    Ok(Cow::Owned(s))
}

pub mod deviation;
#[cfg(feature = "oscal")]
#[cfg_attr(docsrs, doc(cfg(feature = "oscal")))]
pub mod oscal;
pub mod report;
pub mod rfc5280;
pub mod rfc6125;
pub mod rfc8398;
pub mod rfc8551;

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

/// How seriously to treat a lint finding.
///
/// Severity is a property of the lint definition, not the result. A lint that
/// checks a MUST requirement from a normative spec should be [`Severity::Error`].
/// A lint that checks a SHOULD or advisory requirement should be [`Severity::Warn`].
///
/// # Ordering
///
/// `Severity` deliberately does NOT derive `PartialOrd` / `Ord`. Comparing
/// severities directly with `<` / `>=` would couple every caller's
/// comparison semantics to the source-order position of the variants —
/// inserting a new variant in the middle of the enum (e.g., a future
/// syslog-aligned `Critical` between `Error` and `Fatal`) would silently
/// change the meaning of every `>= Severity::Warn` predicate in caller
/// code. The `#[derive(Ord)] on a public enum` stability trap is a known
/// hazard in the Rust ecosystem.
///
/// Use [`Severity::rank`] for ordering: it returns a documented per-variant
/// `u8` where higher values are more severe. The ranks are stable across
/// variant insertions — a new variant picks a free `u8` slot in the right
/// semantic position without disturbing existing ranks.
///
/// Worked example: `if finding.severity.rank() >= Severity::Warn.rank()
/// { ... }` retains its meaning across pkix-lint versions even if a new
/// variant lands between `Info` and `Warn`.
///
/// The rank scale `Info=10, Notice=20, Warn=30, Error=40, Fatal=50` aligns
/// with both the zlint catalog ranking (`pass(3) < notice(4) < warn(5) <
/// error(6) < fatal(7)`, see `~/GIT/zlint/v3/lint/result.go`) and syslog
/// RFC 5424 §6.2.1 severity ranking (Informational > Notice > Warning).
/// Ranks are spaced by 10 to leave room for future insertions.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Severity {
    /// Advisory / best-practice — does not constitute a violation.
    Info,
    /// Minor observation — not a violation but worth surfacing.
    ///
    /// Aligns with zlint's `notice` verdict and syslog RFC 5424 §6.2.1
    /// severity 5 (Notice). Used by the planned `pkix-zlint-bridge`
    /// adapter to map zlint catalog notice-level checks into the
    /// workspace severity model.
    Notice,
    /// Violation of a SHOULD or RECOMMENDED requirement.
    Warn,
    /// Violation of a MUST or REQUIRED requirement.
    Error,
    /// Violation so severe that further evaluation is meaningless.
    ///
    /// For example: malformed DER structure that prevents parsing subsequent fields.
    Fatal,
}

impl Severity {
    /// Documented `u8` rank for stable ordering across variant
    /// insertions. Use this instead of comparing `Severity` values
    /// directly. See the struct rustdoc for the rationale.
    ///
    /// Ranks are spaced by 10 so a future mid-scale insertion can
    /// claim a free slot without disturbing existing ranks. For
    /// example, a syslog-aligned `Critical` between `Error` and
    /// `Fatal` would land at rank 45.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Info => 10,
            Self::Notice => 20,
            Self::Warn => 30,
            Self::Error => 40,
            Self::Fatal => 50,
        }
    }
}

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

/// Whether a lint evaluates a single certificate or the complete validated path.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Scope {
    /// The lint evaluates one certificate in isolation.
    Certificate,
    /// The lint evaluates the full [`ValidatedPath`] and all certificates together.
    Path,
}

// ---------------------------------------------------------------------------
// SubjectKind
// ---------------------------------------------------------------------------

/// Which certificate positions in the chain a lint applies to.
///
/// Used both as a filter in [`Lint::applies_to`] (which certs the lint checks)
/// and as the label in [`LintRunner`] when calling the lint (what cert we're at).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SubjectKind {
    /// End-entity (leaf) certificate — the subject of the chain.
    Leaf,
    /// Intermediate CA certificate — has `BasicConstraints` cA=TRUE, not a trust anchor.
    IntermediateCa,
    /// Any certificate issued directly by a trust anchor (the top intermediate).
    AnchorIssued,
    /// All certificate positions (lint applies universally).
    Any,
}

impl SubjectKind {
    /// Returns `true` if a lint declared for `filter` should run against `self`.
    ///
    /// Rules:
    /// - `Any` filter matches everything.
    /// - An exact match always returns `true`.
    /// - `AnchorIssued` is a sub-category of `IntermediateCa`; a filter of
    ///   `IntermediateCa` also matches `AnchorIssued` certificates.
    #[must_use]
    pub fn matches(self, filter: Self) -> bool {
        match filter {
            Self::Any => true,
            Self::IntermediateCa => self == Self::IntermediateCa || self == Self::AnchorIssued,
            other => self == other,
        }
    }
}

// ---------------------------------------------------------------------------
// LintParameter (PKIX-9vnx.6.4)
// ---------------------------------------------------------------------------

/// Descriptor for a tunable parameter exposed by a [`Lint`] implementation.
///
/// `LintParameter` is the in-memory form of an OSCAL Catalog `Parameter` (see
/// the [OSCAL Catalog model][oscal-cat]). Each parameter has a stable
/// identifier (`id`), a human-readable label, and a default value rendered
/// as a string for OSCAL interchange.
///
/// `LintParameter` is **descriptor-only**. It does not hold the lint's
/// current value; the lint stores its own typed state (`usize`, `Duration`,
/// etc.) and serialises through the descriptor at OSCAL boundaries. The
/// "current value" plumbing happens via [`Lint::set_parameter`]:
/// implementations parse the supplied `value: &str` into their typed state
/// and update it in place. Callers wishing to inspect or override defaults
/// at OSCAL Profile composition time use the `id` to address parameters
/// across lint impls.
///
/// # OSCAL mapping
///
/// | `LintParameter` field | OSCAL `parameter` field |
/// |-----------------------|-------------------------|
/// | `id`                  | `id` (string token)     |
/// | `label`               | `label` (human-readable)|
/// | `default_value`       | `values[0]` (string)    |
///
/// OSCAL's richer parameter shape (constraint, guideline, select, link)
/// is not modelled here; callers needing that surface should serialise
/// `LintParameter` first and then graft on additional OSCAL fields at
/// the Catalog-emit boundary.
///
/// [oscal-cat]: https://pages.nist.gov/OSCAL/concepts/layer/control/catalog/
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct LintParameter {
    /// Stable identifier — used to address the parameter in
    /// [`Lint::set_parameter`] and in OSCAL Profile `modify` directives.
    /// Example: `"max-octets"`.
    pub id: Cow<'static, str>,

    /// Human-readable label, suitable for UI display.
    /// Example: `"Maximum allowed serial number length in octets"`.
    pub label: Cow<'static, str>,

    /// Default value rendered as a string. Lints parse this back into their
    /// typed state if a caller has not supplied an override via
    /// [`Lint::set_parameter`].
    pub default_value: Cow<'static, str>,
}

impl LintParameter {
    /// Construct a [`LintParameter`] with the three required fields.
    ///
    /// Use this constructor instead of struct-literal syntax so the
    /// addition of future fields (OSCAL `constraint`, `guideline`,
    /// `select`, `link` shape mentioned in the type-level rustdoc)
    /// remains a non-breaking change. The struct carries
    /// `#[non_exhaustive]`.
    #[must_use]
    pub fn new(
        id: impl Into<Cow<'static, str>>,
        label: impl Into<Cow<'static, str>>,
        default_value: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            default_value: default_value.into(),
        }
    }
}

/// Error reported by [`Lint::set_parameter`].
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParameterError {
    /// The lint does not expose a parameter with the supplied id.
    UnknownParameter(String),
    /// The supplied value failed to parse or violated a domain constraint
    /// declared by the lint.
    InvalidValue {
        /// Parameter id the invalid value was supplied for.
        id: String,
        /// Human-readable explanation suitable for surfacing to operators.
        reason: String,
    },
}

impl core::fmt::Display for ParameterError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownParameter(id) => write!(f, "unknown lint parameter '{id}'"),
            Self::InvalidValue { id, reason } => {
                write!(f, "invalid value for lint parameter '{id}': {reason}")
            }
        }
    }
}

impl std::error::Error for ParameterError {}

// ---------------------------------------------------------------------------
// LintResult
// ---------------------------------------------------------------------------

/// The outcome of evaluating a single lint against a certificate or path.
///
/// # Stability
///
/// The variant names are stable. The detail field type is
/// `Cow<'static, str>`, accepting both static string literals (zero-cost,
/// via `Cow::Borrowed`) and runtime-formatted owned strings (via
/// `Cow::Owned`).
///
/// # Constructing
///
/// Use the helpers [`LintResult::warn`], [`LintResult::error`], and
/// [`LintResult::fatal`] for idiomatic construction from any
/// `Into<Cow<'static, str>>` source — string literals or owned `String`
/// values both work without explicit `Cow::Borrowed(...)` wrapping:
///
/// ```rust
/// use pkix_lint::LintResult;
///
/// // Static literal — zero-allocation Cow::Borrowed.
/// let r1 = LintResult::error("validity exceeds cap");
///
/// // Runtime-formatted — Cow::Owned, freed with the LintResult.
/// let actual_days = 400u64;
/// let r2 = LintResult::error(format!("validity {actual_days} days exceeds cap"));
/// ```
///
/// Pattern matches use the variant constructors directly:
///
/// ```rust
/// # use pkix_lint::LintResult;
/// # let r = LintResult::warn("x");
/// match &r {
///     LintResult::Warn(detail) => println!("warn: {}", detail),
///     LintResult::Error(detail) => println!("error: {}", detail),
///     _ => {}
/// }
/// ```
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LintResult {
    /// The lint check passed — no finding.
    Pass,
    /// The lint does not apply to this certificate or context.
    ///
    /// For example, a lint that checks SAN for leaves would return `NotApplicable`
    /// when called against an intermediate CA certificate.
    ///
    /// `NotApplicable` is not an error; the runner records it for audit completeness
    /// but it does not affect compliance status.
    NotApplicable,
    /// Advisory finding — the cert deviates from a SHOULD or best practice.
    ///
    /// The detail string is a human-readable explanation of the finding.
    /// Use [`LintResult::warn`] for ergonomic construction.
    Warn(Cow<'static, str>),
    /// Error finding — the cert violates a MUST or REQUIRED requirement.
    ///
    /// The detail string is a human-readable explanation of the finding.
    /// Use [`LintResult::error`] for ergonomic construction.
    Error(Cow<'static, str>),
    /// Fatal finding — further evaluation of this cert/path is not meaningful.
    ///
    /// The detail string is a human-readable explanation of the finding.
    /// The runner stops evaluating remaining lints for the current item when
    /// it encounters a `Fatal`. Use [`LintResult::fatal`] for ergonomic
    /// construction.
    ///
    /// # `Fatal` is report-only
    ///
    /// **`Fatal` does NOT cause the TLS stack to reject the certificate.**
    /// `pkix-lint` is an advisory layer only. All findings — including `Fatal` —
    /// are reported in the `Vec<Finding>` returned by [`LintRunner`]. Whether to
    /// act on a finding (e.g., reject a TLS connection, abort a certificate
    /// issuance, or log a compliance event) is the caller's decision, made at the
    /// integration boundary (e.g., `pkix-chain` or a TLS stack binding).
    ///
    /// The only effect of `Fatal` within `pkix-lint` itself is to stop evaluating
    /// further lints for the current certificate or path — it does not propagate
    /// as a `Result::Err` or cause any panic.
    Fatal(Cow<'static, str>),
}

impl LintResult {
    /// Returns `true` if this result represents a clean pass (no finding).
    #[must_use]
    pub const fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }

    /// Returns `true` if this result represents a finding (Warn, Error, or Fatal).
    #[must_use]
    pub const fn is_finding(&self) -> bool {
        matches!(self, Self::Warn(_) | Self::Error(_) | Self::Fatal(_))
    }

    /// Returns `true` if the runner should stop evaluating further lints for this item.
    #[must_use]
    pub const fn is_fatal(&self) -> bool {
        matches!(self, Self::Fatal(_))
    }

    /// Returns the detail message for `Warn`, `Error`, or `Fatal`; `None` for `Pass`/`NotApplicable`.
    ///
    /// The returned reference is borrowed from `self` and lives only as long
    /// as `self` does. To obtain an owned copy that outlives `self`, clone the
    /// `Cow` directly from the matched variant.
    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Warn(d) | Self::Error(d) | Self::Fatal(d) => Some(d.as_ref()),
            _ => None,
        }
    }

    /// Construct a [`LintResult::Warn`] from any value convertible to
    /// `Cow<'static, str>`.
    ///
    /// Accepts string literals (zero-allocation `Cow::Borrowed`) and owned
    /// `String` values (allocated `Cow::Owned`). Use this for lints that
    /// report runtime-formatted detail.
    #[must_use]
    pub fn warn(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::Warn(detail.into())
    }

    /// Construct a [`LintResult::Error`] from any value convertible to
    /// `Cow<'static, str>`.
    ///
    /// Accepts string literals (zero-allocation `Cow::Borrowed`) and owned
    /// `String` values (allocated `Cow::Owned`). Use this for lints that
    /// report runtime-formatted detail.
    #[must_use]
    pub fn error(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::Error(detail.into())
    }

    /// Construct a [`LintResult::Fatal`] from any value convertible to
    /// `Cow<'static, str>`.
    ///
    /// Accepts string literals (zero-allocation `Cow::Borrowed`) and owned
    /// `String` values (allocated `Cow::Owned`). Use this for lints that
    /// report runtime-formatted detail.
    #[must_use]
    pub fn fatal(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::Fatal(detail.into())
    }
}

// ---------------------------------------------------------------------------
// Display implementations
// ---------------------------------------------------------------------------

impl core::fmt::Display for Severity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Info => f.write_str("info"),
            Self::Notice => f.write_str("notice"),
            Self::Warn => f.write_str("warn"),
            Self::Error => f.write_str("error"),
            Self::Fatal => f.write_str("fatal"),
        }
    }
}

impl core::fmt::Display for LintResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Pass => f.write_str("Pass"),
            Self::NotApplicable => f.write_str("NotApplicable"),
            Self::Warn(msg) => write!(f, "Warn: {msg}"),
            Self::Error(msg) => write!(f, "Error: {msg}"),
            Self::Fatal(msg) => write!(f, "Fatal: {msg}"),
        }
    }
}

impl core::fmt::Display for Finding {
    /// Format: `"lint_id [severity]: message"` for findings, `"lint_id [pass]"` for non-findings.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let severity_label = match &self.result {
            LintResult::Warn(_) => "warn",
            LintResult::Error(_) => "error",
            LintResult::Fatal(_) => "fatal",
            LintResult::Pass => "pass",
            LintResult::NotApplicable => "n/a",
        };
        match self.result.detail() {
            Some(msg) => write!(f, "{} [{}]: {}", self.lint_id, severity_label, msg),
            None => write!(f, "{} [{}]", self.lint_id, severity_label),
        }
    }
}

// ---------------------------------------------------------------------------
// Lint trait
// ---------------------------------------------------------------------------

/// Supertrait of [`Lint`] that lets `Box<dyn Lint>` be cloned.
///
/// **Implementors of [`Lint`] do NOT implement `LintClone` directly.**
/// A blanket impl provides `LintClone` for every type that is
/// `Lint + Clone + 'static`. Concrete lint types just need to derive
/// or implement [`Clone`].
///
/// The clone is used by [`LintRunner::apply_parameter_overrides`] to
/// validate parameter values against a fresh copy of the lint before
/// committing the change to the runner's registered state, giving
/// atomic application semantics on `set_parameter` failures
/// (PKIX-hy2e.6).
pub trait LintClone {
    /// Clone the lint into a fresh `Box<dyn Lint>`.
    ///
    /// The default blanket impl uses [`Clone::clone`] on the concrete
    /// type; do not override this unless your lint has interior
    /// mutability that needs special handling.
    fn clone_box(&self) -> Box<dyn Lint>;
}

impl<T> LintClone for T
where
    T: Lint + Clone + 'static,
{
    fn clone_box(&self) -> Box<dyn Lint> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn Lint> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

/// A single, independently evaluable lint check.
///
/// # Implementing `Lint`
///
/// Each lint must have a stable, globally unique ID (see crate-level doc for the
/// naming convention). Both `check_cert` and `check_path` are provided so the
/// same trait covers both certificate-scoped and path-scoped lints. Implement
/// whichever method is appropriate for your lint and let the other return
/// [`LintResult::NotApplicable`] (the default).
///
/// # Use-case applicability — operator contract
///
/// Many RFC-conformance lints check a property that only applies to a
/// specific *use case* — e.g., TLS server, S/MIME, code-signing,
/// OCSP responder. The trait does not encode use case in its type
/// signature; instead, **use-case selection is the
/// [`LintProfile`][crate::LintProfile] bundle's responsibility.**
///
/// Concretely:
///
/// - [`crate::rfc5280::Rfc5280EkuServerAuthLint`] and
///   [`crate::rfc6125::Rfc6125TlsServerSanLint`] assert TLS-server-only
///   properties. They are bundled by `pkix_profiles::BasicTlsProfile`.
/// - [`crate::rfc8398::Rfc8398SmimeSanLint`] and
///   [`crate::rfc8551::Rfc8551EkuEmailProtectionLint`] assert
///   S/MIME-only properties. They are bundled by
///   `pkix_profiles::BasicSmimeProfile`.
///
/// **These two bundles are mutually exclusive** — no single leaf
/// certificate satisfies all four lints simultaneously, because the
/// EKU requirements (`id-kp-serverAuth` vs `id-kp-emailProtection`) and
/// SAN requirements (dNSName/iPAddress vs rfc822Name/SmtpUTF8Mailbox)
/// describe different cert shapes.
///
/// **Operators MUST NOT create a single "all rfc-conformance lints"
/// bundle that mixes TLS-server and S/MIME lints.** Doing so produces
/// two or more mutually-contradictory `Error` findings on every leaf,
/// regardless of cert shape. The correct pattern is to choose the
/// `LintProfile` bundle that matches the cert's intended use case
/// (`BasicTlsProfile`, `BasicSmimeProfile`, etc.) and call
/// [`check_shape`][crate::check_shape] with it.
///
/// Each affected lint's struct-level rustdoc carries a
/// `# Use-case applicability — operator contract` section reiterating
/// this constraint and naming its canonical `LintProfile` bundler.
///
/// # Object safety
///
/// The trait is object-safe: `Box<dyn Lint>` and `&dyn Lint` both work.
///
/// # Cloneability
///
/// [`Lint`] requires the [`LintClone`] supertrait so `Box<dyn Lint>`
/// can be cloned. A blanket impl provides `LintClone` for every
/// `Lint + Clone + 'static`, so implementors just need to derive or
/// implement [`Clone`] on their concrete type — they do NOT need to
/// implement `LintClone` directly. This requirement is necessary for
/// [`LintRunner::apply_parameter_overrides`] to provide atomic
/// parameter-application semantics: the runner clones lints, applies
/// overrides to the clones, and only swaps on success
/// (PKIX-hy2e.6).
pub trait Lint: LintClone + Send + Sync {
    /// Globally unique, stable identifier for this lint.
    ///
    /// Format: `<regime>.<section>.<noun>` e.g. `"cabf.br.tls.validity.max"`.
    /// This string is part of the public API — never change it once published.
    fn id(&self) -> &'static str;

    /// Human-readable citation: spec name, version, and section.
    ///
    /// Example: `"CA/B Forum TLS BR §6.3.2 (SC-081)"`.
    /// Not parsed by the engine; used in reports and error messages.
    fn citation(&self) -> &'static str;

    /// The declared severity of a positive finding from this lint.
    ///
    /// Note: [`LintResult::Warn`] and [`LintResult::Error`] can be returned
    /// regardless of the declared `severity()`. The declared severity is metadata
    /// used by report renderers and compliance dashboards.
    fn severity(&self) -> Severity;

    /// Whether this lint operates on individual certificates or the full path.
    fn scope(&self) -> Scope;

    /// Which certificate positions this lint applies to.
    ///
    /// For [`Scope::Certificate`] lints, the runner uses this to skip
    /// `check_cert` for positions that don't match, returning
    /// [`LintResult::NotApplicable`] automatically.
    ///
    /// For [`Scope::Path`] lints, `applies_to()` is **not consulted** by the
    /// runner — `check_path` is always called. Path-scope lints that need to
    /// restrict themselves to certain chain configurations should implement
    /// that logic inside `check_path` and return [`LintResult::NotApplicable`]
    /// when the path does not qualify.
    fn applies_to(&self) -> SubjectKind;

    // -- Standards-body metadata (PKIX-9vnx.6.1, renamed in pkix-lint 0.6.0)
    //
    // The next six methods declare per-lint metadata that is useful for any
    // report or serialization format. The OSCAL emit code in
    // `pkix_lint::oscal` is one consumer that maps these fields to OSCAL
    // Catalog Control properties, but the methods are not OSCAL-specific.
    // All are default-provided so existing impls keep compiling; shipped
    // lints should override at least `title` and one standards-body
    // citation field for a usable catalog.

    /// Short human-readable title for the lint.
    ///
    /// Default: returns [`id`](Self::id) verbatim. Override when the lint id
    /// is a slug (e.g., `"cabf.br.tls.validity.max"`) and the title needs to
    /// be a sentence (e.g., `"Leaf certificate validity must not exceed
    /// SC-081 cap"`). The OSCAL emit code maps this to `control.title` when
    /// producing an OSCAL Catalog.
    fn title(&self) -> &str {
        self.id()
    }

    /// Long-form description of the lint's purpose. Optional because not
    /// every lint has more to say than its title and citation.
    ///
    /// Default: `None`. The OSCAL emit code maps this to
    /// `control.parts[name=statement].prose` when producing an OSCAL Catalog.
    fn description(&self) -> Option<&str> {
        None
    }

    /// Standards-body section identifier in `<source>-<section>` shape.
    ///
    /// The slot accepts any standards-body section identifier — IETF RFC,
    /// ITU-T X.509, CA/B Forum Baseline Requirements, NIST SP, etc.:
    ///
    /// * `"rfc5280-4.2.1.9"` — RFC 5280 §4.2.1.9.
    /// * `"cabf-tls-br-6.3.2"` — CA/B Forum TLS BR §6.3.2.
    /// * `"x509-ed4-section-8"` — ITU-T X.509 Edition 4 §8.
    ///
    /// When this returns `Some`, [`spec_url`](Self::spec_url) should also
    /// return a permanent URL where one exists. The OSCAL emit code maps
    /// this to a stable `control.prop` when producing an OSCAL Catalog.
    ///
    /// Renamed from `rfc_section_id` in pkix-lint 0.6.0 because the slot
    /// was never RFC-specific. The deprecated alias remains, and the
    /// default impl here delegates to it (PKIX-7f92.7) so pre-0.6.0
    /// Lint impls that override only the deprecated method continue to
    /// produce a non-None result through this canonical entry point.
    ///
    /// Default: `self.rfc_section_id()`. A pre-0.6.0 impl that
    /// overrides `rfc_section_id` works through this entry point with
    /// zero source changes; a 0.6.0+ impl that overrides
    /// `spec_section_id` is the canonical form going forward.
    fn spec_section_id(&self) -> Option<&str> {
        #[allow(deprecated)]
        self.rfc_section_id()
    }

    /// Deprecated alias for [`spec_section_id`](Self::spec_section_id).
    ///
    /// Renamed because the slot accepts CA/B Forum, ITU-T, NIST, and other
    /// standards-body section identifiers in addition to IETF RFCs.
    /// Override `spec_section_id` instead. The default impl here returns
    /// `None` (it is not symmetric with `spec_section_id` — pre-0.6.0
    /// impls override THIS method, and we cannot delegate back to
    /// `spec_section_id` without risking infinite recursion when
    /// neither is overridden).
    ///
    /// Scheduled removal target: pkix-lint 0.10.0 (a future minor at
    /// least four minors after the 0.6.0 introduction). Consumers who
    /// override this method should migrate to overriding
    /// `spec_section_id` directly.
    #[deprecated(
        since = "0.6.0",
        note = "renamed to `spec_section_id` because the slot accepts non-RFC ids (CA/B Forum, ITU-T, NIST); override `spec_section_id` instead. Scheduled removal target: 0.10.0."
    )]
    fn rfc_section_id(&self) -> Option<&str> {
        None
    }

    /// Permanent URL to the standards-body section referenced by
    /// [`spec_section_id`](Self::spec_section_id).
    ///
    /// For IETF RFCs the canonical form is
    /// `"https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9"`. CA/B
    /// Forum has no stable per-section anchor URL (BR documents are
    /// versioned and re-published frequently); leave this `None` and let
    /// the citation carry the §-reference. The OSCAL emit code maps this
    /// to `control.links[rel=reference]` when producing an OSCAL Catalog.
    ///
    /// Renamed from `rfc_url` in pkix-lint 0.6.0 alongside
    /// `spec_section_id`. The deprecated alias remains, and the
    /// default impl here delegates to it (PKIX-7f92.7) so pre-0.6.0
    /// Lint impls that override only the deprecated method continue
    /// to produce a non-None result through this canonical entry
    /// point.
    ///
    /// Default: `self.rfc_url()`.
    fn spec_url(&self) -> Option<&str> {
        #[allow(deprecated)]
        self.rfc_url()
    }

    /// Deprecated alias for [`spec_url`](Self::spec_url).
    ///
    /// Renamed alongside `spec_section_id`. Override `spec_url`
    /// instead. The default impl here returns `None` (asymmetric with
    /// `spec_url` for the same anti-recursion reason documented on
    /// [`rfc_section_id`](Self::rfc_section_id)).
    ///
    /// Scheduled removal target: pkix-lint 0.10.0.
    #[deprecated(
        since = "0.6.0",
        note = "renamed to `spec_url`; override `spec_url` instead. Scheduled removal target: 0.10.0."
    )]
    fn rfc_url(&self) -> Option<&str> {
        None
    }

    // -- Tunable parameters (PKIX-9vnx.6.4) --------------------------------
    //
    // `parameters()` advertises tunable knobs the lint exposes;
    // `set_parameter` mutates the lint's typed internal state from a
    // string-rendered value. The OSCAL emit code maps `parameters()` to
    // `control.params[*]` and `set_parameter` is the bridge for OSCAL
    // Profile `modify` directives when consuming an OSCAL Profile; but
    // both methods are useful independent of OSCAL.

    /// Tunable parameters exposed by this lint.
    ///
    /// Returns descriptors for every knob the lint exposes. Each
    /// descriptor names the parameter, gives a human-readable label, and
    /// renders its default value as a string.
    ///
    /// The descriptors do not carry the lint's current value — the lint
    /// stores typed state internally. To update a parameter at runtime,
    /// use [`set_parameter`](Self::set_parameter).
    ///
    /// Default: empty slice (no tunable parameters).
    fn parameters(&self) -> &[LintParameter] {
        &[]
    }

    /// Update a tunable parameter from its string-rendered value.
    ///
    /// `id` is the [`LintParameter::id`] addressed by the caller; `value`
    /// is the string-rendered value the lint must parse back into its
    /// typed internal state. Returns [`ParameterError::UnknownParameter`]
    /// when the id is not exposed by this lint, and
    /// [`ParameterError::InvalidValue`] when the value fails to parse or
    /// violates a lint-defined constraint.
    ///
    /// Default: returns [`ParameterError::UnknownParameter`] for every
    /// call. Lints with non-empty [`parameters`](Self::parameters) MUST
    /// override this method.
    ///
    /// # Mutability
    ///
    /// `set_parameter` takes `&mut self` because parameter updates change
    /// the lint's behaviour. Callers typically configure parameters before
    /// installing the lint into a [`LintRunner`]; the runner itself stores
    /// `Box<dyn Lint>` and does not expose mutation.
    #[allow(unused_variables)]
    fn set_parameter(&mut self, id: &str, value: &str) -> Result<(), ParameterError> {
        Err(ParameterError::UnknownParameter(id.to_owned()))
    }

    /// Evaluate the lint against a single certificate.
    ///
    /// `kind` is the role of this certificate in the chain (leaf, intermediate CA, etc.).
    /// `now_unix` is seconds since the Unix epoch at evaluation time.
    ///
    /// Default: returns [`LintResult::NotApplicable`].
    /// Lints with `scope() == Scope::Certificate` MUST override this method.
    #[allow(unused_variables)]
    fn check_cert(&self, cert: &Certificate, kind: SubjectKind, now_unix: u64) -> LintResult {
        LintResult::NotApplicable
    }

    /// Evaluate the lint against the full validated path.
    ///
    /// `chain` is the full certificate chain (leaf-first). `path` is the
    /// [`ValidatedPath`] returned by `pkix_path::validate_path`.
    /// `now_unix` is seconds since the Unix epoch at evaluation time.
    ///
    /// Default: returns [`LintResult::NotApplicable`].
    /// Lints with `scope() == Scope::Path` MUST override this method.
    #[allow(unused_variables)]
    fn check_path(&self, chain: &[Certificate], path: &ValidatedPath, now_unix: u64) -> LintResult {
        LintResult::NotApplicable
    }
}

// ---------------------------------------------------------------------------
// Finding
// ---------------------------------------------------------------------------

/// A recorded lint outcome, associating a lint ID with its result.
///
/// # Evidence pack support
///
/// `Finding` carries the metadata needed to construct an evidence pack
/// (a bundle of cert + path + findings + citations exportable as structured JSON
/// or OSCAL Assessment Results). The `citation` field records the normative
/// citation from [`Lint::citation`]; `evaluated_at_unix` records when the lint
/// was run; `rule_bundle_version` records which version of the lint bundle was
/// active; `cert_sha256` pins the finding to a specific certificate by content
/// hash so the evidence is replayable.
///
/// # Serde deserialization
///
/// All string fields use `Cow<'static, str>` and deserialize as `Cow::Owned`
/// without leaking allocations. The earlier `'de: 'static` bound (required
/// when `LintResult` detail fields were `&'static str`) was removed in
/// pkix-lint 0.3.0 with the migration tracked as PKIX-ua6q.
///
/// `cert_sha256` is serialised as a lowercase hex string in JSON (`Option<String>`
/// shape; `None` for path-scope findings) so OSCAL `Link` / `Prop` consumers
/// see the conventional digest representation, while binary serde formats
/// (postcard, MessagePack) emit raw bytes via the same `Option<[u8; 32]>` field.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Finding {
    /// The stable ID of the lint that produced this finding (from [`Lint::id`]).
    #[cfg_attr(feature = "serde", serde(deserialize_with = "de_cow_static"))]
    pub lint_id: Cow<'static, str>,
    /// The normative citation for this lint (from [`Lint::citation`]).
    ///
    /// Included here so consumers of `Vec<Finding>` do not need to re-look up
    /// the lint to get the citation for report generation and evidence packs.
    #[cfg_attr(feature = "serde", serde(deserialize_with = "de_cow_static"))]
    pub citation: Cow<'static, str>,
    /// Version string of the rule bundle that produced this finding.
    ///
    /// Set by [`LintRunner::with_bundle_version`]. Defaults to `""` when the runner
    /// was constructed with [`LintRunner::new`] without a version.
    ///
    /// Example: `"pkix-lint-cabf/cabf_tls_br v0.2.0, sourced from TLS BR SC-081"`.
    ///
    /// This field enables the "yellow today, green tomorrow because we updated the
    /// rule bundle from v1.3 to v1.4" explanation that prevents operators from
    /// treating a finding change as a tool defect.
    #[cfg_attr(feature = "serde", serde(deserialize_with = "de_cow_static"))]
    pub rule_bundle_version: Cow<'static, str>,
    /// The outcome of the lint evaluation.
    pub result: LintResult,
    /// For certificate-scope lints, the zero-based chain index of the evaluated cert.
    /// `None` for path-scope lints.
    pub cert_index: Option<usize>,
    /// Unix epoch seconds at which the lint was evaluated.
    ///
    /// For audit-mode evaluations (pass issuance time), this records the issuance time.
    /// For operational-mode evaluations (pass current time), this records the current time.
    /// Together with `cert_index` and the chain, this is sufficient to reconstruct
    /// the evaluation context in an evidence pack.
    pub evaluated_at_unix: u64,
    /// SHA-256 of the DER-encoded certificate that triggered this finding.
    ///
    /// Populated by [`LintRunner::run_cert`] for certificate-scope findings.
    /// `None` for path-scope findings (no single cert triggered the finding —
    /// the whole chain did). This is the canonical provenance field for
    /// evidence packs: a given (`lint_id`, `cert_sha256`) pair uniquely
    /// identifies which cert produced which finding, replayable against the
    /// same cert bytes years later.
    ///
    /// JSON serialisation uses a lowercase hex string (`Some` →
    /// `"abc...32hex..."`, `None` → `null`). Binary serde formats emit the
    /// raw 32-byte array.
    #[cfg_attr(
        feature = "serde",
        serde(default, with = "serde_helpers::cert_sha256_hex")
    )]
    pub cert_sha256: Option<[u8; 32]>,
}

impl Finding {
    /// Returns `true` if this finding is actionable (Warn, Error, or Fatal).
    #[must_use]
    pub const fn is_finding(&self) -> bool {
        self.result.is_finding()
    }

    /// Construct a [`Finding`] with the required fields.
    ///
    /// Use this constructor instead of struct-literal syntax so the
    /// addition of future fields (e.g., `path_position`,
    /// `severity_actual`, `evidence_chain_sha256`) remains a
    /// non-breaking change. The struct carries `#[non_exhaustive]`.
    ///
    /// Optional fields ([`Self::cert_index`], [`Self::cert_sha256`])
    /// default to `None`; set them via the corresponding `with_*`
    /// methods or via field assignment from within the defining crate.
    #[must_use]
    pub fn new(
        lint_id: impl Into<Cow<'static, str>>,
        citation: impl Into<Cow<'static, str>>,
        rule_bundle_version: impl Into<Cow<'static, str>>,
        result: LintResult,
        evaluated_at_unix: u64,
    ) -> Self {
        Self {
            lint_id: lint_id.into(),
            citation: citation.into(),
            rule_bundle_version: rule_bundle_version.into(),
            result,
            cert_index: None,
            evaluated_at_unix,
            cert_sha256: None,
        }
    }

    /// Builder-style setter for [`Self::cert_index`]. Returns `self`
    /// for chaining.
    #[must_use]
    pub fn with_cert_index(mut self, cert_index: usize) -> Self {
        self.cert_index = Some(cert_index);
        self
    }

    /// Builder-style setter for [`Self::cert_sha256`]. Returns `self`
    /// for chaining.
    #[must_use]
    pub fn with_cert_sha256(mut self, cert_sha256: [u8; 32]) -> Self {
        self.cert_sha256 = Some(cert_sha256);
        self
    }
}

// ---------------------------------------------------------------------------
// LintRunner
// ---------------------------------------------------------------------------

/// Evaluates a collection of [`Lint`]s against certificates or a validated path.
///
/// The runner is stateless beyond the lint set — construct once, call many times.
///
/// # Findings are advisory only
///
/// `LintRunner` methods return `Vec<Finding>` — they never return `Result::Err`
/// and they never cause a certificate to be rejected by a TLS stack. Findings
/// are an advisory layer. Whether to act on a finding (reject a connection,
/// block a cert, page an operator) is the caller's responsibility, configured
/// per finding-ID at the integration boundary.
///
/// This separation is intentional and must not be violated:
/// - `pkix-lint` does not know whether you are in an audit context, a
///   monitoring context, or an enforcement context. The caller does.
/// - Hard-fail behavior per finding-ID is configured in the integration layer
///   (e.g., `pkix-chain` or a TLS stack binding), not here.
/// - `pkix-lint` will never introduce a code path that returns `Err` or
///   panics based on lint findings.
///
/// # Evaluation order
///
/// Lints are evaluated in the order they were supplied to [`LintRunner::new`].
/// If a lint returns [`LintResult::Fatal`], the runner stops evaluating further
/// lints for the current item (cert or path) and records the fatal finding.
/// See [`LintResult::Fatal`] for the definition of "fatal within lint evaluation."
///
/// # Duplicate lint IDs
///
/// While the runner does not reject duplicate lint IDs, supplying lints with
/// duplicate IDs interacts poorly with the deviation mechanism: a deviation
/// keyed on a given ID will apply to every finding with that ID, which is
/// unlikely to be the intended behavior and makes the audit trail ambiguous.
/// Avoid duplicate IDs; in debug builds [`LintRunner::new`] asserts uniqueness.
///
/// # Thread safety
///
/// `LintRunner` is `Send + Sync` as long as all supplied lints are `Send + Sync`
/// (enforced by the `Lint: Send + Sync` bound).
pub struct LintRunner {
    lints: Vec<Box<dyn Lint>>,
    /// Version string stamped into every [`Finding`] produced by this runner.
    ///
    /// Set via [`LintRunner::with_bundle_version`]. Defaults to `""`.
    bundle_version: std::borrow::Cow<'static, str>,
}

impl core::fmt::Debug for LintRunner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LintRunner")
            .field("lint_count", &self.lints.len())
            .field("bundle_version", &self.bundle_version)
            .finish()
    }
}

impl LintRunner {
    /// Create a new runner from a set of lints, with no bundle version string.
    ///
    /// Lints are evaluated in the order supplied.
    ///
    /// # Panics
    ///
    /// Panics in **both debug and release builds** if any two lints share
    /// the same [`Lint::id`]. Duplicate IDs interact poorly with the
    /// deviation mechanism: a deviation keyed on a given ID would apply
    /// to every finding with that ID, silently halving the visible work
    /// and producing a false sense of compliance. The check is one sort +
    /// dedup over the lint id strings — `O(n log n)` over a typically
    /// small `n`, with no measurable cost for production lint bundles.
    ///
    /// To set a bundle version (recommended for production use), use
    /// [`LintRunner::with_bundle_version`].
    #[must_use]
    pub fn new(lints: Vec<Box<dyn Lint>>) -> Self {
        Self::check_unique_ids(&lints);
        Self {
            lints,
            bundle_version: std::borrow::Cow::Borrowed(""),
        }
    }

    /// Panic with a duplicate-ID message if `lints` contains two lints
    /// sharing the same [`Lint::id`]. Called from [`LintRunner::new`] and
    /// [`LintRunner::with_bundle_version`] so both constructors enforce
    /// the same invariant in both debug and release builds.
    fn check_unique_ids(lints: &[Box<dyn Lint>]) {
        let mut ids: Vec<&str> = lints.iter().map(|l| l.id()).collect();
        let original_len = ids.len();
        ids.sort_unstable();
        ids.dedup();
        if ids.len() != original_len {
            // Re-walk to find the first duplicate so the panic message
            // names it.
            let mut seen: std::collections::HashSet<&str> =
                std::collections::HashSet::with_capacity(lints.len());
            for l in lints {
                let id = l.id();
                if !seen.insert(id) {
                    panic!(
                        "LintRunner constructed with duplicate lint id {id:?}; \
                         duplicate IDs interact incorrectly with deviation matching \
                         and silently produce ambiguous audit trails. Deduplicate \
                         the lint set before constructing the runner."
                    );
                }
            }
            // Unreachable: ids.len() != original_len implies a duplicate
            // exists, which the loop above would have found.
            unreachable!("duplicate detected by dedup but not by HashSet walk");
        }
    }

    /// Create a new runner with an explicit bundle version string.
    ///
    /// The `version` string is stamped into every [`Finding`] produced by this runner
    /// as [`Finding::rule_bundle_version`]. Use this in production to record which
    /// version of the rule bundle was active when findings were generated.
    ///
    /// Accepts any value that converts to `Cow<'static, str>`: string literals
    /// (zero-copy) or owned `String` values (for runtime-constructed versions):
    ///
    /// ```rust,no_run
    /// use pkix_lint::LintRunner;
    /// // `lints` is a Vec<Box<dyn pkix_lint::Lint>> from the calling context.
    /// let lints: Vec<Box<dyn pkix_lint::Lint>> = vec![];
    ///
    /// // Static literal — zero allocation
    /// let runner = LintRunner::with_bundle_version(
    ///     lints,
    ///     "pkix-lint-cabf/cabf_tls_br v0.2.0, sourced from TLS BR SC-081",
    /// );
    ///
    /// // Runtime-constructed version — e.g., read from config
    /// let lints2: Vec<Box<dyn pkix_lint::Lint>> = vec![];
    /// let ver = format!("my-bundle v{}", env!("CARGO_PKG_VERSION"));
    /// let runner2 = LintRunner::with_bundle_version(lints2, ver);
    /// ```
    ///
    /// # Panics
    ///
    /// Same duplicate-ID precondition as [`LintRunner::new`].
    #[must_use]
    pub fn with_bundle_version(
        lints: Vec<Box<dyn Lint>>,
        version: impl Into<std::borrow::Cow<'static, str>>,
    ) -> Self {
        Self::check_unique_ids(&lints);
        Self {
            lints,
            bundle_version: version.into(),
        }
    }

    /// Return a reference to the registered lints.
    #[must_use]
    pub fn lints(&self) -> &[Box<dyn Lint>] {
        &self.lints
    }

    /// Return the bundle version string set on this runner.
    #[must_use]
    pub fn bundle_version(&self) -> &str {
        &self.bundle_version
    }

    /// Return a new `LintRunner` containing only the lints whose
    /// [`Lint::id`] appears in `ids`, in the order `ids` lists them.
    ///
    /// This is the consumer half of the OSCAL Catalog round-trip
    /// introduced in PKIX-9vnx.6.3: a caller emits a Catalog via
    /// [`crate::oscal::catalog::catalog_from_lints`], serializes it to
    /// JSON, parses the JSON back, extracts the ids via
    /// [`crate::oscal::parse::lint_ids_from_catalog`], and reconstructs
    /// an equivalent runner with `filter_to_ids`. Running both runners
    /// on the same chain produces identical [`Finding`] sets — that is
    /// the closure the round-trip test pins.
    ///
    /// `bundle_version` is preserved unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`crate::oscal::parse::ParseError::UnknownLintId`] on the
    /// first id in `ids` that does not match any registered lint. The
    /// caller is responsible for catching this when the Catalog and the
    /// registered lint set are not in sync (e.g., a Catalog was emitted
    /// from a newer pkix-lint with a lint that does not exist in the
    /// current runner's set).
    ///
    /// Lints whose id is registered but not present in `ids` are
    /// silently dropped — that is the intended filter semantic.
    #[cfg(feature = "oscal")]
    #[cfg_attr(docsrs, doc(cfg(feature = "oscal")))]
    pub fn filter_to_ids(
        self,
        ids: &[String],
    ) -> Result<LintRunner, crate::oscal::parse::ParseError> {
        // Index by id for O(1) lookup. We extract into Option<Box<dyn Lint>>
        // so we can take each lint out exactly once, preserving the original
        // Vec's ownership without cloning Box<dyn Lint> (which is not Clone
        // in general).
        let mut by_id: std::collections::HashMap<&'static str, Option<Box<dyn Lint>>> =
            std::collections::HashMap::with_capacity(self.lints.len());
        for lint in self.lints {
            by_id.insert(lint.id(), Some(lint));
        }

        let mut filtered: Vec<Box<dyn Lint>> = Vec::with_capacity(ids.len());
        for id in ids {
            // Match against the registered id set first: lifetime juggling
            // — `by_id` keys are &'static str but `id` is a runtime String,
            // so we lift the lookup through the borrow.
            let key = by_id
                .keys()
                .copied()
                .find(|k| *k == id.as_str())
                .ok_or_else(|| crate::oscal::parse::ParseError::UnknownLintId { id: id.clone() })?;
            // `take` returns the lint exactly once; subsequent duplicates
            // in `ids` would silently get None — we treat that as "drop"
            // since OSCAL Catalogs forbid duplicate Control ids anyway.
            if let Some(lint) = by_id.get_mut(key).and_then(|slot| slot.take()) {
                filtered.push(lint);
            }
        }

        Ok(LintRunner {
            lints: filtered,
            bundle_version: self.bundle_version,
        })
    }

    /// Apply OSCAL Profile `modify.set-parameters` overrides to the
    /// registered lints in place.
    ///
    /// `overrides` is the list produced by
    /// [`crate::oscal::profile::resolve_profile`]. Each entry's
    /// [`crate::oscal::profile::ParameterOverride::param_id`] is the
    /// composite id emitted by
    /// [`crate::oscal::catalog::catalog_from_lints`] in the form
    /// `<lint_id>.<param_id>`. This method matches each composite id
    /// against the set of registered lints using **longest-prefix
    /// matching**: for each override, the registered lint whose
    /// [`Lint::id`] is the longest prefix of `param_id` followed by `.`
    /// owns the override; the remainder after the matched prefix and
    /// dot is the unqualified parameter id passed to
    /// [`Lint::set_parameter`]. This correctly handles lint ids
    /// containing dots (`rfc5280.cert.serial_number.max_octets`) AND
    /// parameter ids containing dots (`thresholds.warn`); the
    /// resolution depends only on the registered lints, not on a
    /// fixed convention about which side may contain dots.
    ///
    /// Longest-prefix matching disambiguates the (rare) case where one
    /// registered lint's id is a strict prefix of another. Operators
    /// are still expected to keep lint ids globally unique, but the
    /// resolution rule is well-defined when prefixes overlap.
    ///
    /// Overrides are applied in the order supplied. For composed
    /// Profiles where inner and outer layers both target the same
    /// parameter, [`crate::oscal::profile::resolve_profile`] orders
    /// inner overrides first; the outer Profile's value takes effect
    /// because it is applied last.
    ///
    /// Composite param ids that contain no `.` separator, or whose
    /// prefix does not match any registered lint id, are rejected as
    /// [`crate::oscal::parse::ParseError::UnknownParameterOverride`].
    ///
    /// # Errors
    ///
    /// * [`crate::oscal::parse::ParseError::UnknownParameterOverride`]
    ///   on the first override whose composite id has no matching
    ///   registered lint. **All `UnknownParameterOverride` errors are
    ///   surfaced before any mutation is applied** — the method
    ///   resolves every override to a `(lint_index, param_id)` pair
    ///   first and fails fast if any cannot be resolved.
    /// * [`crate::oscal::parse::ParseError::InvalidParameterOverride`]
    ///   when the matched lint's
    ///   [`Lint::set_parameter`] rejects the value (wrapping the
    ///   underlying [`ParameterError`]).
    ///
    /// **Atomic on either error variant** (PKIX-hy2e.6): the method
    /// clones every affected lint, applies `set_parameter` to the
    /// clones, and swaps the clones into the runner only after every
    /// override has succeeded. On any error the runner state is
    /// unchanged. The clone is via the [`LintClone`] supertrait
    /// (blanket-impl-ed for every `Lint + Clone + 'static`).
    #[cfg(feature = "oscal")]
    #[cfg_attr(docsrs, doc(cfg(feature = "oscal")))]
    pub fn apply_parameter_overrides(
        &mut self,
        overrides: &[crate::oscal::profile::ParameterOverride],
    ) -> Result<(), crate::oscal::parse::ParseError> {
        // Phase 1: resolve every override to (lint_index, param_id).
        // Fail fast on any UnknownParameterOverride before touching any
        // lint state. Phase 2 below then provides atomic application
        // on InvalidParameterOverride as well via clone-and-swap.
        let mut resolved: Vec<(usize, &str, &crate::oscal::profile::ParameterOverride)> =
            Vec::with_capacity(overrides.len());
        for over in overrides {
            let (lint_index, param_id) = self
                .lints
                .iter()
                .enumerate()
                .filter_map(|(i, l)| {
                    let lint_id = l.id();
                    over.param_id
                        .strip_prefix(lint_id)
                        .and_then(|rest| rest.strip_prefix('.'))
                        .map(|param_id| (i, lint_id.len(), param_id))
                })
                // Longest-prefix match wins. Stable order across calls
                // because iter().enumerate() walks lints in registration
                // order.
                .max_by_key(|(_, prefix_len, _)| *prefix_len)
                .map(|(i, _, param_id)| (i, param_id))
                .ok_or_else(|| crate::oscal::parse::ParseError::UnknownParameterOverride {
                    param_id: over.param_id.clone(),
                })?;
            resolved.push((lint_index, param_id, over));
        }

        // Phase 2: clone-and-swap atomicity (PKIX-hy2e.6). Clone every
        // lint that any override targets, apply set_parameter on the
        // clones, and only commit on full success. Lints not targeted
        // by any override are left untouched.
        //
        // Memory cost: O(distinct_lint_indices) clones, which is at
        // most O(overrides.len()). For realistic OSCAL Profile sizes
        // this is single-digit megabytes worst-case (lints carry a
        // few hundred bytes of state each); for the typical few-
        // override case it is a handful of small clones.
        use std::collections::BTreeMap;
        let mut clones: BTreeMap<usize, Box<dyn Lint>> = BTreeMap::new();
        for (lint_index, param_id, over) in resolved {
            let clone = clones
                .entry(lint_index)
                .or_insert_with(|| self.lints[lint_index].clone_box());
            clone.set_parameter(param_id, &over.value).map_err(
                |source| crate::oscal::parse::ParseError::InvalidParameterOverride {
                    param_id: over.param_id.clone(),
                    source,
                },
            )?;
        }

        // All clones accepted every set_parameter call. Commit by
        // swapping each clone into the registered slot.
        for (lint_index, clone) in clones {
            self.lints[lint_index] = clone;
        }
        Ok(())
    }

    /// Evaluate all certificate-scope lints against `cert`.
    ///
    /// `kind` is the position of this certificate in the chain (leaf, intermediate, etc.).
    /// `now_unix` is the evaluation time (seconds since Unix epoch).
    ///
    /// # Evaluation modes
    ///
    /// Pass the **issuance time** (`cert.tbs_certificate.validity.not_before`) for
    /// audit-mode evaluation: "was this cert compliant when it was issued?"
    ///
    /// Pass the **current time** for operational-mode evaluation: "is this cert
    /// compliant under current rules?"
    ///
    /// Use [`LintRunner::run_cert_at_issuance`] as a convenience wrapper for audit mode.
    ///
    /// Both modes are valid and different — lints with effective dates (e.g., SC-081
    /// validity caps) produce different results depending on which mode is used.
    ///
    /// Lints whose `scope()` is not [`Scope::Certificate`] are skipped entirely
    /// (no finding recorded). Lints in scope but whose `applies_to()` does not
    /// match `kind` produce a [`LintResult::NotApplicable`] finding recorded for
    /// audit completeness.
    ///
    /// Evaluation stops early if any lint returns `Fatal`.
    #[must_use]
    pub fn run_cert(
        &self,
        cert: &Certificate,
        kind: SubjectKind,
        cert_index: usize,
        now_unix: u64,
    ) -> Vec<Finding> {
        // Compute the cert hash once per run_cert call, regardless of how
        // many lints fire on it. SHA-256 of the DER re-encoding is the
        // canonical provenance field for evidence packs (PKIX-a86q).
        // `cert_sha256_of` returns `None` if the cert fails to re-encode;
        // in that case the finding records "provenance unavailable" rather
        // than stamping a misleading hash.
        let cert_sha256 = cert_sha256_of(cert);
        let mut findings = Vec::new();
        for lint in &self.lints {
            if lint.scope() != Scope::Certificate {
                continue;
            }
            let result = if kind.matches(lint.applies_to()) {
                lint.check_cert(cert, kind, now_unix)
            } else {
                LintResult::NotApplicable
            };
            let is_fatal = result.is_fatal();
            findings.push(Finding {
                lint_id: std::borrow::Cow::Borrowed(lint.id()),
                citation: std::borrow::Cow::Borrowed(lint.citation()),
                rule_bundle_version: self.bundle_version.clone(),
                result,
                cert_index: Some(cert_index),
                evaluated_at_unix: now_unix,
                cert_sha256,
            });
            if is_fatal {
                break;
            }
        }
        findings
    }

    /// Evaluate certificate-scope lints as of the certificate's issuance time.
    ///
    /// Convenience wrapper for **audit mode**: extracts `notBefore` from the cert
    /// and passes it as `now_unix` to `run_cert`. This answers: "was this cert
    /// compliant when it was issued?"
    ///
    /// For operational mode ("is it compliant under current rules?"), call `run_cert`
    /// directly with the current time.
    ///
    /// See `run_cert` for full documentation on evaluation modes.
    #[must_use]
    pub fn run_cert_at_issuance(
        &self,
        cert: &Certificate,
        kind: SubjectKind,
        cert_index: usize,
    ) -> Vec<Finding> {
        let issuance_unix = cert
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs();
        self.run_cert(cert, kind, cert_index, issuance_unix)
    }

    /// Evaluate all certificate-scope lints against every certificate in `chain`.
    ///
    /// `kinds` maps chain index to [`SubjectKind`] and MUST have the
    /// same length as `chain`. Each `kinds[i]` is the classification
    /// for `chain[i]`.
    ///
    /// Returns a flat `Vec<Finding>` with `cert_index` set for each.
    ///
    /// # Panics
    ///
    /// Panics if `kinds.len() != chain.len()`. Earlier versions
    /// silently defaulted missing entries to
    /// [`SubjectKind::IntermediateCa`], which produced a class of audit
    /// hazards: a leaf-only lint silently returned `NotApplicable` on
    /// what was actually a leaf cert, and the compliance report
    /// looked clean until manual inspection found the misclassification.
    /// The PKIX-7f92.9 review concluded that a truncated kinds slice is
    /// almost certainly a caller bug, never a deliberate API use; the
    /// runner now fails loudly instead.
    ///
    /// # Determining the `AnchorIssued` position
    ///
    /// The `AnchorIssued` certificate is the one directly signed by the trust anchor —
    /// typically the last certificate in the chain before the anchor itself (i.e., the
    /// highest-index intermediate, `chain[chain.len() - 1]`).
    ///
    /// Callers are responsible for identifying this position and passing
    /// [`SubjectKind::AnchorIssued`] in `kinds`. The runner has no access to trust
    /// anchor information and cannot determine this automatically.
    ///
    /// To identify it: the anchor-issued cert is the one whose issuer DN matches a
    /// trust anchor's subject. Check via `pkix_path::names_match(cert.tbs_certificate.issuer,
    /// anchor.subject)` for each anchor in your trust store.
    ///
    /// # Fatal behavior across certificates
    ///
    /// Note: [`LintResult::Fatal`] stops lint evaluation for the *current certificate
    /// only*. Subsequent certificates in the chain continue to be evaluated.
    #[must_use]
    pub fn run_chain(
        &self,
        chain: &[Certificate],
        kinds: &[SubjectKind],
        now_unix: u64,
    ) -> Vec<Finding> {
        assert_eq!(
            kinds.len(),
            chain.len(),
            "LintRunner::run_chain requires kinds.len() == chain.len() \
             (got kinds={}, chain={}); see PKIX-7f92.9. A shorter `kinds` \
             slice is treated as a caller bug — provide an explicit \
             SubjectKind for every certificate.",
            kinds.len(),
            chain.len(),
        );
        let mut all = Vec::new();
        for (i, cert) in chain.iter().enumerate() {
            let kind = kinds[i];
            all.extend(self.run_cert(cert, kind, i, now_unix));
        }
        all
    }

    /// Evaluate all path-scope lints against the full validated path.
    ///
    /// `chain` must be the same slice passed to `pkix_path::validate_path`.
    /// `path` is the [`ValidatedPath`] returned by that call.
    ///
    /// Evaluation stops early if any lint returns `Fatal`.
    #[must_use]
    pub fn run_path(
        &self,
        chain: &[Certificate],
        path: &ValidatedPath,
        now_unix: u64,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        for lint in &self.lints {
            if lint.scope() != Scope::Path {
                continue;
            }
            let result = lint.check_path(chain, path, now_unix);
            let is_fatal = result.is_fatal();
            findings.push(Finding {
                lint_id: std::borrow::Cow::Borrowed(lint.id()),
                citation: std::borrow::Cow::Borrowed(lint.citation()),
                rule_bundle_version: self.bundle_version.clone(),
                result,
                cert_index: None,
                evaluated_at_unix: now_unix,
                // Path-scope findings have no single triggering cert. The
                // chain as a whole is the subject; downstream consumers
                // typically pair this finding with the path's
                // `chain_certs_sha256` summary rather than a single hash.
                cert_sha256: None,
            });
            if is_fatal {
                break;
            }
        }
        findings
    }
}

// ---------------------------------------------------------------------------
// LintProfile trait
// ---------------------------------------------------------------------------

/// A [`Profile`] that also bundles a set of lints.
///
/// This is the integration point between profile policy and the lint engine.
/// Implement `LintProfile` on a type that already implements [`Profile`] to
/// associate a set of lints with the profile.
///
/// # Why not on `Profile` directly?
///
/// Adding `lints()` to [`pkix_path::Profile`] would create a mandatory dep on
/// `pkix-lint` from `pkix-path`. That would violate `pkix-path`'s `no_std`
/// boundary and force the lint engine into every profile consumer.
/// `LintProfile` is a separate trait in `pkix-lint` that callers opt into.
pub trait LintProfile: Profile {
    /// Return the lints that this profile enforces.
    ///
    /// The returned slice owns `Box<dyn Lint>` values. The runner uses them
    /// directly — no cloning needed.
    fn lints(&self) -> &[Box<dyn Lint>];

    /// Convenience: produce a [`LintRunner`] from this profile's lints.
    ///
    /// Implementors should document whether this method caches the runner or
    /// allocates fresh on each call. Callers that invoke this repeatedly should
    /// cache the returned [`LintRunner`] themselves.
    #[must_use]
    fn lint_runner(&self) -> LintRunner;
}

// ---------------------------------------------------------------------------
// check_shape — single-cert convenience over the lint engine
// ---------------------------------------------------------------------------

/// Run the certificate-scope lints of `profile` against `cert` and report
/// pass/fail without walking a chain or verifying signatures.
///
/// This is a fast single-cert convenience over the lint engine. It sits
/// between [`pkix_path::validate_path`] (the path-validation gate) and
/// [`crate::oscal::emit::assessment_results`] (compliance assertion).
///
/// # Layered semantics
///
/// | Layer | Use case | Cost |
/// |-------|----------|------|
/// | `check_shape` (this fn) | Single cert, structural sanity. \"Is this a sanely-shaped X cert?\" | O(number of lints), microseconds |
/// | [`pkix_path::validate_path`] | Full chain, RFC 5280 §6 path validation including signature checks | O(chain length × verifier cost), milliseconds |
/// | [`crate::oscal::emit::assessment_results`] | OSCAL Assessment Results JSON for compliance audit | Per-finding serialisation cost |
///
/// # Contract
///
/// * Returns `Ok(())` when no [`LintResult::Error`] or [`LintResult::Fatal`]
///   findings are produced.
/// * Returns `Err(findings)` with the **complete** `Vec<Finding>` from
///   [`LintRunner::run_cert`] otherwise. The returned list may include
///   [`LintResult::Warn`], [`LintResult::Pass`], and
///   [`LintResult::NotApplicable`] findings alongside the failing ones —
///   callers can filter as they need.
///
/// Findings on `Warn`-only certs are silently discarded by `check_shape`
/// (the `Ok` variant carries no findings). Callers that need access to
/// `Warn`-level findings even on pass should call [`LintRunner::run_cert`]
/// directly via `profile.lint_runner()`.
///
/// # Parameters
///
/// * `cert` — the parsed certificate under scrutiny.
/// * `kind` — the certificate's role ([`SubjectKind::Leaf`] for an end-entity
///   shape check; [`SubjectKind::IntermediateCa`] for an intermediate). Lints
///   whose [`Lint::applies_to`] does not match record
///   [`LintResult::NotApplicable`] (not a failure).
/// * `now_unix` — evaluation time, seconds since the Unix epoch. Lints with
///   effective dates (e.g., phased validity caps) use this; pass the
///   current time for operational-mode evaluation, or the cert's
///   `not_before` for audit-mode evaluation.
/// * `profile` — any [`LintProfile`] implementor.
///
/// # I/O and side effects
///
/// None. No chain walk, no signature verification, no file or network access.
/// Allocates one [`LintRunner`] and one `Vec<Finding>`.
#[must_use = "the returned Result reports whether the cert passed all Error/Fatal lints"]
pub fn check_shape(
    cert: &Certificate,
    kind: SubjectKind,
    now_unix: u64,
    profile: &dyn LintProfile,
) -> Result<(), Vec<Finding>> {
    let runner = profile.lint_runner();
    let findings = runner.run_cert(cert, kind, 0, now_unix);
    let failed = findings
        .iter()
        .any(|f| matches!(f.result, LintResult::Error(_) | LintResult::Fatal(_)));
    if failed {
        Err(findings)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Send + Sync compile-time assertions (AGENTS.md non-negotiable #6, PKIX-2l0v.2)
// ---------------------------------------------------------------------------

// Every load-bearing public type — results, errors, config carriers,
// runners, stores — is asserted Send+Sync at compile time. AGENTS.md
// non-negotiable #6 requires these types to admit cross-thread caching
// and batch evaluation. The const block fails the workspace build
// immediately if someone adds Rc<T>, RefCell<T>, or any non-Sync field
// to a covered type.
const _: fn() = || {
    fn _assert_send_sync<T: Send + Sync>() {}

    // Lint-engine surface
    _assert_send_sync::<Finding>();
    _assert_send_sync::<LintRunner>();
    _assert_send_sync::<LintResult>();
    _assert_send_sync::<LintParameter>();
    _assert_send_sync::<ParameterError>();

    // Deviation surface
    _assert_send_sync::<crate::deviation::Deviation>();
    _assert_send_sync::<crate::deviation::DeviationScope>();
    _assert_send_sync::<crate::deviation::DeviationStore>();
    _assert_send_sync::<crate::deviation::DeviationAddError>();
    _assert_send_sync::<crate::deviation::DeviationRunResult>();
    _assert_send_sync::<crate::deviation::DeviationRunner>();
    _assert_send_sync::<crate::deviation::ScopePropValue>();

    // Report surface
    _assert_send_sync::<crate::deviation::DeviatedFinding>();
    _assert_send_sync::<crate::report::EvaluationReport>();

    // OSCAL surface (oscal feature only — types are #[cfg]-gated).
    #[cfg(feature = "oscal")]
    _assert_send_sync::<crate::oscal::parse::ParseError>();
    #[cfg(feature = "oscal")]
    _assert_send_sync::<crate::oscal::profile::ResolvedProfile>();
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // SubjectKind::matches tests
    //
    // Oracle: the filter/subject matching rules in the SubjectKind doc comment.
    // -----------------------------------------------------------------------

    #[test]
    fn subject_kind_any_matches_all() {
        for &kind in &[
            SubjectKind::Leaf,
            SubjectKind::IntermediateCa,
            SubjectKind::AnchorIssued,
            SubjectKind::Any,
        ] {
            assert!(
                kind.matches(SubjectKind::Any),
                "{kind:?} must match filter Any"
            );
        }
    }

    #[test]
    fn subject_kind_exact_matches_self() {
        assert!(SubjectKind::Leaf.matches(SubjectKind::Leaf));
        assert!(SubjectKind::IntermediateCa.matches(SubjectKind::IntermediateCa));
        assert!(SubjectKind::AnchorIssued.matches(SubjectKind::AnchorIssued));
    }

    #[test]
    fn subject_kind_intermediate_filter_includes_anchor_issued() {
        // AnchorIssued is a sub-kind of IntermediateCa — an anchor-issued cert
        // is still a CA cert and should be checked by IntermediateCa lints.
        assert!(SubjectKind::AnchorIssued.matches(SubjectKind::IntermediateCa));
    }

    #[test]
    fn subject_kind_leaf_does_not_match_intermediate() {
        assert!(!SubjectKind::Leaf.matches(SubjectKind::IntermediateCa));
        assert!(!SubjectKind::Leaf.matches(SubjectKind::AnchorIssued));
    }

    #[test]
    fn subject_kind_intermediate_does_not_match_leaf() {
        assert!(!SubjectKind::IntermediateCa.matches(SubjectKind::Leaf));
    }

    // -----------------------------------------------------------------------
    // Severity rank stability tests
    //
    // Oracle: the rustdoc on `Severity::rank` pins the documented
    // per-variant u8 values (Info=10, Notice=20, Warn=30, Error=40,
    // Fatal=50). These ranks are part of the public API contract — a
    // caller that wrote `finding.severity.rank() >= 30` is encoding
    // "Warn or above" by rank value. Changing any rank would silently
    // break such callers.
    //
    // PKIX-7f92.24 dropped `derive(PartialOrd, Ord)` to avoid the
    // source-position-coupled comparison trap; this test now locks
    // the explicit rank values instead of the deprecated `<`-based
    // ordering check.
    // -----------------------------------------------------------------------

    #[test]
    fn severity_rank_values_are_pinned() {
        assert_eq!(Severity::Info.rank(), 10);
        assert_eq!(Severity::Notice.rank(), 20);
        assert_eq!(Severity::Warn.rank(), 30);
        assert_eq!(Severity::Error.rank(), 40);
        assert_eq!(Severity::Fatal.rank(), 50);
    }

    #[test]
    fn severity_rank_ordering_is_info_notice_warn_error_fatal() {
        // Rank-based ordering must align with the documented semantic
        // hierarchy. This protects against accidental rank renumbering
        // that would invert the conceptual relation.
        assert!(Severity::Info.rank() < Severity::Notice.rank());
        assert!(Severity::Notice.rank() < Severity::Warn.rank());
        assert!(Severity::Warn.rank() < Severity::Error.rank());
        assert!(Severity::Error.rank() < Severity::Fatal.rank());
    }

    // -----------------------------------------------------------------------
    // LintResult helper method tests
    //
    // Oracle: the LintResult variant semantics in the doc comments.
    // -----------------------------------------------------------------------

    #[test]
    fn lint_result_pass_is_pass() {
        assert!(LintResult::Pass.is_pass());
        assert!(!LintResult::Pass.is_finding());
        assert!(!LintResult::Pass.is_fatal());
        assert_eq!(LintResult::Pass.detail(), None);
    }

    #[test]
    fn lint_result_not_applicable_is_not_pass_not_finding() {
        assert!(!LintResult::NotApplicable.is_pass());
        assert!(!LintResult::NotApplicable.is_finding());
        assert_eq!(LintResult::NotApplicable.detail(), None);
    }

    #[test]
    fn lint_result_warn_is_finding() {
        let r = LintResult::warn("test warning");
        assert!(!r.is_pass());
        assert!(r.is_finding());
        assert!(!r.is_fatal());
        assert_eq!(r.detail(), Some("test warning"));
    }

    #[test]
    fn lint_result_error_is_finding() {
        let r = LintResult::error("test error");
        assert!(!r.is_pass());
        assert!(r.is_finding());
        assert!(!r.is_fatal());
        assert_eq!(r.detail(), Some("test error"));
    }

    #[test]
    fn lint_result_fatal_is_fatal_and_finding() {
        let r = LintResult::fatal("fatal error");
        assert!(!r.is_pass());
        assert!(r.is_finding());
        assert!(r.is_fatal());
        assert_eq!(r.detail(), Some("fatal error"));
    }

    // -----------------------------------------------------------------------
    // LintRunner tests using a trivial in-test Lint implementation
    //
    // Oracle: the runner contract defined in LintRunner doc comments.
    // The test lints are independent oracles — they do not call other lints or
    // validate against the code under test.
    // -----------------------------------------------------------------------

    /// A lint that always passes, used to verify the runner records Pass findings.
    #[derive(Clone)]
    struct AlwaysPass;
    impl Lint for AlwaysPass {
        fn id(&self) -> &'static str {
            "test.always_pass"
        }
        fn citation(&self) -> &'static str {
            "test"
        }
        fn severity(&self) -> Severity {
            Severity::Info
        }
        fn scope(&self) -> Scope {
            Scope::Certificate
        }
        fn applies_to(&self) -> SubjectKind {
            SubjectKind::Any
        }
        fn check_cert(&self, _cert: &Certificate, _kind: SubjectKind, _now: u64) -> LintResult {
            LintResult::Pass
        }
    }

    /// A lint that always warns, used to verify runner records Warn findings.
    #[derive(Clone)]
    struct AlwaysWarn;
    impl Lint for AlwaysWarn {
        fn id(&self) -> &'static str {
            "test.always_warn"
        }
        fn citation(&self) -> &'static str {
            "test"
        }
        fn severity(&self) -> Severity {
            Severity::Warn
        }
        fn scope(&self) -> Scope {
            Scope::Certificate
        }
        fn applies_to(&self) -> SubjectKind {
            SubjectKind::Any
        }
        fn check_cert(&self, _cert: &Certificate, _kind: SubjectKind, _now: u64) -> LintResult {
            LintResult::warn("always warns")
        }
    }

    /// A lint that always returns Fatal, used to test early-exit behavior.
    #[derive(Clone)]
    struct AlwaysFatal;
    impl Lint for AlwaysFatal {
        fn id(&self) -> &'static str {
            "test.always_fatal"
        }
        fn citation(&self) -> &'static str {
            "test"
        }
        fn severity(&self) -> Severity {
            Severity::Fatal
        }
        fn scope(&self) -> Scope {
            Scope::Certificate
        }
        fn applies_to(&self) -> SubjectKind {
            SubjectKind::Any
        }
        fn check_cert(&self, _cert: &Certificate, _kind: SubjectKind, _now: u64) -> LintResult {
            LintResult::fatal("always fatal")
        }
    }

    /// A lint scoped to leaves only, used to verify kind filtering.
    #[derive(Clone)]
    struct LeafOnlyLint;
    impl Lint for LeafOnlyLint {
        fn id(&self) -> &'static str {
            "test.leaf_only"
        }
        fn citation(&self) -> &'static str {
            "test"
        }
        fn severity(&self) -> Severity {
            Severity::Warn
        }
        fn scope(&self) -> Scope {
            Scope::Certificate
        }
        fn applies_to(&self) -> SubjectKind {
            SubjectKind::Leaf
        }
        fn check_cert(&self, _cert: &Certificate, _kind: SubjectKind, _now: u64) -> LintResult {
            LintResult::warn("leaf lint fires")
        }
    }

    /// A path-scope lint, used to verify `run_path`.
    #[derive(Clone)]
    struct PathDepthLint;
    impl Lint for PathDepthLint {
        fn id(&self) -> &'static str {
            "test.path_depth"
        }
        fn citation(&self) -> &'static str {
            "test"
        }
        fn severity(&self) -> Severity {
            Severity::Warn
        }
        fn scope(&self) -> Scope {
            Scope::Path
        }
        fn applies_to(&self) -> SubjectKind {
            SubjectKind::Any
        }
        fn check_path(
            &self,
            _chain: &[Certificate],
            path: &ValidatedPath,
            _now: u64,
        ) -> LintResult {
            if path.depth > 5 {
                LintResult::warn("chain depth exceeds 5")
            } else {
                LintResult::Pass
            }
        }
    }

    // We need a minimal Certificate to call run_cert. Load from a real fixture.
    fn load_fixture_cert() -> Certificate {
        use der::Decode as _;
        Certificate::from_der(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/webpki-self-signed-365d.der"
        ))
        .expect("fixture is valid DER")
    }

    #[test]
    fn runner_records_pass_finding() {
        let cert = load_fixture_cert();
        let runner = LintRunner::new(vec![Box::new(AlwaysPass)]);
        let findings = runner.run_cert(&cert, SubjectKind::Leaf, 0, 0);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].lint_id, "test.always_pass");
        assert_eq!(findings[0].result, LintResult::Pass);
        assert_eq!(findings[0].cert_index, Some(0));
    }

    #[test]
    fn runner_records_warn_finding() {
        let cert = load_fixture_cert();
        let runner = LintRunner::new(vec![Box::new(AlwaysWarn)]);
        let findings = runner.run_cert(&cert, SubjectKind::Leaf, 0, 0);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].lint_id, "test.always_warn");
        assert!(matches!(findings[0].result, LintResult::Warn(_)));
        assert!(findings[0].is_finding());
    }

    #[test]
    fn runner_stops_after_fatal() {
        // Fatal lint followed by another lint — the second must NOT be evaluated.
        let cert = load_fixture_cert();
        let runner = LintRunner::new(vec![
            Box::new(AlwaysFatal),
            Box::new(AlwaysWarn), // must not appear in findings
        ]);
        let findings = runner.run_cert(&cert, SubjectKind::Leaf, 0, 0);
        // Only one finding: the fatal. The warn is never reached.
        assert_eq!(findings.len(), 1, "runner must stop after Fatal");
        assert_eq!(findings[0].lint_id, "test.always_fatal");
        assert!(findings[0].result.is_fatal());
    }

    #[test]
    fn runner_skips_non_applicable_scope_kind() {
        // LeafOnlyLint declares applies_to = Leaf.
        // Running it against IntermediateCa must return NotApplicable, not Warn.
        let cert = load_fixture_cert();
        let runner = LintRunner::new(vec![Box::new(LeafOnlyLint)]);
        let findings = runner.run_cert(&cert, SubjectKind::IntermediateCa, 1, 0);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].result, LintResult::NotApplicable);
    }

    #[test]
    fn runner_applies_leaf_lint_to_leaf() {
        let cert = load_fixture_cert();
        let runner = LintRunner::new(vec![Box::new(LeafOnlyLint)]);
        let findings = runner.run_cert(&cert, SubjectKind::Leaf, 0, 0);
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].result, LintResult::Warn(_)));
    }

    fn validated_path_for_self_signed() -> (Vec<Certificate>, ValidatedPath) {
        use pkix_path::{EcdsaP256Verifier, TrustAnchor, ValidationPolicy};
        let cert = load_fixture_cert();
        let anchor = TrustAnchor::from_cert(cert.clone());
        // 2026-01-01 = pre-SC-081, so 365-day cert passes the 398-day cap.
        let policy = ValidationPolicy::new(1_767_225_600);
        let path = pkix_path::validate_path(
            std::slice::from_ref(&cert),
            &[anchor],
            &policy,
            &EcdsaP256Verifier,
        )
        .expect("fixture cert must validate");
        (vec![cert], path)
    }

    #[test]
    fn runner_skips_cert_lints_in_run_path() {
        // AlwaysWarn is a Certificate-scope lint; run_path must not invoke it.
        let (chain, path) = validated_path_for_self_signed();
        let runner = LintRunner::new(vec![Box::new(AlwaysWarn)]);
        let findings = runner.run_path(&chain, &path, 0);
        assert!(
            findings.is_empty(),
            "run_path must not invoke Certificate-scope lints"
        );
    }

    #[test]
    fn runner_invokes_path_lint_in_run_path() {
        let (chain, path) = validated_path_for_self_signed();
        let runner = LintRunner::new(vec![Box::new(PathDepthLint)]);
        let findings = runner.run_path(&chain, &path, 0);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].lint_id, "test.path_depth");
        // Self-signed chain: depth=0, not > 5 → Pass.
        assert_eq!(findings[0].result, LintResult::Pass);
        assert_eq!(
            findings[0].cert_index, None,
            "path findings have no cert_index"
        );
    }

    #[test]
    fn runner_run_chain_sets_cert_index() {
        let cert = load_fixture_cert();
        let chain = vec![cert.clone(), cert.clone(), cert];
        let kinds = vec![
            SubjectKind::Leaf,
            SubjectKind::IntermediateCa,
            SubjectKind::AnchorIssued,
        ];
        let runner = LintRunner::new(vec![Box::new(AlwaysPass)]);
        let findings = runner.run_chain(&chain, &kinds, 0);
        // One Pass finding per cert.
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].cert_index, Some(0));
        assert_eq!(findings[1].cert_index, Some(1));
        assert_eq!(findings[2].cert_index, Some(2));
    }

    /// Regression test for PKIX-7f92.9: passing a kinds slice shorter
    /// than the chain must panic with a message naming the lengths.
    /// Regression test for PKIX-7f92.7: a Lint impl that overrides only
    /// the deprecated `rfc_section_id` (pre-0.6.0 style) must still
    /// produce a non-None value through the canonical `spec_section_id`
    /// entry point. The delegation in the default `spec_section_id`
    /// impl is what closes the silent-divergence hazard.
    #[test]
    fn spec_section_id_default_delegates_to_deprecated_rfc_section_id_override() {
        #[derive(Clone)]
        struct PreV06Lint;
        #[allow(deprecated)]
        impl Lint for PreV06Lint {
            fn id(&self) -> &'static str { "test.pre-v06" }
            fn citation(&self) -> &'static str { "RFC 5280 §X.Y" }
            fn severity(&self) -> Severity { Severity::Warn }
            fn scope(&self) -> Scope { Scope::Certificate }
            fn applies_to(&self) -> SubjectKind { SubjectKind::Any }
            fn title(&self) -> &str { "Pre-v06 lint" }
            // Only the deprecated method is overridden — the 0.5.x shape.
            fn rfc_section_id(&self) -> Option<&str> { Some("rfc5280-x.y") }
            fn rfc_url(&self) -> Option<&str> { Some("https://example/x.y") }
            fn check_cert(&self, _: &Certificate, _: SubjectKind, _: u64) -> LintResult {
                LintResult::Pass
            }
        }
        let l = PreV06Lint;
        // Canonical entry points return the delegated values, NOT None.
        assert_eq!(l.spec_section_id(), Some("rfc5280-x.y"));
        assert_eq!(l.spec_url(), Some("https://example/x.y"));
    }

    /// Symmetric case: a 0.6.0+ Lint impl that overrides only the new
    /// canonical methods. The deprecated alias returns None (default)
    /// because it cannot delegate back without infinite recursion;
    /// callers calling the deprecated alias must have migrated.
    #[test]
    fn deprecated_rfc_section_id_returns_none_for_v06_impl_overriding_canonical() {
        #[derive(Clone)]
        struct V06Lint;
        impl Lint for V06Lint {
            fn id(&self) -> &'static str { "test.v06" }
            fn citation(&self) -> &'static str { "RFC 5280 §X.Y" }
            fn severity(&self) -> Severity { Severity::Warn }
            fn scope(&self) -> Scope { Scope::Certificate }
            fn applies_to(&self) -> SubjectKind { SubjectKind::Any }
            fn title(&self) -> &str { "v06 lint" }
            // Only the canonical method is overridden — the 0.6.0+ shape.
            fn spec_section_id(&self) -> Option<&str> { Some("rfc5280-x.y") }
            fn spec_url(&self) -> Option<&str> { Some("https://example/x.y") }
            fn check_cert(&self, _: &Certificate, _: SubjectKind, _: u64) -> LintResult {
                LintResult::Pass
            }
        }
        let l = V06Lint;
        assert_eq!(l.spec_section_id(), Some("rfc5280-x.y"));
        // The deprecated alias returns None — calling it on a v0.6.0+ impl
        // is the migration-incomplete state the rustdoc documents.
        #[allow(deprecated)]
        let deprecated_value = l.rfc_section_id();
        assert_eq!(deprecated_value, None);
        #[allow(deprecated)]
        let deprecated_url = l.rfc_url();
        assert_eq!(deprecated_url, None);
    }

    /// Pre-fix, this silently defaulted missing positions to
    /// IntermediateCa, producing the silent-misclassification audit
    /// hazard the bead flagged.
    #[test]
    #[should_panic(expected = "LintRunner::run_chain requires kinds.len() == chain.len()")]
    fn runner_run_chain_panics_on_kinds_shorter_than_chain() {
        let cert = load_fixture_cert();
        let chain = vec![cert.clone(), cert.clone(), cert];
        let kinds = vec![SubjectKind::Leaf]; // intentionally short
        let runner = LintRunner::new(vec![Box::new(AlwaysPass)]);
        let _ = runner.run_chain(&chain, &kinds, 0);
    }

    #[test]
    #[should_panic(expected = "LintRunner::run_chain requires kinds.len() == chain.len()")]
    fn runner_run_chain_panics_on_kinds_longer_than_chain() {
        let cert = load_fixture_cert();
        let chain = vec![cert.clone()];
        let kinds = vec![SubjectKind::Leaf, SubjectKind::IntermediateCa];
        let runner = LintRunner::new(vec![Box::new(AlwaysPass)]);
        let _ = runner.run_chain(&chain, &kinds, 0);
    }

    #[test]
    fn run_cert_stamps_cert_sha256_on_findings() {
        // Oracle: sha2 is the canonical SHA-256 implementation. Compute the
        // expected hash directly from the cert DER outside the lint engine,
        // then compare against the value stamped on the finding. This
        // avoids the "test the code with itself" anti-pattern.
        use der::Encode as _;
        use sha2::Digest as _;

        let cert = load_fixture_cert();
        let der = cert.to_der().expect("encode fixture cert");
        let expected: [u8; 32] = sha2::Sha256::digest(&der).into();

        let runner = LintRunner::new(vec![Box::new(AlwaysPass)]);
        let findings = runner.run_cert(&cert, SubjectKind::Leaf, 0, 0);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].cert_sha256,
            Some(expected),
            "run_cert must stamp SHA-256(DER) on every finding"
        );
    }

    #[test]
    fn run_chain_stamps_per_cert_sha256_on_each_finding() {
        // Oracle: three findings, three identical cert_sha256 values (same
        // fixture cert used at every position). Tests that run_chain re-
        // computes the hash per position rather than caching one across.
        let cert = load_fixture_cert();
        let chain = vec![cert.clone(), cert.clone(), cert];
        let kinds = vec![
            SubjectKind::Leaf,
            SubjectKind::IntermediateCa,
            SubjectKind::AnchorIssued,
        ];
        let runner = LintRunner::new(vec![Box::new(AlwaysPass)]);
        let findings = runner.run_chain(&chain, &kinds, 0);
        assert_eq!(findings.len(), 3);
        assert!(
            findings[0].cert_sha256.is_some(),
            "leaf finding must carry cert_sha256"
        );
        assert_eq!(
            findings[0].cert_sha256, findings[1].cert_sha256,
            "same cert at index 0 and 1 must produce the same hash"
        );
        assert_eq!(
            findings[1].cert_sha256, findings[2].cert_sha256,
            "same cert at index 1 and 2 must produce the same hash"
        );
    }

    #[test]
    fn run_path_leaves_cert_sha256_none_on_path_findings() {
        // Oracle: path-scoped findings have no single triggering cert; the
        // cert_sha256 field must be None. (Future evidence-pack consumers
        // would pair these findings with a separate per-chain hash list.)
        let (chain, path) = validated_path_for_self_signed();
        let runner = LintRunner::new(vec![Box::new(PathDepthLint)]);
        let findings = runner.run_path(&chain, &path, 0);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].cert_sha256, None,
            "path-scope findings must have cert_sha256 = None"
        );
    }

    #[test]
    #[cfg(feature = "serde")]
    fn finding_cert_sha256_serde_round_trip_some() {
        // Oracle: serializing then deserializing a Finding preserves the
        // hash exactly. Independently constructed hash via sha2.
        use sha2::Digest as _;
        let bytes: [u8; 32] = sha2::Sha256::digest(b"fixture bytes for sha256").into();
        let f = Finding {
            lint_id: std::borrow::Cow::Borrowed("x"),
            citation: std::borrow::Cow::Borrowed("c"),
            rule_bundle_version: std::borrow::Cow::Borrowed(""),
            result: LintResult::Pass,
            cert_index: Some(0),
            evaluated_at_unix: 0,
            cert_sha256: Some(bytes),
        };
        let json = serde_json::to_string(&f).expect("serialize");
        // The on-wire form must be a lowercase hex string of length 64.
        let mut expected_hex = String::with_capacity(64);
        for b in &bytes {
            expected_hex.push(char::from_digit(u32::from(b >> 4), 16).unwrap());
            expected_hex.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap());
        }
        assert!(
            json.contains(&expected_hex),
            "JSON must contain the lowercase hex hash; got: {json}"
        );
        let f2: Finding = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(f2.cert_sha256, Some(bytes));
    }

    #[test]
    #[cfg(feature = "serde")]
    fn finding_cert_sha256_serde_round_trip_none() {
        // Oracle: None serializes as JSON null and round-trips back to None.
        let f = Finding {
            lint_id: std::borrow::Cow::Borrowed("x"),
            citation: std::borrow::Cow::Borrowed("c"),
            rule_bundle_version: std::borrow::Cow::Borrowed(""),
            result: LintResult::Pass,
            cert_index: None,
            evaluated_at_unix: 0,
            cert_sha256: None,
        };
        let json = serde_json::to_string(&f).expect("serialize");
        assert!(
            json.contains("\"cert_sha256\":null"),
            "None must serialize as JSON null; got: {json}"
        );
        let f2: Finding = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(f2.cert_sha256, None);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn finding_cert_sha256_rejects_non_hex_string() {
        // Oracle: a string of 64 chars that is not all hex must fail to
        // deserialize rather than silently truncating or zero-filling.
        let bad = r#"{"lint_id":"x","citation":"c","rule_bundle_version":"","result":"Pass","cert_index":null,"evaluated_at_unix":0,"cert_sha256":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}"#;
        let err = serde_json::from_str::<Finding>(bad).expect_err("must reject non-hex chars");
        assert!(
            err.to_string().to_lowercase().contains("hex")
                || err.to_string().to_lowercase().contains("cert_sha256"),
            "error must mention hex / cert_sha256; got: {err}"
        );
    }

    #[test]
    #[cfg(feature = "serde")]
    fn finding_cert_sha256_rejects_non_ascii_multibyte_utf8() {
        // Regression test for PKIX-7f92.1: a 64-BYTE JSON string composed
        // of multi-byte UTF-8 chars passes the `hex.len() == 64` length
        // gate but earlier slicing into the &str at non-char-boundary
        // positions panicked the deserializer. Oracle: 32 copies of the
        // 2-byte UTF-8 sequence for `ü` (U+00FC = 0xC3 0xBC) = 64 bytes,
        // 32 chars. The deserializer must return a serde Error, not
        // panic, on this input.
        let payload: String = "ü".repeat(32);
        assert_eq!(payload.len(), 64, "test oracle: payload is 64 bytes");
        assert_eq!(payload.chars().count(), 32, "test oracle: payload has 32 chars");

        let json = format!(
            r#"{{"lint_id":"x","citation":"c","rule_bundle_version":"","result":"Pass","cert_index":null,"evaluated_at_unix":0,"cert_sha256":"{payload}"}}"#
        );
        let err = serde_json::from_str::<Finding>(&json)
            .expect_err("must reject multi-byte UTF-8 hex string");
        assert!(
            err.to_string().to_lowercase().contains("hex")
                || err.to_string().to_lowercase().contains("cert_sha256"),
            "error must mention hex / cert_sha256; got: {err}"
        );
    }

    #[test]
    #[cfg(feature = "serde")]
    fn finding_cert_sha256_rejects_wrong_length() {
        // Oracle: a hex string of length != 64 must fail to deserialize.
        let bad = r#"{"lint_id":"x","citation":"c","rule_bundle_version":"","result":"Pass","cert_index":null,"evaluated_at_unix":0,"cert_sha256":"abc"}"#;
        let err = serde_json::from_str::<Finding>(bad).expect_err("must reject short hex string");
        assert!(
            err.to_string().to_lowercase().contains("length")
                || err.to_string().to_lowercase().contains("64"),
            "error must mention length; got: {err}"
        );
    }

    #[test]
    fn finding_is_finding_reflects_result() {
        let f_pass = Finding {
            lint_id: std::borrow::Cow::Borrowed("x"),
            citation: std::borrow::Cow::Borrowed("test"),
            rule_bundle_version: std::borrow::Cow::Borrowed(""),
            result: LintResult::Pass,
            cert_index: None,
            evaluated_at_unix: 0,
            cert_sha256: None,
        };
        let f_warn = Finding {
            lint_id: std::borrow::Cow::Borrowed("x"),
            citation: std::borrow::Cow::Borrowed("test"),
            rule_bundle_version: std::borrow::Cow::Borrowed(""),
            result: LintResult::warn("w"),
            cert_index: None,
            evaluated_at_unix: 0,
            cert_sha256: None,
        };
        assert!(!f_pass.is_finding());
        assert!(f_warn.is_finding());
    }

    #[test]
    fn finding_citation_is_threaded_from_lint() {
        let cert = load_fixture_cert();
        let runner = LintRunner::new(vec![Box::new(AlwaysPass)]);
        let findings = runner.run_cert(&cert, SubjectKind::Leaf, 0, 12345);
        assert_eq!(findings.len(), 1);
        // Citation must come from the lint's citation() method.
        assert_eq!(
            findings[0].citation, "test",
            "citation must be threaded from Lint::citation()"
        );
        assert_eq!(
            findings[0].evaluated_at_unix, 12345,
            "evaluated_at_unix must be the passed now_unix"
        );
    }

    #[test]
    fn run_cert_at_issuance_uses_not_before() {
        let cert = load_fixture_cert();
        // Get the expected issuance time from the cert's notBefore.
        let expected_unix = cert
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs();
        let runner = LintRunner::new(vec![Box::new(AlwaysPass)]);
        let findings = runner.run_cert_at_issuance(&cert, SubjectKind::Leaf, 0);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].evaluated_at_unix, expected_unix,
            "run_cert_at_issuance must use cert notBefore as evaluated_at_unix"
        );
    }

    #[test]
    fn bundle_version_stamped_into_findings() {
        let cert = load_fixture_cert();
        let runner = LintRunner::with_bundle_version(
            vec![Box::new(AlwaysPass)],
            "pkix-lint-cabf/cabf_tls_br v0.2.0",
        );
        let findings = runner.run_cert(&cert, SubjectKind::Leaf, 0, 0);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].rule_bundle_version.as_ref(),
            "pkix-lint-cabf/cabf_tls_br v0.2.0",
            "rule_bundle_version must be stamped from runner into Finding"
        );
    }

    #[test]
    fn bundle_version_empty_by_default() {
        let cert = load_fixture_cert();
        let runner = LintRunner::new(vec![Box::new(AlwaysPass)]);
        let findings = runner.run_cert(&cert, SubjectKind::Leaf, 0, 0);
        assert_eq!(findings[0].rule_bundle_version.as_ref(), "");
    }

    // -----------------------------------------------------------------------
    // check_shape tests
    //
    // Oracle: the per-lint behaviour of AlwaysPass / AlwaysWarn / AlwaysError /
    // AlwaysFatal is fixed by their own check_cert implementations above. The
    // tests assert check_shape's Result projection: Ok when no Error / Fatal
    // findings, Err with the full Vec<Finding> otherwise.
    // -----------------------------------------------------------------------

    /// A lint that always returns Error, used to drive check_shape's Err
    /// branch without triggering the runner's Fatal early-exit (which would
    /// truncate the findings list).
    #[derive(Clone)]
    struct AlwaysError;
    impl Lint for AlwaysError {
        fn id(&self) -> &'static str {
            "test.always_error"
        }
        fn citation(&self) -> &'static str {
            "test"
        }
        fn severity(&self) -> Severity {
            Severity::Error
        }
        fn scope(&self) -> Scope {
            Scope::Certificate
        }
        fn applies_to(&self) -> SubjectKind {
            SubjectKind::Any
        }
        fn check_cert(&self, _cert: &Certificate, _kind: SubjectKind, _now: u64) -> LintResult {
            LintResult::error("always errors")
        }
    }

    /// Test-side [`LintProfile`] that bundles an arbitrary lint set behind a
    /// minimal [`pkix_path::Profile`] facade. The Profile half is a no-op
    /// stub; `check_shape` only touches the lints.
    ///
    /// The `build_runner` field is a fn-pointer factory because
    /// [`LintProfile::lint_runner`] returns a fresh [`LintRunner`] by
    /// value, but [`Box<dyn Lint>`] is not [`Clone`] and the profile must
    /// be able to hand out a runner via an immutable `&self`. The
    /// alternatives (shared `Arc<dyn Lint>`, `OnceLock<LintRunner>`)
    /// add complexity that buys nothing in tests — a fn pointer is
    /// trivially [`Copy`] and lets each test wire a specific runner
    /// builder.
    struct TestLintProfile {
        lints: Vec<Box<dyn Lint>>,
        build_runner: fn() -> LintRunner,
    }

    impl pkix_path::Profile for TestLintProfile {
        fn id(&self) -> &'static str {
            "test.profile"
        }
        fn version(&self) -> &'static str {
            "0.0.0"
        }
        fn policy(&self, _now_unix: u64) -> ValidationPolicy {
            ValidationPolicy::default()
        }
        fn policy_oids(&self) -> &[der::asn1::ObjectIdentifier] {
            &[]
        }
    }

    impl LintProfile for TestLintProfile {
        fn lints(&self) -> &[Box<dyn Lint>] {
            &self.lints
        }
        fn lint_runner(&self) -> LintRunner {
            (self.build_runner)()
        }
    }

    impl TestLintProfile {
        fn new(lints: Vec<Box<dyn Lint>>, build_runner: fn() -> LintRunner) -> Self {
            Self {
                lints,
                build_runner,
            }
        }
    }

    fn build_always_pass_runner() -> LintRunner {
        LintRunner::new(vec![Box::new(AlwaysPass)])
    }

    fn build_always_warn_runner() -> LintRunner {
        LintRunner::new(vec![Box::new(AlwaysWarn)])
    }

    fn build_always_error_runner() -> LintRunner {
        LintRunner::new(vec![Box::new(AlwaysError)])
    }

    fn build_always_fatal_runner() -> LintRunner {
        LintRunner::new(vec![Box::new(AlwaysFatal)])
    }

    fn build_pass_plus_warn_runner() -> LintRunner {
        LintRunner::new(vec![Box::new(AlwaysPass), Box::new(AlwaysWarn)])
    }

    fn build_pass_plus_error_runner() -> LintRunner {
        LintRunner::new(vec![Box::new(AlwaysPass), Box::new(AlwaysError)])
    }

    #[test]
    fn check_shape_ok_when_all_lints_pass() {
        let cert = load_fixture_cert();
        let profile = TestLintProfile::new(vec![Box::new(AlwaysPass)], build_always_pass_runner);
        assert!(check_shape(&cert, SubjectKind::Leaf, 0, &profile).is_ok());
    }

    #[test]
    fn check_shape_ok_when_only_warn_findings() {
        let cert = load_fixture_cert();
        let profile = TestLintProfile::new(vec![Box::new(AlwaysWarn)], build_always_warn_runner);
        // Warn-only must produce Ok per the contract: Warn is informational,
        // not a hard rejection. The Warn detail is silently dropped from the
        // Ok variant — callers needing it call run_cert directly.
        assert!(check_shape(&cert, SubjectKind::Leaf, 0, &profile).is_ok());
    }

    #[test]
    fn check_shape_err_on_error_finding() {
        let cert = load_fixture_cert();
        let profile = TestLintProfile::new(vec![Box::new(AlwaysError)], build_always_error_runner);
        let result = check_shape(&cert, SubjectKind::Leaf, 0, &profile);
        let findings = result.expect_err("AlwaysError must produce Err");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].lint_id, "test.always_error");
        assert!(matches!(findings[0].result, LintResult::Error(_)));
    }

    #[test]
    fn check_shape_err_on_fatal_finding() {
        let cert = load_fixture_cert();
        let profile = TestLintProfile::new(vec![Box::new(AlwaysFatal)], build_always_fatal_runner);
        let result = check_shape(&cert, SubjectKind::Leaf, 0, &profile);
        let findings = result.expect_err("AlwaysFatal must produce Err");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].lint_id, "test.always_fatal");
        assert!(findings[0].result.is_fatal());
    }

    #[test]
    fn check_shape_err_carries_all_findings_including_pass() {
        // Two lints: one Pass, one Error. Err variant must carry both
        // findings (not just the failing one) so callers can audit the full
        // evaluation result.
        let cert = load_fixture_cert();
        let profile = TestLintProfile::new(
            vec![Box::new(AlwaysPass), Box::new(AlwaysError)],
            build_pass_plus_error_runner,
        );
        let result = check_shape(&cert, SubjectKind::Leaf, 0, &profile);
        let findings = result.expect_err("any Error must produce Err");
        assert_eq!(findings.len(), 2, "Err carries the full Vec<Finding>");
        assert!(findings.iter().any(|f| f.lint_id == "test.always_pass"));
        assert!(findings.iter().any(|f| f.lint_id == "test.always_error"));
    }

    #[test]
    fn check_shape_ok_when_pass_plus_warn_no_error() {
        // Pass + Warn (no Error / Fatal) → Ok per the contract.
        let cert = load_fixture_cert();
        let profile = TestLintProfile::new(
            vec![Box::new(AlwaysPass), Box::new(AlwaysWarn)],
            build_pass_plus_warn_runner,
        );
        assert!(check_shape(&cert, SubjectKind::Leaf, 0, &profile).is_ok());
    }

    // -----------------------------------------------------------------------
    // Use-case mutual-exclusion regression — operator contract on the Lint
    // trait rustdoc (PKIX-hy2e.1 + PKIX-hy2e.4)
    //
    // The Lint trait rustdoc states that the TLS-server lints
    // (Rfc5280EkuServerAuthLint, Rfc6125TlsServerSanLint) and the S/MIME
    // lints (Rfc8398SmimeSanLint, Rfc8551EkuEmailProtectionLint) describe
    // mutually-exclusive cert shapes — no single leaf certificate
    // satisfies all four simultaneously. This test asserts the claim
    // empirically on a real fixture so the rustdoc cannot drift.
    //
    // Independent oracle: openssl x509 -text on each fixture shows EKU
    // and SAN exactly as expected. webpki-self-signed-365d.der has EKU=
    // TLS Web Server Authentication and SAN=DNS:test.example.com (TLS
    // shape). smime-self-signed-365d.der has EKU=E-mail Protection and
    // SAN=email:test@example.com (S/MIME shape).
    // -----------------------------------------------------------------------

    #[test]
    fn use_case_mutual_exclusion_tls_cert_fails_smime_lints() {
        // TLS-shaped cert: passes TLS lints, fails S/MIME lints.
        use der::Decode as _;
        let cert = Certificate::from_der(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/webpki-self-signed-365d.der"
        ))
        .expect("fixture is valid DER");
        let runner = LintRunner::new(vec![
            Box::new(crate::rfc5280::Rfc5280EkuServerAuthLint),
            Box::new(crate::rfc6125::Rfc6125TlsServerSanLint),
            Box::new(crate::rfc8398::Rfc8398SmimeSanLint),
            Box::new(crate::rfc8551::Rfc8551EkuEmailProtectionLint),
        ]);
        let findings = runner.run_cert(&cert, SubjectKind::Leaf, 0, 0);
        let errors_by_id: Vec<&str> = findings
            .iter()
            .filter(|f| matches!(f.result, LintResult::Error(_)))
            .map(|f| f.lint_id.as_ref())
            .collect();
        assert!(
            errors_by_id
                .iter()
                .any(|id| id.starts_with("rfc8398.") || id.starts_with("rfc8551.")),
            "TLS cert must produce Error findings from the S/MIME lints: \
             found error ids {errors_by_id:?}"
        );
        assert!(
            !errors_by_id
                .iter()
                .any(|id| id.starts_with("rfc5280.cert.eku.") || id.starts_with("rfc6125.")),
            "TLS cert must NOT produce Error findings from the TLS lints: \
             found error ids {errors_by_id:?}"
        );
    }

    #[test]
    fn use_case_mutual_exclusion_smime_cert_fails_tls_lints() {
        // S/MIME-shaped cert: passes S/MIME lints, fails TLS lints.
        use der::Decode as _;
        let cert = Certificate::from_der(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/smime-self-signed-365d.der"
        ))
        .expect("fixture is valid DER");
        let runner = LintRunner::new(vec![
            Box::new(crate::rfc5280::Rfc5280EkuServerAuthLint),
            Box::new(crate::rfc6125::Rfc6125TlsServerSanLint),
            Box::new(crate::rfc8398::Rfc8398SmimeSanLint),
            Box::new(crate::rfc8551::Rfc8551EkuEmailProtectionLint),
        ]);
        let findings = runner.run_cert(&cert, SubjectKind::Leaf, 0, 0);
        let errors_by_id: Vec<&str> = findings
            .iter()
            .filter(|f| matches!(f.result, LintResult::Error(_)))
            .map(|f| f.lint_id.as_ref())
            .collect();
        assert!(
            errors_by_id
                .iter()
                .any(|id| id.starts_with("rfc5280.cert.eku.") || id.starts_with("rfc6125.")),
            "S/MIME cert must produce Error findings from the TLS lints: \
             found error ids {errors_by_id:?}"
        );
        assert!(
            !errors_by_id
                .iter()
                .any(|id| id.starts_with("rfc8398.") || id.starts_with("rfc8551.")),
            "S/MIME cert must NOT produce Error findings from the S/MIME lints: \
             found error ids {errors_by_id:?}"
        );
    }

    // -----------------------------------------------------------------------
    // PKIX-hy2e.7 regression — duplicate lint IDs must panic at runner
    // construction in BOTH debug and release builds.
    //
    // Previously LintRunner::new used #[cfg(debug_assertions)] to gate the
    // dup-ID check, so release builds (e.g., every cargo install user)
    // silently accepted duplicates and produced ambiguous audit trails
    // when deviations keyed on the duplicated id matched both findings.
    // The check is now unconditional. We exercise it via #[should_panic]
    // on a release-flavoured tests path so the test fails if the gate
    // ever returns.
    //
    // Oracle: AGENTS.md test discipline forbids using the code under test
    // as its own oracle. Here the oracle is the panic mechanism itself
    // and the message constant; the assertion verifies that the panic
    // payload names the duplicated id.
    // -----------------------------------------------------------------------

    #[test]
    #[should_panic(expected = "duplicate lint id")]
    fn lint_runner_new_panics_on_duplicate_lint_ids() {
        // AlwaysPass.id() is "test.always_pass"; registering two copies
        // must panic.
        let lints: Vec<Box<dyn Lint>> = vec![Box::new(AlwaysPass), Box::new(AlwaysPass)];
        let _ = LintRunner::new(lints);
    }

    #[test]
    #[should_panic(expected = "duplicate lint id")]
    fn lint_runner_with_bundle_version_panics_on_duplicate_lint_ids() {
        // The duplicate-ID precondition applies to the bundle-version
        // constructor too.
        let lints: Vec<Box<dyn Lint>> = vec![Box::new(AlwaysPass), Box::new(AlwaysPass)];
        let _ = LintRunner::with_bundle_version(lints, "x");
    }

    #[test]
    fn lint_runner_new_accepts_distinct_ids() {
        // AlwaysPass.id() = "test.always_pass"; AlwaysWarn.id() =
        // "test.always_warn". Distinct ids must not panic.
        let lints: Vec<Box<dyn Lint>> = vec![Box::new(AlwaysPass), Box::new(AlwaysWarn)];
        let _runner = LintRunner::new(lints);
    }
}
