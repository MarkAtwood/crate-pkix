//! Deviation (waiver) mechanism for `pkix-lint`.
//!
//! A [`Deviation`] is an operator-authored, scoped, time-bounded exception to a
//! specific lint finding. Deviations are the only mechanism for suppressing or
//! downgrading lint findings — there are no CLI flags or global overrides.
//!
//! # Design rationale
//!
//! The deviation mechanism is designed to:
//! - Make suppression **explicit and attributable**: every deviation has an ID,
//!   a justification, and an `authorized_by` field that appear in reports.
//! - Force **scoping**: deviations match specific certs (by issuer DN, serial, etc.),
//!   not all certs globally.
//! - Enforce **expiry**: deviations with an `effective_end` re-activate findings
//!   after they expire, forcing renewal and re-justification.
//! - **Not launder violations**: a suppressed finding is recorded as a
//!   [`DeviatedFinding`] in the output, not silently removed. Auditors can see it.
//!
//! # Verification via git, not signatures
//!
//! `authorized_by` is human-readable attribution (name or email), not a
//! cryptographic signature. The audit trail comes from the git history of
//! the deviation store: the git log records who committed the deviation file,
//! when, and from which identity. Store deviation files in a git repository
//! with appropriate access controls and signed commits. This provides the
//! same audit properties as an in-band signature without requiring additional
//! key infrastructure that most operators don't have wired into their PKI tooling.
//!
//! # No vendor deviation packs
//!
//! `pkix-lint` never ships deviation packs. CAs, vendors, or policy authorities
//! who want to ship deviations for their customers must distribute them separately,
//! and operators must explicitly load them into their own [`DeviationStore`]. This
//! prevents the tool from becoming an instrument for CA-side laundering.
//!
//! # Usage
//!
//! ```rust,no_run
//! // This example requires an external certificate fixture; it compiles but
//! // cannot run in the doctest harness without DER fixtures on disk.
//! use pkix_lint::deviation::{Deviation, DeviationAction, DeviationScope, DeviationStore};
//! use pkix_lint::Severity;
//!
//! let mut store = DeviationStore::new();
//! store.add(Deviation {
//!     id: "agency-x-fpki-keyusage-2026-q1".to_string(),
//!     target_lint: "fpki.common.6.1.5".to_string(),
//!     scope: DeviationScope::issuer_dn_contains("agency x issuing ca"),
//!     effective_start: None,
//!     effective_end: Some(1_767_225_600), // 2026-01-01
//!     action: DeviationAction::DowngradeSeverityTo(Severity::Info),
//!     justification: "FPKIPA waiver memo 2025-11-03; see exception register entry 47".to_string(),
//!     authorized_by: "agency-x-ciso@agency.gov".to_string(),
//!     // Optional: URI to the backing document. git commit history is the audit trail.
//!     evidence_uri: Some("https://pkipolicy.agency.gov/waivers/2025-11-03".to_string()),
//! }).unwrap();
//!
//! // Use a DeviationRunner (wraps LintRunner) to apply deviations automatically.
//! ```

use crate::Severity;
use x509_cert::Certificate;

#[cfg(feature = "serde")]
use crate::de_cow_static;

/// Error returned by [`DeviationStore::add`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviationAddError {
    /// A deviation with the same `id` already exists in the store.
    DuplicateId(String),
    /// A required string field (`justification` or `authorized_by`) was empty.
    EmptyField(String),
}

impl std::fmt::Display for DeviationAddError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateId(id) => {
                write!(f, "deviation id '{id}' already exists in the store")
            }
            Self::EmptyField(field) => {
                write!(f, "deviation field '{field}' must not be empty")
            }
        }
    }
}

impl std::error::Error for DeviationAddError {}

/// A scoped, time-bounded exception to a specific lint finding.
///
/// See the module-level documentation for the design rationale and usage.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deviation {
    /// Unique identifier for this deviation within the operator's store.
    ///
    /// Appears verbatim in finding output as `DEVIATION APPLIED by <id>`.
    /// Must be unique within the [`DeviationStore`] that contains it.
    pub id: String,

    /// The stable lint ID this deviation applies to.
    ///
    /// Must exactly match the value returned by [`crate::Lint::id`] for the
    /// target lint. Deviations are lint-ID scoped — they do not apply to all
    /// findings of a given severity or category.
    pub target_lint: String,

    /// Which certificates this deviation applies to.
    ///
    /// Only certs that match the scope will have the deviation applied.
    /// Use [`DeviationScope::any()`] only for internal CAs or test environments
    /// where the profile itself is being applied informally.
    pub scope: DeviationScope,

    /// Unix epoch (seconds) after which this deviation becomes active.
    ///
    /// `None` means the deviation is active immediately (from the Unix epoch).
    pub effective_start: Option<u64>,

    /// Unix epoch (seconds) after which this deviation expires.
    ///
    /// `None` means the deviation never expires. This is strongly discouraged
    /// for production deviations — omitting an end date removes the automatic
    /// re-review trigger. Use `None` only for structural deviations that are
    /// permanent by design (e.g., an internal CA that will never follow FPKI policy).
    pub effective_end: Option<u64>,

    /// What to do with a matching finding.
    pub action: DeviationAction,

    /// Human-readable justification for this deviation.
    ///
    /// Examples: "FPKIPA waiver memo 2025-11-03", "Internal CA not subject to FPKI",
    /// "CA confirmed CP §6.1.5 interpreted as optional for HW tokens per guidance doc".
    /// Appears in finding output and audit reports. Must be non-empty.
    pub justification: String,

    /// Who authorized this deviation.
    ///
    /// The name or email of the person with authority to approve the deviation.
    /// Examples: `"agency-x-ciso@agency.gov"`, `"CN=PKI Officer, OU=CISO, O=Agency X"`.
    ///
    /// This is human-readable attribution, not a cryptographic signature.
    /// The verification layer is the git commit history of the deviation store:
    /// the git log records who committed the deviation file, when, and from
    /// which identity. Store your deviation files in a git repository with
    /// appropriate access controls and signed commits; that provides the
    /// audit trail without requiring additional signing infrastructure here.
    ///
    /// Must be non-empty.
    pub authorized_by: String,

    /// Optional URI pointing to the backing waiver or authorization document.
    ///
    /// When present, this URI is included in [`DeviatedFinding`] output so that
    /// operators can navigate directly to the authorization document when
    /// reviewing or escalating a deviated finding.
    ///
    /// # Examples
    ///
    /// - `Some("file:///var/lib/agency-x-pki/waivers/2025-11-03.pdf")` — local file
    /// - `Some("https://pkipolicy.agency.gov/waivers/2025-11-03")` — web document
    /// - `Some("https://github.com/agency-x/pki-exceptions/issues/47")` — issue tracker
    ///
    /// `None` is acceptable but discouraged for production deviations in gov/mil
    /// contexts where the IG may ask for the authorizing document.
    pub evidence_uri: Option<String>,
}

impl Deviation {
    /// Returns `true` if this deviation is active at `now_unix`.
    ///
    /// A deviation is active when:
    /// - `effective_start` is `None` or `<= now_unix`
    /// - `effective_end` is `None` or `> now_unix`
    ///
    /// The `>` comparison on `effective_end` means a deviation expires at
    /// the second it reaches its end timestamp, not one second after.
    #[must_use]
    pub fn is_active_at(&self, now_unix: u64) -> bool {
        let after_start = self.effective_start.map_or(true, |start| now_unix >= start);
        let before_end = self.effective_end.map_or(true, |end| now_unix < end);
        after_start && before_end
    }

    /// Returns `true` if this deviation applies to `cert` at `now_unix`.
    ///
    /// Both the time-active check and the scope check must pass.
    #[must_use]
    pub fn applies_to(&self, cert: &Certificate, now_unix: u64) -> bool {
        if !self.is_active_at(now_unix) {
            return false;
        }
        self.scope.matches(cert)
    }
}

// ---------------------------------------------------------------------------
// DeviationScope: open-ended kind + props bag
//
// PKIX-9vnx.11: replaces the closed enum with a `kind: String` discriminator
// plus a `props: Vec<(String, ScopePropValue)>` typed bag, mirroring the
// OSCAL Subject shape. Constructors retain ergonomic, type-safe construction
// of the four canonical kinds; future scope axes (PKIX-8mzp's
// `SubjectDnContains`, `PolicyOid`, etc.) are expressible via new `kind`
// strings + props without growing the public enum surface.
// ---------------------------------------------------------------------------

/// Canonical kind discriminator: deviation applies to all certificates.
///
/// Used as the value of [`DeviationScope::kind`]. Has no props.
pub const SCOPE_KIND_ANY: &str = "pkix-lint.scope.any";

/// Canonical kind discriminator: deviation applies to certs whose issuer DN
/// (RFC 4514 string form) contains a substring (case-insensitive).
///
/// Carries one prop: [`PROP_ISSUER_DN_SUBSTRING`] (a `Text` prop).
pub const SCOPE_KIND_ISSUER_DN_CONTAINS: &str = "pkix-lint.scope.issuer-dn-contains";

/// Canonical kind discriminator: deviation applies to certs whose issuer DN
/// matches exactly (RFC 4518 normalized comparison via
/// `pkix_path::names_match`).
///
/// Carries one prop: [`PROP_ISSUER_DN_DER`] (a `Bytes` prop holding the DER
/// encoding of the issuer `Name`).
pub const SCOPE_KIND_ISSUER_DN_EXACT: &str = "pkix-lint.scope.issuer-dn-exact";

/// Canonical kind discriminator: deviation applies to certs issued by a
/// specific CA within a serial number range (inclusive on both ends).
///
/// Carries three props: [`PROP_ISSUER_DN_DER`] (Bytes, DER of issuer),
/// [`PROP_SERIAL_START`] (Bytes), [`PROP_SERIAL_END`] (Bytes).
pub const SCOPE_KIND_SERIAL_RANGE: &str = "pkix-lint.scope.serial-range";

/// Prop name: the substring used by [`SCOPE_KIND_ISSUER_DN_CONTAINS`].
///
/// Value is a [`ScopePropValue::Text`] (pre-lowercased by
/// [`DeviationStore::add`]).
pub const PROP_ISSUER_DN_SUBSTRING: &str = "pkix-lint.issuer-dn-substring";

/// Prop name: the DER encoding of an issuer `Name`, used by
/// [`SCOPE_KIND_ISSUER_DN_EXACT`] and [`SCOPE_KIND_SERIAL_RANGE`].
///
/// Value is a [`ScopePropValue::Bytes`].
pub const PROP_ISSUER_DN_DER: &str = "pkix-lint.issuer-dn-der";

/// Prop name: the inclusive lower bound of the serial-range, used by
/// [`SCOPE_KIND_SERIAL_RANGE`].
///
/// Value is a [`ScopePropValue::Bytes`].
pub const PROP_SERIAL_START: &str = "pkix-lint.serial-start";

/// Prop name: the inclusive upper bound of the serial-range, used by
/// [`SCOPE_KIND_SERIAL_RANGE`].
///
/// Value is a [`ScopePropValue::Bytes`].
pub const PROP_SERIAL_END: &str = "pkix-lint.serial-end";

/// A typed value in a [`DeviationScope`] props bag.
///
/// The two current variants cover the four canonical scope kinds:
/// - [`ScopePropValue::Text`] for human-readable strings (e.g. a substring of
///   an issuer DN).
/// - [`ScopePropValue::Bytes`] for binary data (e.g. a DER-encoded `Name` or
///   a DER positive-integer serial number).
///
/// `#[non_exhaustive]` so future scope axes can introduce additional variants
/// (e.g. an `Oid` variant for `PKIX-8mzp`'s planned `PolicyOid` scope)
/// without a breaking change.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScopePropValue {
    /// A text value. Used for human-readable strings such as the lowercased
    /// substring of an issuer DN.
    Text(String),
    /// A binary value. Used for DER-encoded structures (e.g. `Name`) and for
    /// DER positive-integer serial numbers (big-endian minimal encoding).
    Bytes(Vec<u8>),
}

/// Specifies which certificates a [`Deviation`] applies to.
///
/// `DeviationScope` is an open-ended discriminator + typed-props bag, mirroring
/// the OSCAL Subject shape. The discriminator [`Self::kind`] selects the
/// matching algorithm; [`Self::props`] carries the parameters for that
/// algorithm.
///
/// # Canonical kinds (built in)
///
/// Four kinds ship in `pkix-lint`. Use the matching constructor rather than
/// constructing the struct directly:
///
/// | Constructor | Kind constant | Matches |
/// |-------------|---------------|---------|
/// | [`Self::any`] | [`SCOPE_KIND_ANY`] | All certificates |
/// | [`Self::issuer_dn_contains`] | [`SCOPE_KIND_ISSUER_DN_CONTAINS`] | Issuer DN string contains a substring (case-insensitive) |
/// | [`Self::issuer_dn_exact`] | [`SCOPE_KIND_ISSUER_DN_EXACT`] | Issuer DN matches exactly (RFC 4518 normalized) |
/// | [`Self::serial_range`] | [`SCOPE_KIND_SERIAL_RANGE`] | Issuer DN + serial in inclusive byte-lex range |
///
/// # Choosing a scope
///
/// Use the narrowest scope that resolves the actual problem:
/// - Prefer [`Self::serial_range`] when the deviation covers a specific
///   issuance batch.
/// - Prefer [`Self::issuer_dn_exact`] when all certs from a given CA are
///   affected.
/// - Use [`Self::issuer_dn_contains`] for human-readable convenience scoping
///   in dev/test.
/// - Use [`Self::any`] only for internal CAs or test environments where the
///   profile is intentionally not applicable.
///
/// # Open-ended extensibility
///
/// Additional scope axes (e.g. `PKIX-8mzp`'s planned `SubjectDnContains`,
/// `PolicyOid`) are expressible via new `kind` strings + props without
/// modifying this struct. [`Self::matches`] short-circuits to `false` for
/// unknown kinds (fail-closed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviationScope {
    /// The subject-type discriminator. One of the `SCOPE_KIND_*` constants for
    /// the canonical kinds, or a custom kind string for caller-defined axes.
    pub kind: String,
    /// Typed props that parameterize the scope. Property names are
    /// kind-specific; see the `SCOPE_KIND_*` constants for the props each
    /// canonical kind expects.
    ///
    /// Stored as a `Vec` rather than a map to preserve insertion order. Linear
    /// scans by name are O(N) but N is small (≤3 today, ≤a handful even for
    /// future scope axes).
    pub props: Vec<(String, ScopePropValue)>,
}

impl DeviationScope {
    /// Construct a [`SCOPE_KIND_ANY`] scope (matches all certificates).
    #[must_use]
    pub fn any() -> Self {
        Self {
            kind: SCOPE_KIND_ANY.to_string(),
            props: Vec::new(),
        }
    }

    /// Construct a [`SCOPE_KIND_ISSUER_DN_CONTAINS`] scope.
    ///
    /// `substring` is matched (case-insensitively) against the RFC 4514 string
    /// form of the certificate's issuer DN. Pre-lowercase the substring or
    /// rely on [`DeviationStore::add`] to do so at insertion time; matching
    /// assumes the stored substring is already lowercase.
    ///
    /// This is a substring match, not an RFC 4518-normalized DN match. Prefer
    /// [`Self::issuer_dn_exact`] when precise DN identity is required.
    ///
    /// Case folding uses [`str::to_lowercase`] (Unicode-aware default
    /// case mapping). Accented Latin, CJK kana, and other non-ASCII
    /// characters fold according to the Unicode case mapping tables on
    /// both the stored substring side and the cert-issuer-DN side, so
    /// scoping a deviation by `"agency müller ca"` matches a cert whose
    /// issuer DN renders as `"CN=Agency Müller CA"`. The fold allocates
    /// a fresh `String` per match; caller-side caching is recommended
    /// for hot paths if profiling shows the cost.
    #[must_use]
    pub fn issuer_dn_contains(substring: impl Into<String>) -> Self {
        Self {
            kind: SCOPE_KIND_ISSUER_DN_CONTAINS.to_string(),
            props: vec![(
                PROP_ISSUER_DN_SUBSTRING.to_string(),
                ScopePropValue::Text(substring.into()),
            )],
        }
    }

    /// Construct a [`SCOPE_KIND_ISSUER_DN_EXACT`] scope.
    ///
    /// The issuer DN is matched using
    /// [`pkix_path::names_match`] (RFC 4518 normalization).
    ///
    /// # Errors
    ///
    /// Returns [`der::Error`] if `name` fails to DER-encode.
    pub fn issuer_dn_exact(name: &x509_cert::name::Name) -> Result<Self, der::Error> {
        use der::Encode as _;
        let der = name.to_der()?;
        Ok(Self {
            kind: SCOPE_KIND_ISSUER_DN_EXACT.to_string(),
            props: vec![(PROP_ISSUER_DN_DER.to_string(), ScopePropValue::Bytes(der))],
        })
    }

    /// Construct a [`SCOPE_KIND_SERIAL_RANGE`] scope.
    ///
    /// `issuer` is the CA's subject DN (matched via
    /// [`pkix_path::names_match`]); `start` and `end` are the serial number
    /// bounds (inclusive) as raw bytes in DER positive-integer encoding.
    ///
    /// # Errors
    ///
    /// Returns [`der::Error`] if `issuer` fails to DER-encode.
    pub fn serial_range(
        issuer: &x509_cert::name::Name,
        start: Vec<u8>,
        end: Vec<u8>,
    ) -> Result<Self, der::Error> {
        use der::Encode as _;
        let der = issuer.to_der()?;
        Ok(Self {
            kind: SCOPE_KIND_SERIAL_RANGE.to_string(),
            props: vec![
                (PROP_ISSUER_DN_DER.to_string(), ScopePropValue::Bytes(der)),
                (PROP_SERIAL_START.to_string(), ScopePropValue::Bytes(start)),
                (PROP_SERIAL_END.to_string(), ScopePropValue::Bytes(end)),
            ],
        })
    }

    /// Get a prop value by name, or `None` if no such prop exists.
    ///
    /// Used internally by [`Self::matches`] and by the OSCAL emit/parse layer.
    #[must_use]
    pub fn get_prop(&self, name: &str) -> Option<&ScopePropValue> {
        self.props
            .iter()
            .find_map(|(k, v)| (k == name).then_some(v))
    }

    fn get_text(&self, name: &str) -> Option<&str> {
        match self.get_prop(name)? {
            ScopePropValue::Text(s) => Some(s.as_str()),
            ScopePropValue::Bytes(_) => None,
        }
    }

    fn get_bytes(&self, name: &str) -> Option<&[u8]> {
        match self.get_prop(name)? {
            ScopePropValue::Bytes(b) => Some(b.as_slice()),
            ScopePropValue::Text(_) => None,
        }
    }

    /// Returns `true` if `cert` is within this scope.
    ///
    /// Dispatches on [`Self::kind`]. Unknown kinds return `false`
    /// (fail-closed). Within each known kind, missing-or-wrong-typed props
    /// also return `false` rather than panicking — the constructors prevent
    /// this for code-built scopes, and the OSCAL parser rejects malformed
    /// input before any [`DeviationScope`] is constructed.
    #[must_use]
    pub fn matches(&self, cert: &Certificate) -> bool {
        match self.kind.as_str() {
            SCOPE_KIND_ANY => true,
            SCOPE_KIND_ISSUER_DN_CONTAINS => {
                let Some(substring) = self.get_text(PROP_ISSUER_DN_SUBSTRING) else {
                    return false;
                };
                // `substring` is pre-lowercased by `DeviationStore::add`
                // using the same `str::to_lowercase` Unicode-aware fold
                // we apply here. Cross-side consistency is the
                // correctness invariant.
                //
                // `str::to_lowercase` uses Unicode case mapping tables
                // (default casing per the Unicode standard) and folds
                // accented Latin, CJK kana, etc. correctly. CA DN
                // strings in non-Western European jurisdictions
                // (Bundesdruckerei, Caisse des Dépôts, Polish/Czech
                // CAs) routinely use non-ASCII characters; ASCII-only
                // folding silently failed these matches.
                //
                // This allocates a fresh String each call. For
                // realistic deviation-store sizes the cost is
                // immaterial; a caller-side cache of `(deviation_id,
                // cert_sha256) → bool` is the recommended remedy if
                // profiling ever shows otherwise.
                let issuer_str = cert.tbs_certificate.issuer.to_string().to_lowercase();
                issuer_str.contains(substring)
            }
            SCOPE_KIND_ISSUER_DN_EXACT => {
                let Some(der) = self.get_bytes(PROP_ISSUER_DN_DER) else {
                    return false;
                };
                use der::Decode as _;
                let Ok(name) = x509_cert::name::Name::from_der(der) else {
                    return false;
                };
                pkix_path::names_match(&name, &cert.tbs_certificate.issuer)
            }
            SCOPE_KIND_SERIAL_RANGE => {
                let Some(der) = self.get_bytes(PROP_ISSUER_DN_DER) else {
                    return false;
                };
                let Some(start) = self.get_bytes(PROP_SERIAL_START) else {
                    return false;
                };
                let Some(end) = self.get_bytes(PROP_SERIAL_END) else {
                    return false;
                };
                use der::Decode as _;
                let Ok(issuer) = x509_cert::name::Name::from_der(der) else {
                    return false;
                };
                if !pkix_path::names_match(&issuer, &cert.tbs_certificate.issuer) {
                    return false;
                }
                let serial = cert.tbs_certificate.serial_number.as_bytes();
                let cmp_start = serial_cmp(serial, start);
                let cmp_end = serial_cmp(serial, end);
                cmp_start.is_ge() && cmp_end.is_le()
            }
            // Unknown kind: fail-closed.
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// serde::Serialize for DeviationScope and ScopePropValue
//
// `Name` (DER-encoded) is the only field that does not have a built-in serde
// impl. Bytes are serialized as hex strings to keep the JSON readable.
// Deserialization is not provided; round-tripping requires going through the
// OSCAL parser (see `pkix_lint::oscal::parse`).
// ---------------------------------------------------------------------------

#[cfg(feature = "serde")]
impl serde::Serialize for ScopePropValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStructVariant as _;
        match self {
            Self::Text(s) => serializer.serialize_newtype_variant("ScopePropValue", 0, "Text", s),
            Self::Bytes(b) => {
                let mut sv =
                    serializer.serialize_struct_variant("ScopePropValue", 1, "Bytes", 1)?;
                sv.serialize_field("hex", &hex_encode(b))?;
                sv.end()
            }
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for DeviationScope {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;
        let mut st = serializer.serialize_struct("DeviationScope", 2)?;
        st.serialize_field("kind", &self.kind)?;
        st.serialize_field("props", &self.props)?;
        st.end()
    }
}

/// Lowercase-hex encode bytes (no separator). Used by serde::Serialize for
/// [`ScopePropValue::Bytes`] to keep the JSON form human-readable.
#[cfg(feature = "serde")]
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Compare two byte slices as DER positive-integer serial numbers.
///
/// DER positive integers are big-endian with a leading 0x00 byte only when the
/// high bit would otherwise be set (sign-bit convention). Leading zeros are
/// stripped before comparing; longer (after stripping) is greater, equal length
/// falls through to lexicographic byte comparison.
///
/// Call sites use `.is_ge()` / `.is_le()` for "in range" checks.
fn serial_cmp(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    let a = strip_leading_zeros(a);
    let b = strip_leading_zeros(b);
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[first_nonzero..]
}

/// What a [`Deviation`] does to a matching finding.
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviationAction {
    /// Change the finding's severity to the specified level.
    ///
    /// The finding is still recorded in the output — it is not removed.
    /// The deviation ID appears in the [`DeviatedFinding`] so auditors can see it.
    DowngradeSeverityTo(Severity),

    /// Mark the finding as suppressed (effectively `NotApplicable` for reporting).
    ///
    /// The finding is still recorded as a [`DeviatedFinding`] with
    /// `action: DeviationAction::Suppress` so auditors can see that the deviation
    /// was applied. It does not appear as a normal finding.
    ///
    /// Use only when `DowngradeSeverityTo(Severity::Info)` is not sufficient
    /// (e.g., the finding would be incorrectly categorized as Info in reports).
    Suppress,
}

/// A finding with a deviation applied.
///
/// The underlying lint ID, original result, and deviation metadata are all
/// preserved for audit purposes. A `DeviatedFinding` is never silently hidden.
///
/// # Operator UI guidance
///
/// Display deviated findings as "DEVIATION APPLIED" rather than green/pass.
/// Show `deviation_id`, `justification`, and `evidence_uri` (when present) so
/// operators can navigate to the backing waiver document without a second lookup.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviatedFinding {
    /// The stable lint ID of the lint that produced this finding.
    #[cfg_attr(feature = "serde", serde(deserialize_with = "de_cow_static"))]
    pub lint_id: std::borrow::Cow<'static, str>,
    /// The citation for the lint that produced this finding.
    #[cfg_attr(feature = "serde", serde(deserialize_with = "de_cow_static"))]
    pub citation: std::borrow::Cow<'static, str>,
    /// The original lint result before the deviation was applied.
    pub original_result: crate::LintResult,
    /// The deviation ID that was applied.
    pub deviation_id: String,
    /// The action taken by the deviation.
    pub action: DeviationAction,
    /// Human-readable justification from the deviation.
    pub justification: String,
    /// URI pointing to the backing waiver document, if one was provided.
    ///
    /// `None` if the deviation did not include an `evidence_uri`.
    pub evidence_uri: Option<String>,
    /// For certificate-scope findings, the zero-based chain index.
    pub cert_index: Option<usize>,
    /// Unix epoch seconds at which the lint was evaluated.
    ///
    /// Propagated from [`crate::Finding::evaluated_at_unix`] when the deviation
    /// is applied. Matches the `now_unix` passed to the runner method.
    pub evaluated_at_unix: u64,
}

impl DeviatedFinding {
    /// Returns the effective severity after the deviation was applied.
    ///
    /// - `DowngradeSeverityTo(s)` returns `s`.
    /// - `Suppress` returns `None` (the finding is suppressed from normal output).
    #[must_use]
    pub const fn effective_severity(&self) -> Option<Severity> {
        match &self.action {
            DeviationAction::DowngradeSeverityTo(s) => Some(*s),
            DeviationAction::Suppress => None,
        }
    }
}

/// An in-memory collection of [`Deviation`]s.
///
/// The store is currently append-only. Future versions may add update/delete
/// and persistence (file-backed JSON/OSCAL format) — tracked as PKIX-dbhe.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviationStore {
    deviations: Vec<Deviation>,
}

impl DeviationStore {
    /// Create an empty store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            deviations: Vec::new(),
        }
    }

    /// Add a deviation to the store.
    ///
    /// # Errors
    ///
    /// - [`DeviationAddError::EmptyField`] if `deviation.justification` or
    ///   `deviation.authorized_by` is empty.
    /// - [`DeviationAddError::DuplicateId`] if a deviation with the same
    ///   `id` already exists in the store.
    pub fn add(&mut self, mut deviation: Deviation) -> Result<(), DeviationAddError> {
        if deviation.justification.is_empty() {
            return Err(DeviationAddError::EmptyField("justification".into()));
        }
        if deviation.authorized_by.is_empty() {
            return Err(DeviationAddError::EmptyField("authorized_by".into()));
        }
        if self.deviations.iter().any(|d| d.id == deviation.id) {
            return Err(DeviationAddError::DuplicateId(deviation.id.clone()));
        }
        // Normalize the issuer-dn-contains substring to lowercase at
        // insertion time so that matching logic does not need to re-normalize
        // on every call. This prevents a silent no-match when callers pass a
        // mixed-case substring.
        //
        // Use `str::to_lowercase` (Unicode-aware) consistent with the
        // matching code in `DeviationScope::matches`. Cross-side
        // consistency is the correctness invariant: any byte sequence
        // that lowercases to itself on both sides matches; any
        // sequence that lowercases differently on the two sides
        // silently no-matches. The pre-fix `make_ascii_lowercase`
        // call left non-ASCII characters (e.g., 'ü' in 'Müller')
        // untouched on both sides; lowercase user input 'müller'
        // could never match cert-side 'Müller'. (PKIX-hy2e.8)
        if deviation.scope.kind == SCOPE_KIND_ISSUER_DN_CONTAINS {
            for (name, value) in &mut deviation.scope.props {
                if name == PROP_ISSUER_DN_SUBSTRING {
                    if let ScopePropValue::Text(s) = value {
                        *s = s.to_lowercase();
                    }
                }
            }
        }
        self.deviations.push(deviation);
        Ok(())
    }

    /// Return all deviations in the store.
    #[must_use]
    pub fn all(&self) -> &[Deviation] {
        &self.deviations
    }

    /// Return all deviations that are active at `now_unix`.
    #[must_use = "iterator is lazy; collect or iterate to use results"]
    pub fn active_at(&self, now_unix: u64) -> impl Iterator<Item = &Deviation> {
        self.deviations
            .iter()
            .filter(move |d| d.is_active_at(now_unix))
    }

    /// Return all deviations targeting `lint_id` that are active at `now_unix`.
    #[must_use = "iterator is lazy; collect or iterate to use results"]
    pub fn active_for_lint<'a>(
        &'a self,
        lint_id: &'a str,
        now_unix: u64,
    ) -> impl Iterator<Item = &'a Deviation> {
        self.deviations
            .iter()
            .filter(move |d| d.target_lint.as_str() == lint_id && d.is_active_at(now_unix))
    }

    /// Return all deviations that have expired as of `now_unix`.
    ///
    /// Used by corpus-reporting tools to surface deviations that need renewal.
    #[must_use = "iterator is lazy; collect or iterate to use results"]
    pub fn expired_at(&self, now_unix: u64) -> impl Iterator<Item = &Deviation> {
        self.deviations
            .iter()
            .filter(move |d| d.effective_end.is_some_and(|end| now_unix >= end))
    }

    /// Check whether a specific finding should be deviated.
    ///
    /// Returns the first active deviation that matches `cert` and `lint_id` at
    /// `now_unix`, or `None` if no deviation applies.
    ///
    /// In the case of multiple matching deviations, the first one added to the
    /// store wins. Deviations should be scoped to avoid unintentional overlap.
    #[must_use]
    pub fn find_deviation(
        &self,
        lint_id: &str,
        cert: &Certificate,
        now_unix: u64,
    ) -> Option<&Deviation> {
        self.deviations
            .iter()
            .find(|d| d.target_lint.as_str() == lint_id && d.applies_to(cert, now_unix))
    }
}

// ---------------------------------------------------------------------------
// DeviationRunner
// ---------------------------------------------------------------------------

/// The output of a [`DeviationRunner`] evaluation: findings with deviations applied.
///
/// Findings where a deviation was applied are moved from `findings` to `deviated`.
/// Callers can use `findings` for normal compliance reporting and `deviated`
/// for audit/transparency reporting.
///
/// # Stability
///
/// This struct is `#[non_exhaustive]`: new fields may be added in future minor
/// versions (e.g., a `suppressed` list for audit purposes). Do not construct
/// `DeviationRunResult` directly with struct literal syntax; use
/// [`DeviationRunResult::default()`] or obtain it from [`DeviationRunner`].
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviationRunResult {
    /// Findings that were not affected by any deviation.
    ///
    /// Contains the full output of the inner [`crate::LintRunner`] minus any
    /// findings that were moved to [`Self::deviated`]. This includes
    /// [`crate::LintResult::Pass`] and [`crate::LintResult::NotApplicable`]
    /// findings as well as actionable ones — mirroring the behaviour of
    /// [`crate::LintRunner::run_cert`]. Callers that want only actionable
    /// results should filter with [`crate::Finding::is_finding`].
    pub findings: Vec<crate::Finding>,

    /// Findings that had a deviation applied.
    ///
    /// These are always included in output (never silently hidden) so that
    /// auditors can see what was deviated and why. If `action` is
    /// [`DeviationAction::Suppress`], `effective_severity()` returns `None`;
    /// the caller can display these with a "DEVIATION APPLIED" tag rather than
    /// as normal findings.
    pub deviated: Vec<DeviatedFinding>,
}

/// A lint runner that applies [`DeviationStore`] logic to findings.
///
/// `DeviationRunner` wraps a [`crate::LintRunner`] and a [`DeviationStore`].
/// After each lint evaluation, it checks whether a deviation applies to the
/// finding. If one does, the finding is moved to [`DeviationRunResult::deviated`];
/// otherwise it stays in [`DeviationRunResult::findings`].
///
/// # Transparency guarantee
///
/// `DeviationRunner` **never silently drops findings**. Every finding — including
/// deviated ones — appears in [`DeviationRunResult`]. Operators see what was
/// deviated; auditors can enumerate deviations via [`DeviationStore::all`].
///
/// # Usage
///
/// ```rust,no_run
/// // `cert` and `now_unix` are obtained from the calling context.
/// use pkix_lint::deviation::{DeviationRunner, DeviationStore};
/// use pkix_lint::{LintRunner, SubjectKind};
/// use x509_cert::Certificate;
///
/// let cert: Certificate = unimplemented!("load from DER");
/// let now_unix: u64 = unimplemented!("current Unix epoch seconds");
/// let store = DeviationStore::new(); // populate with operator deviations
/// let runner = LintRunner::new(vec![/* your lints */]);
/// let dev_runner = DeviationRunner::new(runner, store);
///
/// let result = dev_runner.run_cert(&cert, SubjectKind::Leaf, 0, now_unix);
/// // result.findings — normal findings
/// // result.deviated — deviated findings (always included for auditability)
/// ```
pub struct DeviationRunner {
    runner: crate::LintRunner,
    store: DeviationStore,
}

impl DeviationRunner {
    /// Create a new deviation runner from a lint runner and a deviation store.
    #[must_use]
    pub const fn new(runner: crate::LintRunner, store: DeviationStore) -> Self {
        Self { runner, store }
    }

    /// Return a reference to the inner [`crate::LintRunner`].
    #[must_use]
    pub const fn lint_runner(&self) -> &crate::LintRunner {
        &self.runner
    }

    /// Return a reference to the [`DeviationStore`].
    #[must_use]
    pub const fn deviation_store(&self) -> &DeviationStore {
        &self.store
    }

    /// Evaluate certificate-scope lints and apply deviations.
    ///
    /// Same semantics as [`crate::LintRunner::run_cert`], but findings are
    /// partitioned into `findings` (no deviation) and `deviated` (deviation applied).
    #[must_use]
    pub fn run_cert(
        &self,
        cert: &Certificate,
        kind: crate::SubjectKind,
        cert_index: usize,
        now_unix: u64,
    ) -> DeviationRunResult {
        let raw = self.runner.run_cert(cert, kind, cert_index, now_unix);
        self.apply_deviations(raw, cert, now_unix)
    }

    /// Evaluate certificate-scope lints as of the cert's `notBefore` date and
    /// apply deviations.
    ///
    /// Mirrors [`crate::LintRunner::run_cert_at_issuance`]: extracts the
    /// `notBefore` timestamp and calls `run_cert` with that value as `now_unix`.
    /// This answers "was this cert compliant when it was issued?"
    #[must_use]
    pub fn run_cert_at_issuance(
        &self,
        cert: &Certificate,
        kind: crate::SubjectKind,
        cert_index: usize,
    ) -> DeviationRunResult {
        let issuance_unix = cert
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs();
        self.run_cert(cert, kind, cert_index, issuance_unix)
    }

    /// Evaluate certificate-scope lints on every cert in `chain` and apply deviations.
    ///
    /// `kinds` maps chain index to [`crate::SubjectKind`]. If `kinds` is shorter than
    /// `chain`, remaining certificates are treated as [`crate::SubjectKind::IntermediateCa`].
    #[must_use]
    pub fn run_chain(
        &self,
        chain: &[Certificate],
        kinds: &[crate::SubjectKind],
        now_unix: u64,
    ) -> DeviationRunResult {
        let mut result = DeviationRunResult::default();
        for (i, cert) in chain.iter().enumerate() {
            let kind = kinds
                .get(i)
                .copied()
                .unwrap_or(crate::SubjectKind::IntermediateCa);
            let raw = self.runner.run_cert(cert, kind, i, now_unix);
            let partial = self.apply_deviations(raw, cert, now_unix);
            result.findings.extend(partial.findings);
            result.deviated.extend(partial.deviated);
        }
        result
    }

    /// Evaluate path-scope lints and apply deviations.
    ///
    /// For path-scope lints, scope matching uses the leaf certificate (`chain[0]`).
    ///
    /// # Limitations
    ///
    /// Path-scope deviation matching always uses the leaf certificate (`chain[0]`)
    /// for scope evaluation. [`DeviationScope::IssuerDnExact`] and
    /// [`DeviationScope::SerialRange`] must reference the leaf certificate's
    /// issuer DN — deviations scoped to an intermediate CA's DN will not match.
    #[must_use]
    pub fn run_path(
        &self,
        chain: &[Certificate],
        path: &crate::ValidatedPath,
        now_unix: u64,
    ) -> DeviationRunResult {
        let raw = self.runner.run_path(chain, path, now_unix);
        // Use the leaf cert for scope matching on path-level deviations.
        // If the chain is empty (shouldn't happen after validate_path), fall
        // back to no scope matching (treat as Any).
        match chain.first() {
            Some(leaf) => self.apply_deviations(raw, leaf, now_unix),
            None => DeviationRunResult {
                findings: raw,
                deviated: vec![],
            },
        }
    }

    /// Internal: partition a `Vec<Finding>` by whether a deviation applies.
    fn apply_deviations(
        &self,
        raw: Vec<crate::Finding>,
        cert: &Certificate,
        now_unix: u64,
    ) -> DeviationRunResult {
        let mut result = DeviationRunResult::default();
        for finding in raw {
            // Only attempt to apply deviations to actionable findings.
            // Pass and NotApplicable findings are never waived.
            if !finding.result.is_finding() {
                result.findings.push(finding);
                continue;
            }
            match self.store.find_deviation(&finding.lint_id, cert, now_unix) {
                None => {
                    result.findings.push(finding);
                }
                Some(dev) => {
                    result.deviated.push(DeviatedFinding {
                        lint_id: finding.lint_id,
                        citation: finding.citation,
                        original_result: finding.result,
                        deviation_id: dev.id.clone(),
                        action: dev.action.clone(),
                        justification: dev.justification.clone(),
                        evidence_uri: dev.evidence_uri.clone(),
                        cert_index: finding.cert_index,
                        evaluated_at_unix: finding.evaluated_at_unix,
                    });
                }
            }
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LintResult;

    fn make_deviation(id: &str, lint_id: &str) -> Deviation {
        Deviation {
            id: id.to_string(),
            target_lint: lint_id.to_string(),
            scope: DeviationScope::any(),
            effective_start: None,
            effective_end: None,
            action: DeviationAction::DowngradeSeverityTo(Severity::Info),
            justification: "test justification".to_string(),
            authorized_by: "test-author@example.com".to_string(),
            evidence_uri: None,
        }
    }

    fn load_cert() -> Certificate {
        use der::Decode as _;
        Certificate::from_der(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/webpki-self-signed-365d.der"
        ))
        .expect("fixture is valid DER")
    }

    // -----------------------------------------------------------------------
    // is_active_at tests
    // Oracle: the time-range semantics in Deviation::is_active_at doc comment.
    // -----------------------------------------------------------------------

    #[test]
    fn deviation_active_at_no_bounds() {
        let d = make_deviation("d1", "test.lint");
        // No bounds: always active.
        assert!(d.is_active_at(0));
        assert!(d.is_active_at(u64::MAX));
    }

    #[test]
    fn deviation_active_after_start() {
        let d = Deviation {
            effective_start: Some(100),
            effective_end: None,
            ..make_deviation("d2", "test.lint")
        };
        assert!(!d.is_active_at(99), "before start must not be active");
        assert!(d.is_active_at(100), "at start must be active");
        assert!(d.is_active_at(200), "after start must be active");
    }

    #[test]
    fn deviation_expires_at_end() {
        let d = Deviation {
            effective_start: None,
            effective_end: Some(200),
            ..make_deviation("d3", "test.lint")
        };
        assert!(d.is_active_at(199), "before end must be active");
        assert!(
            !d.is_active_at(200),
            "at end must NOT be active (exclusive)"
        );
        assert!(!d.is_active_at(201), "after end must not be active");
    }

    #[test]
    fn deviation_active_within_range() {
        let d = Deviation {
            effective_start: Some(100),
            effective_end: Some(200),
            ..make_deviation("d4", "test.lint")
        };
        assert!(!d.is_active_at(99));
        assert!(d.is_active_at(100));
        assert!(d.is_active_at(150));
        assert!(d.is_active_at(199));
        assert!(!d.is_active_at(200));
    }

    // -----------------------------------------------------------------------
    // DeviationScope::matches tests
    // Oracle: the scope-matching rules in the DeviationScope doc comment.
    // -----------------------------------------------------------------------

    #[test]
    fn scope_any_matches_any_cert() {
        let cert = load_cert();
        assert!(DeviationScope::any().matches(&cert));
    }

    #[test]
    fn scope_issuer_dn_contains_case_insensitive() {
        let cert = load_cert();
        // The webpki-self-signed-365d cert has a CN we can match.
        // Get the issuer string to find what's in it.
        let issuer = cert.tbs_certificate.issuer.to_string();
        // Take the first word of the issuer for a partial match.
        let word = issuer.split_whitespace().next().unwrap_or("cert");
        // issuer_dn_contains requires a pre-lowercased substring; the match
        // is case-insensitive because the cert's issuer string is lowercased
        // at match time. Both lowercase and originally-cased input must match
        // once lowercased at construction.
        let scope_lower = DeviationScope::issuer_dn_contains(word.to_lowercase());
        let scope_upper = DeviationScope::issuer_dn_contains(word.to_uppercase().to_lowercase());
        assert!(scope_lower.matches(&cert), "lowercase match must succeed");
        assert!(
            scope_upper.matches(&cert),
            "lowercased-at-construction match must succeed"
        );
    }

    #[test]
    fn scope_issuer_dn_contains_no_match() {
        let cert = load_cert();
        let scope = DeviationScope::issuer_dn_contains("XYZ_NONEXISTENT_ISSUER_9999");
        assert!(!scope.matches(&cert));
    }

    /// `DeviationStore::add` normalizes `IssuerDnContains` to lowercase so that
    /// callers who pass a mixed-case substring get a working deviation rather than
    /// a silently inactive one.
    #[test]
    fn deviation_store_add_normalizes_issuer_dn_contains_to_lowercase() {
        let cert = load_cert();
        let issuer = cert.tbs_certificate.issuer.to_string();
        let word = issuer
            .split(|c: char| !c.is_alphanumeric())
            .find(|w| !w.is_empty())
            .unwrap_or("test");
        let uppercase_word = word.to_uppercase();

        // Only run the assertion when the word has a meaningful uppercase form.
        if uppercase_word == word.to_lowercase() {
            return;
        }

        // Add a deviation whose scope uses an UPPERCASE substring.
        let mut store = DeviationStore::new();
        let deviation = Deviation {
            scope: DeviationScope::issuer_dn_contains(uppercase_word.clone()),
            ..make_deviation("norm-test", "test.lint")
        };
        store.add(deviation).expect("add must succeed");

        // The stored substring must have been normalized to lowercase.
        let stored = &store.all()[0].scope;
        assert_eq!(stored.kind, SCOPE_KIND_ISSUER_DN_CONTAINS);
        let stored_substring = match stored.get_prop(PROP_ISSUER_DN_SUBSTRING) {
            Some(ScopePropValue::Text(s)) => s,
            other => panic!("expected Text substring prop, got {other:?}"),
        };
        assert_eq!(
            *stored_substring,
            uppercase_word.to_lowercase(),
            "DeviationStore::add must lowercase issuer-dn-substring prop"
        );

        // And the normalized deviation must match the cert.
        assert!(
            stored.matches(&cert),
            "normalized issuer-dn-contains scope must match cert"
        );
    }

    /// Regression for PKIX-hy2e.8: case folding must be Unicode-aware
    /// on both sides (DeviationStore::add and DeviationScope::matches).
    /// The pre-fix `make_ascii_lowercase` left non-ASCII characters
    /// untouched on both sides; lowercase user input 'müller' could
    /// never match cert-side 'Müller' because the cert's 'ü' was not
    /// folded to match the stored substring's 'ü'. (Well, the bug was
    /// inverted: stored substring "müller" preserves 'ü'; cert side
    /// "Müller" leaves 'M' uppercase. With `to_lowercase` both fold to
    /// the same form.)
    ///
    /// Independent oracle: Unicode 15.1 default case mapping table.
    /// "Müller".to_lowercase() == "müller". "MÜLLER".to_lowercase() ==
    /// "müller". This is the property `to_lowercase` was designed to
    /// provide; `make_ascii_lowercase` does not.
    #[test]
    fn case_folding_is_unicode_aware_for_store_normalization() {
        // The store-side normalization happens in DeviationStore::add.
        let mut store = DeviationStore::new();
        let deviation = Deviation {
            scope: DeviationScope::issuer_dn_contains("MÜLLER"),
            ..make_deviation("muller-test", "test.lint")
        };
        store.add(deviation).expect("add must succeed");

        let stored = &store.all()[0].scope;
        let stored_substring = match stored.get_prop(PROP_ISSUER_DN_SUBSTRING) {
            Some(ScopePropValue::Text(s)) => s,
            other => panic!("expected Text substring prop, got {other:?}"),
        };
        assert_eq!(
            *stored_substring, "müller",
            "DeviationStore::add must Unicode-lowercase the issuer-dn-substring; \
             pre-fix make_ascii_lowercase produced \"mÜller\" (Ü untouched)"
        );
    }

    #[test]
    fn case_folding_is_unicode_aware_via_to_lowercase() {
        // Confirm the std::str::to_lowercase oracle behaves as
        // expected for the worked example in the rustdoc. This is the
        // independent oracle for the regression — if Rust's
        // to_lowercase ever changed semantics for "Müller" → "müller"
        // we would need to revisit the deviation matching strategy.
        assert_eq!("Müller".to_lowercase(), "müller");
        assert_eq!("MÜLLER".to_lowercase(), "müller");
        // ASCII-only fold leaves Ü/ü unchanged — that is the bug shape.
        let mut s = String::from("MÜLLER");
        s.make_ascii_lowercase();
        assert_eq!(s, "mÜller", "ASCII-only fold is documented to leave non-ASCII alone");
        // The pre-fix code on the cert side did exactly this fold, so
        // a lowercase stored substring 'müller' could not match 'mÜller'.
    }

    // -----------------------------------------------------------------------
    // IssuerDnExact scope tests
    //
    // Oracle: IssuerDnExact uses pkix_path::names_match (RFC 4518 normalization).
    // A cert's issuer DN must match the stored DN via that same function.
    // -----------------------------------------------------------------------

    #[test]
    fn scope_issuer_dn_exact_matches_cert_issuer() {
        let cert = load_cert();
        // Use the cert's own issuer DN as the exact match — must succeed.
        let scope = DeviationScope::issuer_dn_exact(&cert.tbs_certificate.issuer)
            .expect("issuer DN must DER-encode");
        assert!(
            scope.matches(&cert),
            "issuer_dn_exact with cert's own issuer must match"
        );
    }

    #[test]
    fn scope_issuer_dn_exact_does_not_match_different_dn() {
        use der::Decode as _;
        let cert = load_cert();
        // Use the cert's subject DN as the "issuer" — for a self-signed cert subject==issuer,
        // so use a different cert's issuer if available. Since we only have one fixture
        // that is self-signed (subject == issuer), we test non-match by constructing
        // an issuer_dn_exact with a DIFFERENT cert's issuer.
        //
        // Load the smime fixture (different cert, different DN).
        let other_cert = Certificate::from_der(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/smime-self-signed-365d.der"
        ))
        .expect("fixture is valid DER");
        // Use smime cert's issuer as the scope — should not match the webpki cert.
        let scope = DeviationScope::issuer_dn_exact(&other_cert.tbs_certificate.issuer)
            .expect("issuer DN must DER-encode");
        // If both certs have the same issuer DN, the test is vacuous. Check first.
        let same = pkix_path::names_match(
            &cert.tbs_certificate.issuer,
            &other_cert.tbs_certificate.issuer,
        );
        if !same {
            assert!(
                !scope.matches(&cert),
                "issuer_dn_exact with different issuer must not match"
            );
        }
        // If same (both self-signed with identical DNs), the test passes vacuously —
        // the fixtures happen to have the same issuer, and that's acceptable.
    }

    // -----------------------------------------------------------------------
    // SerialRange scope tests
    //
    // Oracle: serial_cmp implements DER positive integer comparison.
    // Boundary conditions are tested independently of the cert fixture.
    // -----------------------------------------------------------------------

    #[test]
    fn serial_cmp_greater() {
        use core::cmp::Ordering;
        // 0x02 > 0x01
        assert_eq!(serial_cmp(&[0x02], &[0x01]), Ordering::Greater);
        // longer byte sequence (more digits) is larger
        assert_eq!(serial_cmp(&[0x01, 0x00], &[0xFF]), Ordering::Greater);
    }

    #[test]
    fn serial_cmp_less() {
        use core::cmp::Ordering;
        // 0x01 < 0x02
        assert_eq!(serial_cmp(&[0x01], &[0x02]), Ordering::Less);
        // shorter (after strip) is smaller
        assert_eq!(serial_cmp(&[0xFF], &[0x01, 0x00]), Ordering::Less);
    }

    #[test]
    fn serial_cmp_equal() {
        use core::cmp::Ordering;
        // identical
        assert_eq!(serial_cmp(&[0x05], &[0x05]), Ordering::Equal);
    }

    #[test]
    fn serial_cmp_leading_zeros_stripped() {
        use core::cmp::Ordering;
        // 0x00 0x01 = 1, 0x01 = 1 — equal after stripping leading zero on a.
        assert_eq!(serial_cmp(&[0x00, 0x01], &[0x01]), Ordering::Equal);
        // is_ge / is_le on Equal are both true (matches old serial_lex_{ge,le} behavior).
        assert!(serial_cmp(&[0x00, 0x01], &[0x01]).is_ge());
        assert!(serial_cmp(&[0x00, 0x01], &[0x01]).is_le());
    }

    #[test]
    fn scope_serial_range_matches_cert_in_range() {
        let cert = load_cert();
        let serial = cert.tbs_certificate.serial_number.as_bytes().to_vec();
        // Range is [serial, serial] — cert's own serial, must match.
        let scope =
            DeviationScope::serial_range(&cert.tbs_certificate.issuer, serial.clone(), serial)
                .expect("issuer DN must DER-encode");
        assert!(
            scope.matches(&cert),
            "cert's own serial must be within [serial, serial]"
        );
    }

    #[test]
    fn scope_serial_range_excludes_cert_outside_range() {
        let cert = load_cert();
        let serial = cert.tbs_certificate.serial_number.as_bytes();
        // Range is [serial+1, serial+2] — cert's serial is below, must not match.
        // Construct a start that is definitely higher: 0xFF repeated.
        let start = vec![0xFF; serial.len() + 1]; // much larger than any fixed serial
        let end = vec![0xFF; serial.len() + 2];
        let scope = DeviationScope::serial_range(&cert.tbs_certificate.issuer, start, end)
            .expect("issuer DN must DER-encode");
        assert!(
            !scope.matches(&cert),
            "cert serial below range start must not match"
        );
    }

    #[test]
    fn scope_serial_range_wrong_issuer_no_match() {
        use der::Decode as _;
        let cert = load_cert();
        let other_cert = Certificate::from_der(include_bytes!(
            "../../pkix-path/tests/fixtures/policy-checks/smime-self-signed-365d.der"
        ))
        .expect("fixture is valid DER");
        let serial = cert.tbs_certificate.serial_number.as_bytes().to_vec();
        // Use the other cert's issuer — should not match cert.
        let scope = DeviationScope::serial_range(
            &other_cert.tbs_certificate.issuer,
            vec![0x00],
            vec![0xFF; serial.len() + 2],
        )
        .expect("issuer DN must DER-encode");
        let same_issuer = pkix_path::names_match(
            &cert.tbs_certificate.issuer,
            &other_cert.tbs_certificate.issuer,
        );
        if !same_issuer {
            assert!(
                !scope.matches(&cert),
                "wrong issuer in serial_range must not match"
            );
        }
    }

    // -----------------------------------------------------------------------
    // PKIX-9vnx.11: open-ended kind discriminator
    //
    // Verifies that unknown kinds and props-bag malformations fail closed.
    // -----------------------------------------------------------------------

    #[test]
    fn scope_unknown_kind_fails_closed() {
        let cert = load_cert();
        let scope = DeviationScope {
            kind: "pkix-lint.scope.future-axis-not-yet-defined".to_string(),
            props: vec![],
        };
        assert!(
            !scope.matches(&cert),
            "unknown kind must fail-closed (return false)"
        );
    }

    #[test]
    fn scope_issuer_dn_contains_missing_prop_fails_closed() {
        let cert = load_cert();
        // Hand-built scope with kind set but the substring prop missing.
        let scope = DeviationScope {
            kind: SCOPE_KIND_ISSUER_DN_CONTAINS.to_string(),
            props: vec![],
        };
        assert!(
            !scope.matches(&cert),
            "missing substring prop must fail-closed"
        );
    }

    #[test]
    fn scope_issuer_dn_exact_wrong_typed_prop_fails_closed() {
        let cert = load_cert();
        // Hand-built scope where the DER prop is Text instead of Bytes.
        let scope = DeviationScope {
            kind: SCOPE_KIND_ISSUER_DN_EXACT.to_string(),
            props: vec![(
                PROP_ISSUER_DN_DER.to_string(),
                ScopePropValue::Text("not bytes".to_string()),
            )],
        };
        assert!(
            !scope.matches(&cert),
            "wrong-typed issuer-dn-der prop must fail-closed"
        );
    }

    #[test]
    fn scope_issuer_dn_exact_malformed_der_fails_closed() {
        let cert = load_cert();
        let scope = DeviationScope {
            kind: SCOPE_KIND_ISSUER_DN_EXACT.to_string(),
            props: vec![(
                PROP_ISSUER_DN_DER.to_string(),
                // Random bytes that do not decode as a Name.
                ScopePropValue::Bytes(vec![0xFF, 0xFE, 0xFD]),
            )],
        };
        assert!(
            !scope.matches(&cert),
            "malformed issuer-dn-der bytes must fail-closed"
        );
    }

    #[test]
    fn scope_constructor_kinds_match_constants() {
        // The constructors must produce scopes whose `kind` field matches the
        // corresponding `SCOPE_KIND_*` constant. This is an invariant the OSCAL
        // emit/parse layer relies on.
        assert_eq!(DeviationScope::any().kind, SCOPE_KIND_ANY);
        assert_eq!(
            DeviationScope::issuer_dn_contains("x").kind,
            SCOPE_KIND_ISSUER_DN_CONTAINS
        );
        let cert = load_cert();
        let exact = DeviationScope::issuer_dn_exact(&cert.tbs_certificate.issuer)
            .expect("issuer DN must DER-encode");
        assert_eq!(exact.kind, SCOPE_KIND_ISSUER_DN_EXACT);
        let range =
            DeviationScope::serial_range(&cert.tbs_certificate.issuer, vec![0x01], vec![0x02])
                .expect("issuer DN must DER-encode");
        assert_eq!(range.kind, SCOPE_KIND_SERIAL_RANGE);
    }

    // -----------------------------------------------------------------------
    // DeviationStore tests
    // Oracle: the store contract in DeviationStore doc comments.
    // -----------------------------------------------------------------------

    #[test]
    fn store_add_and_retrieve() {
        let mut store = DeviationStore::new();
        store
            .add(make_deviation("d1", "test.lint.a"))
            .expect("add should succeed");
        store
            .add(make_deviation("d2", "test.lint.b"))
            .expect("add should succeed");
        assert_eq!(store.all().len(), 2);
    }

    #[test]
    fn store_rejects_empty_justification() {
        let mut store = DeviationStore::new();
        let result = store.add(Deviation {
            justification: String::new(),
            ..make_deviation("d1", "test.lint")
        });
        assert_eq!(
            result,
            Err(DeviationAddError::EmptyField("justification".into())),
            "empty justification must return EmptyField error"
        );
    }

    #[test]
    fn store_rejects_empty_authorized_by() {
        let mut store = DeviationStore::new();
        let result = store.add(Deviation {
            authorized_by: String::new(),
            ..make_deviation("d1", "test.lint")
        });
        assert_eq!(
            result,
            Err(DeviationAddError::EmptyField("authorized_by".into())),
            "empty authorized_by must return EmptyField error"
        );
    }

    #[test]
    fn store_rejects_duplicate_id() {
        let mut store = DeviationStore::new();
        store
            .add(make_deviation("d1", "test.lint.a"))
            .expect("first add should succeed");
        let result = store.add(make_deviation("d1", "test.lint.b")); // same id → error
        assert!(result.is_err(), "duplicate id must return Err");
        assert_eq!(
            result.unwrap_err(),
            DeviationAddError::DuplicateId("d1".to_string())
        );
    }

    #[test]
    fn store_find_deviation_matches() {
        let cert = load_cert();
        let now: u64 = 1_000_000;
        let mut store = DeviationStore::new();
        store
            .add(Deviation {
                effective_start: None,
                effective_end: None,
                ..make_deviation("d1", "test.lint.a")
            })
            .expect("add should succeed");
        let found = store.find_deviation("test.lint.a", &cert, now);
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, "d1");
    }

    #[test]
    fn store_find_deviation_no_match_wrong_lint() {
        let cert = load_cert();
        let now: u64 = 1_000_000;
        let mut store = DeviationStore::new();
        store
            .add(make_deviation("d1", "test.lint.a"))
            .expect("add should succeed");
        assert!(store.find_deviation("test.lint.b", &cert, now).is_none());
    }

    #[test]
    fn store_find_deviation_expired_not_matched() {
        let cert = load_cert();
        let now: u64 = 1_000;
        let mut store = DeviationStore::new();
        store
            .add(Deviation {
                effective_end: Some(500), // expired at 500
                ..make_deviation("d1", "test.lint.a")
            })
            .expect("add should succeed");
        // At now=1000, the deviation has expired.
        assert!(store.find_deviation("test.lint.a", &cert, now).is_none());
    }

    #[test]
    fn store_expired_at_reports_expired_deviations() {
        let mut store = DeviationStore::new();
        store
            .add(Deviation {
                effective_end: Some(500),
                ..make_deviation("d1", "test.lint.a")
            })
            .expect("add should succeed");
        store
            .add(Deviation {
                effective_end: None, // never expires
                ..make_deviation("d2", "test.lint.b")
            })
            .expect("add should succeed");
        let expired: Vec<_> = store.expired_at(1000).collect();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].id, "d1");
    }

    #[test]
    fn deviated_finding_effective_severity() {
        let f = DeviatedFinding {
            lint_id: std::borrow::Cow::Borrowed("test.lint"),
            citation: std::borrow::Cow::Borrowed("test citation"),
            original_result: LintResult::error("original"),
            deviation_id: "d1".to_string(),
            action: DeviationAction::DowngradeSeverityTo(Severity::Info),
            justification: "test justification".to_string(),
            evidence_uri: None,
            cert_index: None,
            evaluated_at_unix: 0,
        };
        assert_eq!(f.effective_severity(), Some(Severity::Info));

        let f2 = DeviatedFinding {
            action: DeviationAction::Suppress,
            ..f
        };
        assert_eq!(f2.effective_severity(), None);
    }

    // -----------------------------------------------------------------------
    // DeviationRunner tests
    // Oracle: DeviationRunner contract from doc comments.
    // -----------------------------------------------------------------------

    /// A lint that always returns Error — used to test deviation application.
    struct AlwaysError;
    impl crate::Lint for AlwaysError {
        fn id(&self) -> &'static str {
            "test.always_error"
        }
        fn citation(&self) -> &'static str {
            "test"
        }
        fn severity(&self) -> crate::Severity {
            crate::Severity::Error
        }
        fn scope(&self) -> crate::Scope {
            crate::Scope::Certificate
        }
        fn applies_to(&self) -> crate::SubjectKind {
            crate::SubjectKind::Any
        }
        fn check_cert(
            &self,
            _cert: &Certificate,
            _kind: crate::SubjectKind,
            _now: u64,
        ) -> crate::LintResult {
            crate::LintResult::error("always errors")
        }
    }

    /// A lint that always passes — used to verify non-deviated findings stay in findings.
    struct AlwaysPass;
    impl crate::Lint for AlwaysPass {
        fn id(&self) -> &'static str {
            "test.always_pass"
        }
        fn citation(&self) -> &'static str {
            "test"
        }
        fn severity(&self) -> crate::Severity {
            crate::Severity::Info
        }
        fn scope(&self) -> crate::Scope {
            crate::Scope::Certificate
        }
        fn applies_to(&self) -> crate::SubjectKind {
            crate::SubjectKind::Any
        }
        fn check_cert(
            &self,
            _cert: &Certificate,
            _kind: crate::SubjectKind,
            _now: u64,
        ) -> crate::LintResult {
            crate::LintResult::Pass
        }
    }

    #[test]
    fn deviation_runner_moves_deviated_finding_to_deviated() {
        let cert = load_cert();
        let now: u64 = 1_000_000;

        let mut store = DeviationStore::new();
        store
            .add(Deviation {
                target_lint: "test.always_error".to_string(),
                ..make_deviation("d1", "test.always_error")
            })
            .expect("add should succeed");

        let runner = crate::LintRunner::new(vec![Box::new(AlwaysError)]);
        let dev_runner = DeviationRunner::new(runner, store);
        let result = dev_runner.run_cert(&cert, crate::SubjectKind::Leaf, 0, now);

        // The error finding must be deviated, not in normal findings.
        assert!(
            result.findings.is_empty(),
            "deviated finding must not be in findings"
        );
        assert_eq!(
            result.deviated.len(),
            1,
            "deviated finding must be in deviated"
        );
        assert_eq!(result.deviated[0].lint_id, "test.always_error");
        assert_eq!(result.deviated[0].deviation_id, "d1");
        // Original result is preserved.
        assert!(matches!(
            result.deviated[0].original_result,
            crate::LintResult::Error(_)
        ));
    }

    #[test]
    fn deviation_runner_non_deviated_finding_stays_in_findings() {
        let cert = load_cert();
        let now: u64 = 1_000_000;

        // Deviation targets a different lint than what we're running.
        let mut store = DeviationStore::new();
        store
            .add(make_deviation("d1", "test.different_lint"))
            .expect("add should succeed");

        let runner = crate::LintRunner::new(vec![Box::new(AlwaysPass)]);
        let dev_runner = DeviationRunner::new(runner, store);
        let result = dev_runner.run_cert(&cert, crate::SubjectKind::Leaf, 0, now);

        // Pass finding not matched by deviation: stays in findings.
        assert_eq!(result.findings.len(), 1);
        assert!(result.deviated.is_empty());
    }

    #[test]
    fn deviation_runner_expired_deviation_does_not_apply() {
        let cert = load_cert();
        let now: u64 = 2_000_000;

        let mut store = DeviationStore::new();
        store
            .add(Deviation {
                effective_end: Some(1_000_000), // expired before now
                ..make_deviation("d1", "test.always_error")
            })
            .expect("add should succeed");

        let runner = crate::LintRunner::new(vec![Box::new(AlwaysError)]);
        let dev_runner = DeviationRunner::new(runner, store);
        let result = dev_runner.run_cert(&cert, crate::SubjectKind::Leaf, 0, now);

        // Expired deviation: error finding stays in findings (not deviated).
        assert_eq!(result.findings.len(), 1);
        assert!(result.deviated.is_empty());
    }

    #[test]
    fn deviation_runner_suppress_action_sets_effective_severity_none() {
        let cert = load_cert();
        let now: u64 = 1_000_000;

        let mut store = DeviationStore::new();
        store
            .add(Deviation {
                action: DeviationAction::Suppress,
                ..make_deviation("d1", "test.always_error")
            })
            .expect("add should succeed");

        let runner = crate::LintRunner::new(vec![Box::new(AlwaysError)]);
        let dev_runner = DeviationRunner::new(runner, store);
        let result = dev_runner.run_cert(&cert, crate::SubjectKind::Leaf, 0, now);

        assert!(result.findings.is_empty());
        assert_eq!(result.deviated.len(), 1);
        // Suppressed findings have no effective severity.
        assert_eq!(result.deviated[0].effective_severity(), None);
    }

    /// `evidence_uri` flows from Deviation through to `DeviatedFinding`.
    ///
    /// Oracle: `DeviatedFinding.evidence_uri` must equal `Deviation.evidence_uri`.
    /// This is the field operators use to navigate to the waiver document.
    #[test]
    fn evidence_uri_flows_to_deviated_finding() {
        let cert = load_cert();
        let now: u64 = 1_000_000;
        let uri = "https://pkipolicy.agency.gov/waivers/2025-11-03";

        let mut store = DeviationStore::new();
        store
            .add(Deviation {
                evidence_uri: Some(uri.to_string()),
                ..make_deviation("d1", "test.always_error")
            })
            .expect("add should succeed");

        let runner = crate::LintRunner::new(vec![Box::new(AlwaysError)]);
        let dev_runner = DeviationRunner::new(runner, store);
        let result = dev_runner.run_cert(&cert, crate::SubjectKind::Leaf, 0, now);

        assert_eq!(result.deviated.len(), 1);
        assert_eq!(
            result.deviated[0].evidence_uri.as_deref(),
            Some(uri),
            "evidence_uri must flow from Deviation to DeviatedFinding"
        );
        // justification also flows through.
        assert_eq!(result.deviated[0].justification, "test justification");
    }

    /// When `evidence_uri` is None, `DeviatedFinding.evidence_uri` is None.
    #[test]
    fn evidence_uri_none_when_deviation_has_no_uri() {
        let cert = load_cert();
        let now: u64 = 1_000_000;

        let mut store = DeviationStore::new();
        store
            .add(make_deviation("d1", "test.always_error"))
            .expect("add should succeed"); // evidence_uri: None

        let runner = crate::LintRunner::new(vec![Box::new(AlwaysError)]);
        let dev_runner = DeviationRunner::new(runner, store);
        let result = dev_runner.run_cert(&cert, crate::SubjectKind::Leaf, 0, now);

        assert_eq!(result.deviated.len(), 1);
        assert_eq!(result.deviated[0].evidence_uri, None);
    }
}
