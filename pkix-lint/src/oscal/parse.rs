//! Parser for OSCAL Risk arrays emitted by [`super::emit::risks_from_store`].
//!
//! This module is the inverse of the deviation-policy emit half. Given a
//! [`serde_json::Value`] in the shape produced by
//! [`super::emit::risks_from_store`] — a JSON array of OSCAL Risk objects
//! with `status = "deviation-approved"` and `pkix-lint.*` namespaced props
//! — [`deviation_store_from_risks`] reconstructs a
//! [`crate::deviation::DeviationStore`].
//!
//! # Round-trip contract
//!
//! The parser is intentionally narrow: it accepts the exact shape emitted
//! by this crate, not arbitrary OSCAL Risk documents authored by other
//! tools. This trade lets us guarantee that `(emit . parse)` over any
//! non-empty store yields an `Eq`-equal store while keeping the parser
//! small and the error surface clear. Risk objects produced by other
//! OSCAL emitters (e.g. a POA&M from a different toolchain) are out of
//! scope.
//!
//! # Lossless `Name` decoding
//!
//! Issuer DNs are reconstructed from the `pkix-lint.issuer-dn-der` prop
//! (DER bytes, lowercase hex). The companion `pkix-lint.issuer-dn` prop
//! is the RFC 4514 display string and is informational only — the parser
//! never reads it.
//!
//! # Errors
//!
//! All malformed-input paths return a descriptive [`ParseError`] rather
//! than panicking, per the bead acceptance criterion.

use crate::deviation::{
    Deviation, DeviationAction, DeviationAddError, DeviationScope, DeviationStore,
};
use crate::Severity;
use serde_json::Value;

/// Error returned by [`deviation_store_from_risks`].
///
/// Every variant carries enough context (the index of the offending Risk
/// in the input array, and the field name where applicable) for an
/// operator to locate the problem in the source JSON.
#[derive(Debug)]
#[non_exhaustive]
pub enum ParseError {
    /// The top-level [`Value`] was not a JSON array.
    NotArray,
    /// The Risk at the given index was not a JSON object.
    RiskNotObject {
        /// Position of the offending Risk in the input array.
        index: usize,
    },
    /// The Risk's `status` was missing or not `"deviation-approved"`.
    InvalidStatus {
        /// Position of the offending Risk in the input array.
        index: usize,
        /// The status value that was found (empty string if absent).
        found: String,
    },
    /// The Risk had no `description` field carrying the deviation
    /// justification.
    MissingDescription {
        /// Position of the offending Risk in the input array.
        index: usize,
    },
    /// The Risk's `subjects` array was missing or not a JSON array.
    SubjectsNotArray {
        /// Position of the offending Risk in the input array.
        index: usize,
    },
    /// The Risk had an empty `subjects` array.
    MissingSubject {
        /// Position of the offending Risk in the input array.
        index: usize,
    },
    /// The first entry in the Risk's `subjects` array was not a JSON
    /// object.
    SubjectNotObject {
        /// Position of the offending Risk in the input array.
        index: usize,
    },
    /// The subject had no `type` discriminator.
    SubjectMissingType {
        /// Position of the offending Risk in the input array.
        index: usize,
    },
    /// The subject's `type` was not one of the known
    /// `pkix-lint.scope.*` discriminators.
    UnknownSubjectType {
        /// Position of the offending Risk in the input array.
        index: usize,
        /// The `type` value that was found.
        found: String,
    },
    /// A required Risk-level prop was missing from `props`.
    MissingProp {
        /// Position of the offending Risk in the input array.
        index: usize,
        /// Name of the missing prop.
        name: &'static str,
    },
    /// A required subject-level prop was missing from the subject's
    /// `props`.
    MissingSubjectProp {
        /// Position of the offending Risk in the input array.
        index: usize,
        /// Name of the missing prop.
        name: &'static str,
    },
    /// A required prop was present but its value was an empty string.
    EmptyProp {
        /// Position of the offending Risk in the input array.
        index: usize,
        /// Name of the empty prop.
        name: &'static str,
    },
    /// The `pkix-lint.action` prop value did not match `suppress` or
    /// `downgrade:<severity-label>` with a known severity label.
    UnknownAction {
        /// Position of the offending Risk in the input array.
        index: usize,
        /// The action string that was found.
        found: String,
    },
    /// A hex-encoded prop value failed to decode (odd length, or a
    /// non-hex byte).
    MalformedHex {
        /// Position of the offending Risk in the input array.
        index: usize,
        /// Name of the prop whose value failed to decode.
        prop: &'static str,
    },
    /// The DER bytes carried by `pkix-lint.issuer-dn-der` were empty or
    /// failed to parse as an X.509 [`Name`](x509_cert::name::Name).
    MalformedDer {
        /// Position of the offending Risk in the input array.
        index: usize,
        /// Name of the prop whose DER bytes failed to parse.
        prop: &'static str,
    },
    /// A timestamp prop (`pkix-lint.effective-start` /
    /// `pkix-lint.effective-end`) was not a decimal `u64`.
    InvalidU64 {
        /// Position of the offending Risk in the input array.
        index: usize,
        /// Name of the offending prop.
        prop: &'static str,
        /// The value that failed to parse.
        found: String,
    },
    /// The reconstructed [`Deviation`] was rejected by
    /// [`DeviationStore::add`] (duplicate id, or an empty required
    /// field that survived parse-side checks).
    AddFailed {
        /// Position of the offending Risk in the input array.
        index: usize,
        /// Underlying error from [`DeviationStore::add`].
        source: DeviationAddError,
    },

    // -- Catalog parsing (PKIX-9vnx.6.3) -----------------------------------
    /// The top-level OSCAL Catalog value was not a JSON object (Catalog
    /// emitters produce `{"catalog": {...}}`).
    CatalogNotObject,
    /// The expected `catalog` wrapper key was missing or not an object.
    CatalogMissingWrapper,
    /// The `catalog.controls` field was missing or not a JSON array.
    ControlsNotArray,
    /// A Control at the given index was not a JSON object.
    ControlNotObject {
        /// Position of the offending Control in `catalog.controls`.
        index: usize,
    },
    /// A Control was missing its required `id` field.
    ControlMissingId {
        /// Position of the offending Control in `catalog.controls`.
        index: usize,
    },
    /// A Control's `id` was present but not a JSON string.
    ControlIdNotString {
        /// Position of the offending Control in `catalog.controls`.
        index: usize,
    },
    /// A Control's `id` was a string but empty.
    ControlIdEmpty {
        /// Position of the offending Control in `catalog.controls`.
        index: usize,
    },

    // -- Catalog → registered Lint set (PKIX-9vnx.6.3) ---------------------
    /// `filter_to_ids` was passed an id that no registered Lint matches.
    UnknownLintId {
        /// The unmatched Catalog Control id.
        id: String,
    },

    // -- Profile composition (PKIX-9vnx.7) ---------------------------------
    /// The top-level OSCAL Profile value was not a JSON object.
    ProfileNotObject,
    /// The expected `profile` wrapper key was missing or not an object.
    ProfileMissingWrapper,
    /// The `profile.imports` field was missing or not a JSON array.
    ProfileImportsNotArray,
    /// An entry in `profile.imports` was not a JSON object.
    ProfileImportNotObject {
        /// Position of the offending import in `profile.imports`.
        index: usize,
    },
    /// An import was missing its required `href` field.
    ProfileImportMissingHref {
        /// Position of the offending import in `profile.imports`.
        index: usize,
    },
    /// An import's `href` was present but not a JSON string.
    ProfileImportHrefNotString {
        /// Position of the offending import in `profile.imports`.
        index: usize,
    },
    /// An import's `href` was a string but empty.
    ProfileImportHrefEmpty {
        /// Position of the offending import in `profile.imports`.
        index: usize,
    },
    /// An import's `href` had no matching entry in the supplied
    /// `sources` map.
    ProfileImportUnresolved {
        /// Position of the offending import in `profile.imports`.
        index: usize,
        /// The unresolved href.
        href: String,
    },
    /// A `sources` entry referenced by an import was neither an OSCAL
    /// Catalog (`{"catalog": …}`) nor an OSCAL Profile
    /// (`{"profile": …}`).
    ProfileImportSourceUnknown {
        /// Position of the offending import in `profile.imports`.
        index: usize,
        /// The href whose source had an unrecognised wrapper.
        href: String,
    },
    /// Profile-imports-Profile chain visited the same href twice.
    ProfileImportCycle {
        /// The href whose re-entry closed the cycle.
        href: String,
    },
    /// `profile.imports[].include-controls` was present but not a JSON
    /// array.
    ProfileIncludeControlsNotArray {
        /// Position of the offending import in `profile.imports`.
        index: usize,
    },
    /// `profile.imports[].exclude-controls` was present but not a JSON
    /// array.
    ProfileExcludeControlsNotArray {
        /// Position of the offending import in `profile.imports`.
        index: usize,
    },
    /// An entry in `include-controls` / `exclude-controls` was not a
    /// JSON object.
    ProfileWithIdsEntryNotObject {
        /// Position of the parent import in `profile.imports`.
        index: usize,
        /// Position of the offending entry in the directives array.
        entry_index: usize,
    },
    /// An entry's `with-ids` field was not a JSON array.
    ProfileWithIdsNotArray {
        /// Position of the parent import in `profile.imports`.
        index: usize,
        /// Position of the offending entry in the directives array.
        entry_index: usize,
    },
    /// An id in a `with-ids` array was not a JSON string.
    ProfileWithIdNotString {
        /// Position of the parent import in `profile.imports`.
        index: usize,
        /// Position of the offending entry in the directives array.
        entry_index: usize,
    },
    /// `profile.modify.set-parameters` was present but not a JSON
    /// array.
    ProfileSetParametersNotArray,
    /// An entry in `set-parameters` was not a JSON object.
    ProfileSetParameterNotObject {
        /// Position of the offending entry in `set-parameters`.
        entry_index: usize,
    },
    /// A `set-parameters` entry was missing its required `param-id`
    /// field or it was not a JSON string.
    ProfileSetParameterMissingId {
        /// Position of the offending entry in `set-parameters`.
        entry_index: usize,
    },
    /// A `set-parameters` entry's `param-id` was a string but empty.
    ProfileSetParameterIdEmpty {
        /// Position of the offending entry in `set-parameters`.
        entry_index: usize,
    },
    /// A `set-parameters` entry's `values` field was missing or not a
    /// JSON array.
    ProfileSetParameterValuesNotArray {
        /// Position of the offending entry in `set-parameters`.
        entry_index: usize,
    },
    /// A `set-parameters` entry's `values` field was an empty array
    /// (OSCAL requires at least one value).
    ProfileSetParameterValuesEmpty {
        /// Position of the offending entry in `set-parameters`.
        entry_index: usize,
    },
    /// A `set-parameters` entry's first `values[0]` was not a JSON
    /// string.
    ProfileSetParameterValueNotString {
        /// Position of the offending entry in `set-parameters`.
        entry_index: usize,
    },

    // -- Profile overrides → registered Lint set (PKIX-9vnx.7) -------------
    /// `apply_parameter_overrides` was passed a composite param id that
    /// did not match `<lint_id>.<param_id>` for any registered Lint.
    UnknownParameterOverride {
        /// The unmatched composite param id.
        param_id: String,
    },
    /// `apply_parameter_overrides` matched a lint by id but
    /// [`crate::Lint::set_parameter`] rejected the value.
    InvalidParameterOverride {
        /// The composite param id where the override originated.
        param_id: String,
        /// Underlying [`crate::ParameterError`] surfaced from
        /// [`crate::Lint::set_parameter`].
        source: crate::ParameterError,
    },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotArray => write!(f, "top-level OSCAL value is not a JSON array"),
            Self::RiskNotObject { index } => {
                write!(f, "Risk at index {index} is not a JSON object")
            }
            Self::InvalidStatus { index, found } => write!(
                f,
                "Risk at index {index} has status '{found}', expected 'deviation-approved'"
            ),
            Self::MissingDescription { index } => {
                write!(
                    f,
                    "Risk at index {index} has no description (justification)"
                )
            }
            Self::SubjectsNotArray { index } => {
                write!(f, "Risk at index {index} has no subjects array")
            }
            Self::MissingSubject { index } => {
                write!(f, "Risk at index {index} has an empty subjects array")
            }
            Self::SubjectNotObject { index } => {
                write!(
                    f,
                    "Risk at index {index} has a subject entry that is not a JSON object"
                )
            }
            Self::SubjectMissingType { index } => {
                write!(
                    f,
                    "Risk at index {index} has a subject with no 'type' discriminator"
                )
            }
            Self::UnknownSubjectType { index, found } => write!(
                f,
                "Risk at index {index} has unknown subject type '{found}'"
            ),
            Self::MissingProp { index, name } => {
                write!(f, "Risk at index {index} is missing required prop '{name}'")
            }
            Self::MissingSubjectProp { index, name } => write!(
                f,
                "Risk at index {index} subject is missing required prop '{name}'"
            ),
            Self::EmptyProp { index, name } => {
                write!(
                    f,
                    "Risk at index {index} has empty value for required prop '{name}'"
                )
            }
            Self::UnknownAction { index, found } => write!(
                f,
                "Risk at index {index} has unrecognized action value '{found}'"
            ),
            Self::MalformedHex { index, prop } => {
                write!(f, "Risk at index {index} prop '{prop}' is not valid hex")
            }
            Self::MalformedDer { index, prop } => write!(
                f,
                "Risk at index {index} prop '{prop}' is empty or not a valid DER-encoded Name"
            ),
            Self::InvalidU64 { index, prop, found } => write!(
                f,
                "Risk at index {index} prop '{prop}' is not a decimal u64: '{found}'"
            ),
            Self::AddFailed { index, source } => write!(
                f,
                "Risk at index {index} could not be added to the store: {source}"
            ),
            Self::CatalogNotObject => {
                write!(f, "top-level OSCAL Catalog value is not a JSON object")
            }
            Self::CatalogMissingWrapper => {
                write!(f, "OSCAL Catalog value is missing the 'catalog' wrapper")
            }
            Self::ControlsNotArray => {
                write!(f, "catalog.controls is missing or not a JSON array")
            }
            Self::ControlNotObject { index } => {
                write!(f, "Control at index {index} is not a JSON object")
            }
            Self::ControlMissingId { index } => {
                write!(f, "Control at index {index} is missing required 'id' field")
            }
            Self::ControlIdNotString { index } => {
                write!(f, "Control at index {index} 'id' is not a JSON string")
            }
            Self::ControlIdEmpty { index } => {
                write!(f, "Control at index {index} 'id' is an empty string")
            }
            Self::UnknownLintId { id } => write!(
                f,
                "Catalog Control id '{id}' has no matching registered Lint"
            ),
            Self::ProfileNotObject => {
                write!(f, "top-level OSCAL Profile value is not a JSON object")
            }
            Self::ProfileMissingWrapper => {
                write!(f, "OSCAL Profile value is missing the 'profile' wrapper")
            }
            Self::ProfileImportsNotArray => {
                write!(f, "profile.imports is missing or not a JSON array")
            }
            Self::ProfileImportNotObject { index } => {
                write!(f, "profile.imports[{index}] is not a JSON object")
            }
            Self::ProfileImportMissingHref { index } => write!(
                f,
                "profile.imports[{index}] is missing required 'href' field"
            ),
            Self::ProfileImportHrefNotString { index } => {
                write!(f, "profile.imports[{index}] 'href' is not a JSON string")
            }
            Self::ProfileImportHrefEmpty { index } => {
                write!(f, "profile.imports[{index}] 'href' is an empty string")
            }
            Self::ProfileImportUnresolved { index, href } => write!(
                f,
                "profile.imports[{index}] href '{href}' has no entry in sources"
            ),
            Self::ProfileImportSourceUnknown { index, href } => write!(
                f,
                "profile.imports[{index}] href '{href}' source is neither a Catalog nor a Profile"
            ),
            Self::ProfileImportCycle { href } => {
                write!(f, "profile import cycle detected at href '{href}'")
            }
            Self::ProfileIncludeControlsNotArray { index } => write!(
                f,
                "profile.imports[{index}].include-controls is not a JSON array"
            ),
            Self::ProfileExcludeControlsNotArray { index } => write!(
                f,
                "profile.imports[{index}].exclude-controls is not a JSON array"
            ),
            Self::ProfileWithIdsEntryNotObject { index, entry_index } => write!(
                f,
                "profile.imports[{index}] include/exclude-controls[{entry_index}] is not a JSON object"
            ),
            Self::ProfileWithIdsNotArray { index, entry_index } => write!(
                f,
                "profile.imports[{index}] include/exclude-controls[{entry_index}].with-ids is not a JSON array"
            ),
            Self::ProfileWithIdNotString { index, entry_index } => write!(
                f,
                "profile.imports[{index}] include/exclude-controls[{entry_index}].with-ids contains a non-string id"
            ),
            Self::ProfileSetParametersNotArray => {
                write!(f, "profile.modify.set-parameters is not a JSON array")
            }
            Self::ProfileSetParameterNotObject { entry_index } => write!(
                f,
                "profile.modify.set-parameters[{entry_index}] is not a JSON object"
            ),
            Self::ProfileSetParameterMissingId { entry_index } => write!(
                f,
                "profile.modify.set-parameters[{entry_index}] is missing required 'param-id'"
            ),
            Self::ProfileSetParameterIdEmpty { entry_index } => write!(
                f,
                "profile.modify.set-parameters[{entry_index}] 'param-id' is an empty string"
            ),
            Self::ProfileSetParameterValuesNotArray { entry_index } => write!(
                f,
                "profile.modify.set-parameters[{entry_index}] 'values' is missing or not a JSON array"
            ),
            Self::ProfileSetParameterValuesEmpty { entry_index } => write!(
                f,
                "profile.modify.set-parameters[{entry_index}] 'values' is empty"
            ),
            Self::ProfileSetParameterValueNotString { entry_index } => write!(
                f,
                "profile.modify.set-parameters[{entry_index}] 'values[0]' is not a JSON string"
            ),
            Self::UnknownParameterOverride { param_id } => write!(
                f,
                "no registered Lint owns composite parameter id '{param_id}'"
            ),
            Self::InvalidParameterOverride { param_id, source } => write!(
                f,
                "Lint rejected parameter override for '{param_id}': {source}"
            ),
        }
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::AddFailed { source, .. } => Some(source),
            Self::InvalidParameterOverride { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Parse an OSCAL Risk array (as emitted by
/// [`super::emit::risks_from_store`]) into a [`DeviationStore`].
///
/// `value` must be a JSON array of OSCAL Risk objects. Each Risk is
/// decoded into a single [`Deviation`] and inserted via
/// [`DeviationStore::add`], which preserves the store's
/// duplicate-id and substring-normalization invariants.
///
/// # Errors
///
/// Returns [`ParseError`] for any malformed input (missing required
/// props, unknown discriminators, malformed hex / DER, duplicate id,
/// etc.). The parser does not panic on user input.
pub fn deviation_store_from_risks(value: &Value) -> Result<DeviationStore, ParseError> {
    let arr = value.as_array().ok_or(ParseError::NotArray)?;
    let mut store = DeviationStore::new();
    for (idx, risk) in arr.iter().enumerate() {
        let deviation = parse_risk(idx, risk)?;
        store
            .add(deviation)
            .map_err(|source| ParseError::AddFailed { index: idx, source })?;
    }
    Ok(store)
}

fn parse_risk(idx: usize, risk: &Value) -> Result<Deviation, ParseError> {
    let obj = risk
        .as_object()
        .ok_or(ParseError::RiskNotObject { index: idx })?;

    // Status MUST be "deviation-approved".
    let status = obj.get("status").and_then(Value::as_str).unwrap_or("");
    if status != "deviation-approved" {
        return Err(ParseError::InvalidStatus {
            index: idx,
            found: status.to_string(),
        });
    }

    // Justification comes from `description`. `statement` is a redundant
    // copy on emit (both fields carry the same justification text); we
    // read `description` and ignore `statement`.
    let justification = obj
        .get("description")
        .and_then(Value::as_str)
        .ok_or(ParseError::MissingDescription { index: idx })?
        .to_string();

    // Risk-level props.
    let props_slice: Option<&[Value]> = obj
        .get("props")
        .and_then(Value::as_array)
        .map(Vec::as_slice);
    let get_prop = |name: &'static str| -> Option<&str> { find_prop_value(props_slice, name) };

    let id = required_nonempty_prop(
        idx,
        get_prop("pkix-lint.deviation-id"),
        "pkix-lint.deviation-id",
    )?
    .to_string();
    let target_lint = required_nonempty_prop(
        idx,
        get_prop("pkix-lint.target-lint"),
        "pkix-lint.target-lint",
    )?
    .to_string();
    let action_str = required_nonempty_prop(idx, get_prop("pkix-lint.action"), "pkix-lint.action")?;
    let action = parse_action(idx, action_str)?;
    let authorized_by = required_nonempty_prop(
        idx,
        get_prop("pkix-lint.authorized-by"),
        "pkix-lint.authorized-by",
    )?
    .to_string();
    let effective_start = parse_optional_u64(
        idx,
        get_prop("pkix-lint.effective-start"),
        "pkix-lint.effective-start",
    )?;
    let effective_end = parse_optional_u64(
        idx,
        get_prop("pkix-lint.effective-end"),
        "pkix-lint.effective-end",
    )?;

    // Subjects → scope.
    let subjects = obj
        .get("subjects")
        .and_then(Value::as_array)
        .ok_or(ParseError::SubjectsNotArray { index: idx })?;
    let first_subject = subjects
        .first()
        .ok_or(ParseError::MissingSubject { index: idx })?;
    let scope = parse_subject(idx, first_subject)?;

    // Links → evidence_uri (first `rel=reference` link wins).
    let evidence_uri = parse_evidence_uri(obj.get("links"));

    Ok(Deviation {
        id,
        target_lint,
        scope,
        effective_start,
        effective_end,
        action,
        justification,
        authorized_by,
        evidence_uri,
    })
}

fn required_nonempty_prop<'a>(
    idx: usize,
    value: Option<&'a str>,
    name: &'static str,
) -> Result<&'a str, ParseError> {
    let s = value.ok_or(ParseError::MissingProp { index: idx, name })?;
    if s.is_empty() {
        return Err(ParseError::EmptyProp { index: idx, name });
    }
    Ok(s)
}

fn parse_action(idx: usize, s: &str) -> Result<DeviationAction, ParseError> {
    if s == "suppress" {
        return Ok(DeviationAction::Suppress);
    }
    if let Some(rest) = s.strip_prefix("downgrade:") {
        let sev = match rest {
            "info" => Severity::Info,
            "notice" => Severity::Notice,
            "warn" => Severity::Warn,
            "error" => Severity::Error,
            "fatal" => Severity::Fatal,
            _ => {
                return Err(ParseError::UnknownAction {
                    index: idx,
                    found: s.to_string(),
                });
            }
        };
        return Ok(DeviationAction::DowngradeSeverityTo(sev));
    }
    Err(ParseError::UnknownAction {
        index: idx,
        found: s.to_string(),
    })
}

fn parse_optional_u64(
    idx: usize,
    value: Option<&str>,
    prop_name: &'static str,
) -> Result<Option<u64>, ParseError> {
    match value {
        None => Ok(None),
        Some(v) => v
            .parse::<u64>()
            .map(Some)
            .map_err(|_| ParseError::InvalidU64 {
                index: idx,
                prop: prop_name,
                found: v.to_string(),
            }),
    }
}

fn parse_subject(idx: usize, subj: &Value) -> Result<DeviationScope, ParseError> {
    let obj = subj
        .as_object()
        .ok_or(ParseError::SubjectNotObject { index: idx })?;
    let ty = obj
        .get("type")
        .and_then(Value::as_str)
        .ok_or(ParseError::SubjectMissingType { index: idx })?;
    let props_slice: Option<&[Value]> = obj
        .get("props")
        .and_then(Value::as_array)
        .map(Vec::as_slice);
    let get_prop = |name: &'static str| -> Option<&str> { find_prop_value(props_slice, name) };
    let required = |name: &'static str| -> Result<&str, ParseError> {
        get_prop(name).ok_or(ParseError::MissingSubjectProp { index: idx, name })
    };

    use crate::deviation::{
        PROP_ISSUER_DN_DER, PROP_ISSUER_DN_SUBSTRING, PROP_SERIAL_END, PROP_SERIAL_START,
        SCOPE_KIND_ANY, SCOPE_KIND_ISSUER_DN_CONTAINS, SCOPE_KIND_ISSUER_DN_EXACT,
        SCOPE_KIND_SERIAL_RANGE,
    };
    match ty {
        SCOPE_KIND_ANY => Ok(DeviationScope::any()),

        SCOPE_KIND_ISSUER_DN_CONTAINS => {
            let substring = required(PROP_ISSUER_DN_SUBSTRING)?.to_string();
            Ok(DeviationScope::issuer_dn_contains(substring))
        }

        SCOPE_KIND_ISSUER_DN_EXACT => {
            let der_hex = required(PROP_ISSUER_DN_DER)?;
            let der = hex_decode(der_hex).ok_or(ParseError::MalformedHex {
                index: idx,
                prop: PROP_ISSUER_DN_DER,
            })?;
            let name = decode_name(idx, &der, PROP_ISSUER_DN_DER)?;
            DeviationScope::issuer_dn_exact(&name).map_err(|_| ParseError::MalformedDer {
                index: idx,
                prop: PROP_ISSUER_DN_DER,
            })
        }

        SCOPE_KIND_SERIAL_RANGE => {
            let der_hex = required(PROP_ISSUER_DN_DER)?;
            let der = hex_decode(der_hex).ok_or(ParseError::MalformedHex {
                index: idx,
                prop: PROP_ISSUER_DN_DER,
            })?;
            let issuer = decode_name(idx, &der, PROP_ISSUER_DN_DER)?;
            let start_hex = required(PROP_SERIAL_START)?;
            let start = hex_decode(start_hex).ok_or(ParseError::MalformedHex {
                index: idx,
                prop: PROP_SERIAL_START,
            })?;
            let end_hex = required(PROP_SERIAL_END)?;
            let end = hex_decode(end_hex).ok_or(ParseError::MalformedHex {
                index: idx,
                prop: PROP_SERIAL_END,
            })?;
            DeviationScope::serial_range(&issuer, start, end).map_err(|_| {
                ParseError::MalformedDer {
                    index: idx,
                    prop: PROP_ISSUER_DN_DER,
                }
            })
        }

        other => Err(ParseError::UnknownSubjectType {
            index: idx,
            found: other.to_string(),
        }),
    }
}

fn decode_name(
    idx: usize,
    der: &[u8],
    prop: &'static str,
) -> Result<x509_cert::name::Name, ParseError> {
    use der::Decode as _;
    if der.is_empty() {
        return Err(ParseError::MalformedDer { index: idx, prop });
    }
    x509_cert::name::Name::from_der(der).map_err(|_| ParseError::MalformedDer { index: idx, prop })
}

/// Find the first link with `rel == "reference"` and return its `href`.
///
/// Mirrors the emit shape: `risks_from_store` writes a single-element
/// `links` array with `rel=reference` and `text="Deviation authorization
/// document"` when `evidence_uri` is `Some`. The parser ignores `text`
/// and trusts only `rel` as the discriminator.
fn parse_evidence_uri(links: Option<&Value>) -> Option<String> {
    let arr = links?.as_array()?;
    for link in arr {
        let obj = match link.as_object() {
            Some(o) => o,
            None => continue,
        };
        let rel = obj.get("rel").and_then(Value::as_str);
        if rel == Some("reference") {
            if let Some(href) = obj.get("href").and_then(Value::as_str) {
                return Some(href.to_string());
            }
        }
    }
    None
}

fn find_prop_value<'a>(props: Option<&'a [Value]>, name: &str) -> Option<&'a str> {
    let arr = props?;
    arr.iter()
        .filter_map(Value::as_object)
        .find(|obj| obj.get("name").and_then(Value::as_str) == Some(name))
        .and_then(|obj| obj.get("value").and_then(Value::as_str))
}

/// Local hex-string decoder. Returns `None` on odd-length input or any
/// non-hex byte. Kept inline to avoid pulling in a hex crate dependency
/// just for this parser. Matches the encoder at
/// [`super::emit`]: lowercase emit, parser accepts mixed case.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = nibble(bytes[i])?;
        let lo = nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// OSCAL Catalog parsing (PKIX-9vnx.6.3)
// ---------------------------------------------------------------------------

/// Extract the ordered list of Control ids from an OSCAL Catalog JSON
/// [`Value`].
///
/// The parser is intentionally narrow — it matches the shape emitted by
/// [`super::catalog::catalog_from_lints`], not arbitrary OSCAL Catalogs.
/// Specifically, it accepts a top-level `{"catalog": { "controls":
/// [{"id": "…"}, …]}}` document. Catalogs that nest Controls inside
/// `groups[]`, or that pin Control ids on `class` instead of `id`, are
/// outside this parser's contract.
///
/// Returns the Control ids in document order — same order
/// [`super::catalog::catalog_from_lints`] emitted them.
///
/// # Errors
///
/// * [`ParseError::CatalogNotObject`] — top-level value is not a JSON
///   object.
/// * [`ParseError::CatalogMissingWrapper`] — the required `catalog` key
///   is absent or not a JSON object.
/// * [`ParseError::ControlsNotArray`] — the `controls` field is missing
///   or not a JSON array.
/// * [`ParseError::ControlNotObject`], [`ControlMissingId`], etc. —
///   per-Control validation errors with the index of the offending
///   entry.
///
/// [`ControlMissingId`]: ParseError::ControlMissingId
pub fn lint_ids_from_catalog(value: &Value) -> Result<Vec<String>, ParseError> {
    let obj = value.as_object().ok_or(ParseError::CatalogNotObject)?;
    let catalog = obj
        .get("catalog")
        .and_then(|c| c.as_object())
        .ok_or(ParseError::CatalogMissingWrapper)?;
    let controls = catalog
        .get("controls")
        .and_then(|c| c.as_array())
        .ok_or(ParseError::ControlsNotArray)?;

    let mut ids: Vec<String> = Vec::with_capacity(controls.len());
    for (index, control) in controls.iter().enumerate() {
        let control_obj = control
            .as_object()
            .ok_or(ParseError::ControlNotObject { index })?;
        let id_value = control_obj
            .get("id")
            .ok_or(ParseError::ControlMissingId { index })?;
        let id_str = id_value
            .as_str()
            .ok_or(ParseError::ControlIdNotString { index })?;
        if id_str.is_empty() {
            return Err(ParseError::ControlIdEmpty { index });
        }
        ids.push(id_str.to_owned());
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deviation::{Deviation, DeviationAction, DeviationScope, DeviationStore};
    use crate::Severity;
    use serde_json::{json, Value};

    // -----------------------------------------------------------------
    // Round-trip closure: emit -> parse -> Eq
    //
    // The independent oracle here is the emit half — by construction
    // (emit . parse) must be the identity over any value produced by
    // emit. Tests assert *both* directions: parse accepts what emit
    // produces, and the reconstructed store compares Eq to the source
    // store. Where a fixture file is required (real Name DER bytes), we
    // load the PKITS GoodCACert.crt — the same fixture emit uses.
    // -----------------------------------------------------------------

    fn sample_deviation_contains() -> Deviation {
        Deviation {
            id: "policy-2026-fpki-keyusage-q1".to_string(),
            target_lint: "fpki.common.6.1.5".to_string(),
            scope: DeviationScope::issuer_dn_contains("agency x issuing ca"),
            effective_start: Some(1_704_067_200),
            effective_end: Some(1_767_225_600),
            action: DeviationAction::DowngradeSeverityTo(Severity::Warn),
            justification: "FPKIPA waiver memo 2025-11-03; see exception register entry 47"
                .to_string(),
            authorized_by: "agency-x-ciso@agency.gov".to_string(),
            evidence_uri: Some("https://pkipolicy.agency.gov/waivers/2025-11-03".to_string()),
        }
    }

    #[test]
    fn round_trip_issuer_dn_contains_full_fields() {
        let mut store = DeviationStore::new();
        store.add(sample_deviation_contains()).expect("add");
        let risks = super::super::emit::risks_from_store(&store);
        let value = Value::Array(risks);
        let parsed = deviation_store_from_risks(&value).expect("parse");
        assert_eq!(parsed, store);
    }

    #[test]
    fn round_trip_suppress_and_any_scope() {
        let mut store = DeviationStore::new();
        store
            .add(Deviation {
                id: "policy-internal-ca-suppress".to_string(),
                target_lint: "rfc5280.keyusage.required".to_string(),
                scope: DeviationScope::any(),
                effective_start: None,
                effective_end: None,
                action: DeviationAction::Suppress,
                justification: "Internal lab CA, never published to relying parties".to_string(),
                authorized_by: "lab-lead@example.com".to_string(),
                evidence_uri: None,
            })
            .expect("add");
        let risks = super::super::emit::risks_from_store(&store);
        let parsed = deviation_store_from_risks(&Value::Array(risks)).expect("parse");
        assert_eq!(parsed, store);
    }

    /// Helper: try to load the PKITS GoodCACert.crt fixture used by the
    /// emit tests, returning `None` if it's not present (so the test
    /// can be skipped in environments without PKITS, mirroring the
    /// emit-side pattern at `emit::tests::test_encode_scope_issuer_dn_exact_carries_der`).
    fn load_pkits_good_ca() -> Option<x509_cert::Certificate> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../pkix-path/tests/pkits/certs/GoodCACert.crt");
        let bytes = std::fs::read(&path).ok()?;
        use der::Decode as _;
        x509_cert::Certificate::from_der(&bytes).ok()
    }

    #[test]
    fn round_trip_issuer_dn_exact() {
        let Some(cert) = load_pkits_good_ca() else {
            eprintln!("PKITS GoodCACert.crt not available — skipping");
            return;
        };
        let mut store = DeviationStore::new();
        store
            .add(Deviation {
                id: "policy-good-ca-exact".to_string(),
                target_lint: "rfc5280.bc.ca-true-required".to_string(),
                scope: DeviationScope::issuer_dn_exact(&cert.tbs_certificate.subject)
                    .expect("DER encode"),
                effective_start: None,
                effective_end: Some(2_000_000_000),
                action: DeviationAction::DowngradeSeverityTo(Severity::Info),
                justification: "Known intermediate; waiver tracked in eng-pki #42".to_string(),
                authorized_by: "pki-lead@example.com".to_string(),
                evidence_uri: None,
            })
            .expect("add");
        let risks = super::super::emit::risks_from_store(&store);
        let parsed = deviation_store_from_risks(&Value::Array(risks)).expect("parse");
        assert_eq!(parsed, store);
    }

    #[test]
    fn round_trip_serial_range() {
        let Some(cert) = load_pkits_good_ca() else {
            eprintln!("PKITS GoodCACert.crt not available — skipping");
            return;
        };
        let mut store = DeviationStore::new();
        store
            .add(Deviation {
                id: "policy-batch-2026-q1".to_string(),
                target_lint: "rfc5280.serial.unique".to_string(),
                scope: DeviationScope::serial_range(
                    &cert.tbs_certificate.subject,
                    vec![0x01, 0x00],
                    vec![0x01, 0xff],
                )
                .expect("DER encode"),
                effective_start: Some(1_704_067_200),
                effective_end: Some(1_711_929_600),
                action: DeviationAction::DowngradeSeverityTo(Severity::Warn),
                justification: "Issuance batch from Q1 2024 known-collision regenerated"
                    .to_string(),
                authorized_by: "ca-ops@example.com".to_string(),
                evidence_uri: Some(
                    "https://pki.example.com/incidents/2024-q1-serial-coll".to_string(),
                ),
            })
            .expect("add");
        let risks = super::super::emit::risks_from_store(&store);
        let parsed = deviation_store_from_risks(&Value::Array(risks)).expect("parse");
        assert_eq!(parsed, store);
    }

    #[test]
    fn round_trip_optional_fields_all_none() {
        let mut store = DeviationStore::new();
        store
            .add(Deviation {
                id: "policy-no-optionals".to_string(),
                target_lint: "rfc5280.aki.required".to_string(),
                scope: DeviationScope::any(),
                effective_start: None,
                effective_end: None,
                action: DeviationAction::Suppress,
                justification: "Bootstrap root that predates AKI requirement".to_string(),
                authorized_by: "ops@example.com".to_string(),
                evidence_uri: None,
            })
            .expect("add");
        let risks = super::super::emit::risks_from_store(&store);
        let parsed = deviation_store_from_risks(&Value::Array(risks)).expect("parse");
        assert_eq!(parsed, store);

        // Verify the parsed back deviation actually has all three
        // optional fields set to None (defends against a parser that
        // silently fills defaults).
        let d = &parsed.all()[0];
        assert!(d.effective_start.is_none());
        assert!(d.effective_end.is_none());
        assert!(d.evidence_uri.is_none());
    }

    #[test]
    fn round_trip_multi_deviation_store() {
        // Two deviations with different scopes and actions — exercises
        // the loop over the input array as well as DeviationStore::add's
        // duplicate-id check (no duplicates here, so add succeeds twice).
        let mut store = DeviationStore::new();
        store.add(sample_deviation_contains()).expect("add 1");
        store
            .add(Deviation {
                id: "policy-second-suppress".to_string(),
                action: DeviationAction::Suppress,
                scope: DeviationScope::any(),
                ..sample_deviation_contains()
            })
            .expect("add 2");
        let risks = super::super::emit::risks_from_store(&store);
        assert_eq!(risks.len(), 2);
        let parsed = deviation_store_from_risks(&Value::Array(risks)).expect("parse");
        assert_eq!(parsed, store);
    }

    // -----------------------------------------------------------------
    // Negative tests — every ParseError variant has an explicit fixture.
    //
    // Test inputs are hand-assembled at the JSON layer (not via emit
    // mutation) so that future refactors of emit cannot inadvertently
    // weaken the malformed-input contract.
    // -----------------------------------------------------------------

    #[test]
    fn rejects_top_level_non_array() {
        let v = json!({"not": "an array"});
        let err = deviation_store_from_risks(&v).expect_err("should fail");
        assert!(matches!(err, ParseError::NotArray));
    }

    #[test]
    fn rejects_risk_not_object() {
        let v = json!(["not-an-object"]);
        let err = deviation_store_from_risks(&v).expect_err("should fail");
        assert!(matches!(err, ParseError::RiskNotObject { index: 0 }));
    }

    #[test]
    fn rejects_wrong_status() {
        let v = json!([{
            "uuid": "00000000-0000-8000-8000-000000000000",
            "status": "open",
            "description": "x",
            "props": [],
            "subjects": [{"type": "pkix-lint.scope.any"}]
        }]);
        let err = deviation_store_from_risks(&v).expect_err("should fail");
        match err {
            ParseError::InvalidStatus { index: 0, found } => assert_eq!(found, "open"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn rejects_missing_description() {
        let v = json!([{
            "uuid": "00000000-0000-8000-8000-000000000000",
            "status": "deviation-approved",
            "props": [],
            "subjects": [{"type": "pkix-lint.scope.any"}]
        }]);
        let err = deviation_store_from_risks(&v).expect_err("should fail");
        assert!(matches!(err, ParseError::MissingDescription { index: 0 }));
    }

    /// Build a minimal valid Risk object that the test can mutate to
    /// exercise individual error paths without re-typing the bulk of the
    /// shape.
    fn minimal_valid_risk() -> Value {
        json!({
            "uuid": "00000000-0000-8000-8000-000000000000",
            "status": "deviation-approved",
            "description": "j",
            "props": [
                {"name": "pkix-lint.deviation-id", "value": "d1", "ns": "https://pkix.rs/oscal/pkix-lint"},
                {"name": "pkix-lint.target-lint",  "value": "t1", "ns": "https://pkix.rs/oscal/pkix-lint"},
                {"name": "pkix-lint.action",       "value": "suppress", "ns": "https://pkix.rs/oscal/pkix-lint"},
                {"name": "pkix-lint.authorized-by","value": "a1", "ns": "https://pkix.rs/oscal/pkix-lint"}
            ],
            "subjects": [{"type": "pkix-lint.scope.any"}]
        })
    }

    /// Drop a prop by name from a Risk JSON value. Panics if the value
    /// shape isn't `{"props": [...]}`.
    fn drop_prop(risk: &mut Value, name: &str) {
        let props = risk["props"].as_array_mut().expect("props array");
        props.retain(|p| p["name"].as_str() != Some(name));
    }

    /// Set a prop value by name on a Risk JSON value, adding the prop if
    /// it doesn't exist.
    fn set_prop(risk: &mut Value, name: &str, value: &str) {
        let props = risk["props"].as_array_mut().expect("props array");
        if let Some(existing) = props.iter_mut().find(|p| p["name"].as_str() == Some(name)) {
            existing["value"] = Value::String(value.to_string());
        } else {
            props.push(json!({
                "name": name,
                "value": value,
                "ns": "https://pkix.rs/oscal/pkix-lint",
            }));
        }
    }

    #[test]
    fn rejects_missing_required_prop_deviation_id() {
        let mut risk = minimal_valid_risk();
        drop_prop(&mut risk, "pkix-lint.deviation-id");
        let err = deviation_store_from_risks(&Value::Array(vec![risk])).expect_err("should fail");
        assert!(matches!(
            err,
            ParseError::MissingProp {
                index: 0,
                name: "pkix-lint.deviation-id"
            }
        ));
    }

    #[test]
    fn rejects_missing_required_prop_target_lint() {
        let mut risk = minimal_valid_risk();
        drop_prop(&mut risk, "pkix-lint.target-lint");
        let err = deviation_store_from_risks(&Value::Array(vec![risk])).expect_err("should fail");
        assert!(matches!(
            err,
            ParseError::MissingProp {
                index: 0,
                name: "pkix-lint.target-lint"
            }
        ));
    }

    #[test]
    fn rejects_missing_required_prop_action() {
        let mut risk = minimal_valid_risk();
        drop_prop(&mut risk, "pkix-lint.action");
        let err = deviation_store_from_risks(&Value::Array(vec![risk])).expect_err("should fail");
        assert!(matches!(
            err,
            ParseError::MissingProp {
                index: 0,
                name: "pkix-lint.action"
            }
        ));
    }

    #[test]
    fn rejects_missing_required_prop_authorized_by() {
        let mut risk = minimal_valid_risk();
        drop_prop(&mut risk, "pkix-lint.authorized-by");
        let err = deviation_store_from_risks(&Value::Array(vec![risk])).expect_err("should fail");
        assert!(matches!(
            err,
            ParseError::MissingProp {
                index: 0,
                name: "pkix-lint.authorized-by"
            }
        ));
    }

    #[test]
    fn rejects_empty_required_prop() {
        let mut risk = minimal_valid_risk();
        set_prop(&mut risk, "pkix-lint.deviation-id", "");
        let err = deviation_store_from_risks(&Value::Array(vec![risk])).expect_err("should fail");
        assert!(matches!(
            err,
            ParseError::EmptyProp {
                index: 0,
                name: "pkix-lint.deviation-id"
            }
        ));
    }

    #[test]
    fn rejects_unknown_action_bare() {
        let mut risk = minimal_valid_risk();
        set_prop(&mut risk, "pkix-lint.action", "ignore");
        let err = deviation_store_from_risks(&Value::Array(vec![risk])).expect_err("should fail");
        match err {
            ParseError::UnknownAction { index: 0, found } => assert_eq!(found, "ignore"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_action_unknown_severity() {
        let mut risk = minimal_valid_risk();
        set_prop(&mut risk, "pkix-lint.action", "downgrade:critical");
        let err = deviation_store_from_risks(&Value::Array(vec![risk])).expect_err("should fail");
        match err {
            ParseError::UnknownAction { index: 0, found } => {
                assert_eq!(found, "downgrade:critical");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_u64_effective_start() {
        let mut risk = minimal_valid_risk();
        set_prop(&mut risk, "pkix-lint.effective-start", "not-a-number");
        let err = deviation_store_from_risks(&Value::Array(vec![risk])).expect_err("should fail");
        match err {
            ParseError::InvalidU64 {
                index: 0,
                prop,
                found,
            } => {
                assert_eq!(prop, "pkix-lint.effective-start");
                assert_eq!(found, "not-a-number");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn rejects_missing_subjects_array() {
        let mut risk = minimal_valid_risk();
        risk.as_object_mut().unwrap().remove("subjects");
        let err = deviation_store_from_risks(&Value::Array(vec![risk])).expect_err("should fail");
        assert!(matches!(err, ParseError::SubjectsNotArray { index: 0 }));
    }

    #[test]
    fn rejects_empty_subjects_array() {
        let mut risk = minimal_valid_risk();
        risk["subjects"] = json!([]);
        let err = deviation_store_from_risks(&Value::Array(vec![risk])).expect_err("should fail");
        assert!(matches!(err, ParseError::MissingSubject { index: 0 }));
    }

    #[test]
    fn rejects_subject_missing_type() {
        let mut risk = minimal_valid_risk();
        risk["subjects"] = json!([{"title": "no type here"}]);
        let err = deviation_store_from_risks(&Value::Array(vec![risk])).expect_err("should fail");
        assert!(matches!(err, ParseError::SubjectMissingType { index: 0 }));
    }

    #[test]
    fn rejects_unknown_subject_type() {
        let mut risk = minimal_valid_risk();
        risk["subjects"] = json!([{"type": "pkix-lint.scope.future-variant"}]);
        let err = deviation_store_from_risks(&Value::Array(vec![risk])).expect_err("should fail");
        match err {
            ParseError::UnknownSubjectType { index: 0, found } => {
                assert_eq!(found, "pkix-lint.scope.future-variant");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn rejects_missing_subject_prop_substring() {
        let mut risk = minimal_valid_risk();
        risk["subjects"] = json!([{
            "type": "pkix-lint.scope.issuer-dn-contains",
            "props": []
        }]);
        let err = deviation_store_from_risks(&Value::Array(vec![risk])).expect_err("should fail");
        assert!(matches!(
            err,
            ParseError::MissingSubjectProp {
                index: 0,
                name: "pkix-lint.issuer-dn-substring"
            }
        ));
    }

    #[test]
    fn rejects_malformed_hex_in_dn_der() {
        let mut risk = minimal_valid_risk();
        risk["subjects"] = json!([{
            "type": "pkix-lint.scope.issuer-dn-exact",
            "props": [
                {"name": "pkix-lint.issuer-dn-der", "value": "not-hex", "ns": "https://pkix.rs/oscal/pkix-lint"}
            ]
        }]);
        let err = deviation_store_from_risks(&Value::Array(vec![risk])).expect_err("should fail");
        assert!(matches!(
            err,
            ParseError::MalformedHex {
                index: 0,
                prop: "pkix-lint.issuer-dn-der"
            }
        ));
    }

    #[test]
    fn rejects_empty_der_for_issuer_dn_exact() {
        let mut risk = minimal_valid_risk();
        risk["subjects"] = json!([{
            "type": "pkix-lint.scope.issuer-dn-exact",
            "props": [
                {"name": "pkix-lint.issuer-dn-der", "value": "", "ns": "https://pkix.rs/oscal/pkix-lint"}
            ]
        }]);
        let err = deviation_store_from_risks(&Value::Array(vec![risk])).expect_err("should fail");
        assert!(matches!(
            err,
            ParseError::MalformedDer {
                index: 0,
                prop: "pkix-lint.issuer-dn-der"
            }
        ));
    }

    #[test]
    fn rejects_garbage_der_for_issuer_dn_exact() {
        let mut risk = minimal_valid_risk();
        // Valid-hex but not a valid X.509 Name encoding.
        risk["subjects"] = json!([{
            "type": "pkix-lint.scope.issuer-dn-exact",
            "props": [
                {"name": "pkix-lint.issuer-dn-der", "value": "deadbeef", "ns": "https://pkix.rs/oscal/pkix-lint"}
            ]
        }]);
        let err = deviation_store_from_risks(&Value::Array(vec![risk])).expect_err("should fail");
        assert!(matches!(
            err,
            ParseError::MalformedDer {
                index: 0,
                prop: "pkix-lint.issuer-dn-der"
            }
        ));
    }

    #[test]
    fn rejects_serial_range_missing_serial_start() {
        let Some(cert) = load_pkits_good_ca() else {
            eprintln!("PKITS GoodCACert.crt not available — skipping");
            return;
        };
        use der::Encode as _;
        let der = cert.tbs_certificate.subject.to_der().expect("encode");
        let der_hex: String = der.iter().map(|b| format!("{b:02x}")).collect();
        let mut risk = minimal_valid_risk();
        risk["subjects"] = json!([{
            "type": "pkix-lint.scope.serial-range",
            "props": [
                {"name": "pkix-lint.issuer-dn-der", "value": der_hex, "ns": "https://pkix.rs/oscal/pkix-lint"},
                {"name": "pkix-lint.serial-end",    "value": "01ff",   "ns": "https://pkix.rs/oscal/pkix-lint"}
            ]
        }]);
        let err = deviation_store_from_risks(&Value::Array(vec![risk])).expect_err("should fail");
        assert!(matches!(
            err,
            ParseError::MissingSubjectProp {
                index: 0,
                name: "pkix-lint.serial-start"
            }
        ));
    }

    #[test]
    fn rejects_duplicate_id_in_input() {
        // Two Risks with the same `pkix-lint.deviation-id`. The first
        // adds successfully; the second triggers DeviationStore::add's
        // duplicate check via ParseError::AddFailed.
        let v = Value::Array(vec![minimal_valid_risk(), minimal_valid_risk()]);
        let err = deviation_store_from_risks(&v).expect_err("should fail");
        match err {
            ParseError::AddFailed { index: 1, source } => {
                assert!(matches!(source, DeviationAddError::DuplicateId(_)))
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn empty_input_yields_empty_store() {
        let v = Value::Array(vec![]);
        let parsed = deviation_store_from_risks(&v).expect("parse");
        assert_eq!(parsed, DeviationStore::new());
    }

    #[test]
    fn parser_accepts_uppercase_hex() {
        // hex_decode is case-insensitive; the emitter writes lowercase
        // but a hand-edited deviation file may use uppercase. This
        // codifies that the parser does not require strict lowercase.
        assert_eq!(hex_decode("DEAD"), Some(vec![0xde, 0xad]));
        assert_eq!(hex_decode("dead"), Some(vec![0xde, 0xad]));
        assert_eq!(hex_decode("DeAd"), Some(vec![0xde, 0xad]));
        assert_eq!(hex_decode("DEA"), None); // odd length
        assert_eq!(hex_decode("XYZW"), None); // non-hex
    }

    #[test]
    fn parse_action_covers_all_severity_variants() {
        assert!(matches!(
            parse_action(0, "suppress"),
            Ok(DeviationAction::Suppress)
        ));
        assert!(matches!(
            parse_action(0, "downgrade:info"),
            Ok(DeviationAction::DowngradeSeverityTo(Severity::Info))
        ));
        assert!(matches!(
            parse_action(0, "downgrade:notice"),
            Ok(DeviationAction::DowngradeSeverityTo(Severity::Notice))
        ));
        assert!(matches!(
            parse_action(0, "downgrade:warn"),
            Ok(DeviationAction::DowngradeSeverityTo(Severity::Warn))
        ));
        assert!(matches!(
            parse_action(0, "downgrade:error"),
            Ok(DeviationAction::DowngradeSeverityTo(Severity::Error))
        ));
        assert!(matches!(
            parse_action(0, "downgrade:fatal"),
            Ok(DeviationAction::DowngradeSeverityTo(Severity::Fatal))
        ));
    }

    #[test]
    fn second_link_with_rel_reference_is_ignored_when_first_matches() {
        // emit only writes one link, but the parser should be deterministic
        // when faced with two — first-match wins.
        let mut store = DeviationStore::new();
        store
            .add(Deviation {
                evidence_uri: Some("https://first.example.com/".to_string()),
                ..sample_deviation_contains()
            })
            .expect("add");
        let mut risks = super::super::emit::risks_from_store(&store);
        // Append a second rel=reference link to the first Risk.
        risks[0]["links"]
            .as_array_mut()
            .expect("links array")
            .push(json!({
                "href": "https://second.example.com/",
                "rel": "reference",
                "text": "Deviation authorization document",
            }));
        let parsed = deviation_store_from_risks(&Value::Array(risks)).expect("parse");
        assert_eq!(
            parsed.all()[0].evidence_uri.as_deref(),
            Some("https://first.example.com/")
        );
    }
}
