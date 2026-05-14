//! OSCAL Profile composition for pkix-lint.
//!
//! Implements OSCAL Profile resolution semantics — `import` references,
//! `include-controls` / `exclude-controls` filters, and
//! `modify.set-parameters` overrides — for callers who choose OSCAL
//! Profile JSON as their lint-bundle composition format. OSCAL Profile
//! semantics are one supported way to compose pkix-lint bundles, not the
//! mandated workspace mechanism: callers can equally compose bundles
//! directly via [`crate::LintRunner::filter_to_ids`] and
//! [`crate::LintRunner::apply_parameter_overrides`] without ever
//! producing an OSCAL document. See `pkix-lint/src/oscal/mod.rs` for the
//! framing.
//!
//! This module is the resolver. Given an OSCAL Profile
//! [`serde_json::Value`] and a `sources` map of referenced Catalogs
//! and Profiles, [`resolve_profile`] produces a [`ResolvedProfile`]
//! whose `control_ids` plug into [`crate::LintRunner::filter_to_ids`]
//! and whose `parameter_overrides` plug into
//! [`crate::LintRunner::apply_parameter_overrides`].
//!
//! # Composition examples
//!
//! Three composition shapes are supported (and pinned by tests in this
//! module):
//!
//! 1. **Plain Profile** — a Profile imports one Catalog and selects a
//!    subset of Controls.
//! 2. **Layered Profile** — a Profile imports several Catalogs (or
//!    Catalogs + a transitively-imported Profile), each with their own
//!    include/exclude filters, then layers `set-parameters` overrides on
//!    top.
//! 3. **Override Profile** — a Profile imports another Profile (which
//!    already imports a Catalog), inheriting its selections and adding
//!    targeted `exclude-controls` to disable specific Controls or
//!    additional `set-parameters` to tighten parameter values.
//!
//! # `import.href` resolution
//!
//! Each `imports[].href` is matched verbatim against the keys of the
//! `sources` map. Callers may use any href scheme they like — local
//! fragment identifiers (`"#rs.pkix.rfc5280"`), URIs
//! (`"file:///etc/pkix-lint/catalogs/rfc5280.json"`), or stable opaque
//! strings — provided the same string keys the corresponding entry in
//! `sources`. The resolver does not perform any I/O.
//!
//! # Cycle detection
//!
//! Profile-imports-Profile chains are walked recursively. The resolver
//! tracks the set of hrefs currently on the import stack and returns
//! [`ParseError::ProfileImportCycle`] if an import would revisit one,
//! preserving the offending href for the operator.
//!
//! # OSCAL Profile shape accepted
//!
//! The parser is intentionally narrow — it implements the directives
//! named in the PKIX-9vnx.7 acceptance criteria and the subset of the
//! OSCAL Profile model `pkix-lint` needs. Specifically:
//!
//! * `profile.imports[].href` — required string, looked up in `sources`.
//! * `profile.imports[].include-all` — when present (as `{}`), every
//!   Control id in the imported source is included before exclude
//!   filters apply.
//! * `profile.imports[].include-controls[].with-ids[]` — explicit ids to
//!   include. Multiple `include-controls` entries are unioned.
//! * `profile.imports[].exclude-controls[].with-ids[]` — explicit ids
//!   to drop *after* include filters. Multiple `exclude-controls` entries
//!   are unioned.
//! * `profile.modify.set-parameters[].param-id` and `values[0]` —
//!   parameter overrides addressed by the composite param id
//!   ([`crate::oscal::catalog`] emits Catalog Parameters with the
//!   composite id `<lint_id>.<param_id>`; Profile `modify.set-parameters`
//!   must reference that same id).
//!
//! Other OSCAL Profile fields (`merge.combine`, `modify.alters`,
//! `back-matter`, custom `merge.custom`) are not interpreted. Profiles
//! that rely on them must either drop those directives or compose them
//! with an external OSCAL toolchain first.
//!
//! # Provenance
//!
//! Added in PKIX-9vnx.7. Subsumes the scope of PKIX-9vnx.6.5 (the
//! standalone parameter-overrides extractor) — `set-parameters` is
//! handled here as part of the broader Profile-resolution flow.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

use super::parse::{lint_ids_from_catalog, ParseError};

/// Output of [`resolve_profile`]: the ordered list of Control ids the
/// composed Profile selects, plus the parameter overrides it carries.
///
/// `control_ids` is in document order across imports, with duplicates
/// removed (first occurrence wins). `parameter_overrides` is in the
/// order the `modify.set-parameters` directives appear in the Profile,
/// after recursive resolution of imports — inner Profile overrides
/// precede outer Profile overrides, so an outer Profile that sets the
/// same parameter takes effect last.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolvedProfile {
    /// Ordered set of OSCAL Control ids selected by the Profile.
    pub control_ids: Vec<String>,
    /// Parameter overrides extracted from `modify.set-parameters`
    /// directives, in resolution order.
    pub parameter_overrides: Vec<ParameterOverride>,
}

impl ResolvedProfile {
    /// Construct a [`ResolvedProfile`] with the listed control ids and
    /// parameter overrides.
    ///
    /// Use this constructor instead of struct-literal syntax so future
    /// fields (the OSCAL Profile model carries `merge.combine`,
    /// `modify.alters`, `back-matter` that are not interpreted today
    /// per this crate's rustdoc) remain non-breaking additions. The
    /// struct carries `#[non_exhaustive]`.
    #[must_use]
    pub fn new(control_ids: Vec<String>, parameter_overrides: Vec<ParameterOverride>) -> Self {
        Self {
            control_ids,
            parameter_overrides,
        }
    }
}

/// A single OSCAL `set-parameter` directive resolved against a Catalog.
///
/// `param_id` is the composite OSCAL Parameter id
/// (`<lint_id>.<param_id>`) emitted by
/// [`crate::oscal::catalog::catalog_from_lints`]. `value` is the first
/// entry of the directive's `values` array.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParameterOverride {
    /// Composite OSCAL Parameter id (`<lint_id>.<param_id>`).
    pub param_id: String,
    /// Override value, rendered as a string per the OSCAL Parameter
    /// model.
    pub value: String,
}

impl ParameterOverride {
    /// Construct a [`ParameterOverride`].
    ///
    /// Use this constructor instead of struct-literal syntax so future
    /// fields (the OSCAL Parameter model carries `constraint`,
    /// `guideline`, `select`, `link` shape mentioned in the
    /// [`crate::LintParameter`] rustdoc) remain non-breaking additions.
    /// The struct carries `#[non_exhaustive]`.
    #[must_use]
    pub fn new(param_id: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            param_id: param_id.into(),
            value: value.into(),
        }
    }
}

/// Resolve an OSCAL Profile [`Value`] into a flat list of selected
/// Control ids plus parameter overrides.
///
/// `profile` is the top-level OSCAL Profile JSON value (a JSON object
/// whose only top-level key is `"profile"`). `sources` maps every href
/// referenced transitively by the Profile to its source [`Value`],
/// which must itself be either an OSCAL Catalog
/// (`{"catalog": {...}}`) or another OSCAL Profile
/// (`{"profile": {...}}`).
///
/// # Errors
///
/// * [`ParseError::ProfileNotObject`] — the top-level value is not a
///   JSON object.
/// * [`ParseError::ProfileMissingWrapper`] — the required `profile`
///   key is absent or not an object.
/// * [`ParseError::ProfileImportsNotArray`] — `profile.imports` is
///   missing or not an array.
/// * [`ParseError::ProfileImportMissingHref`] / `ProfileImportHrefNotString`
///   — an import is missing its `href` or has a non-string href.
/// * [`ParseError::ProfileImportUnresolved`] — an import's href has no
///   entry in `sources`.
/// * [`ParseError::ProfileImportCycle`] — Profile-imports-Profile
///   chain visits the same href twice.
/// * [`ParseError::ProfileImportSourceUnknown`] — a `sources` entry is
///   neither a Catalog nor a Profile.
/// * [`ParseError::ProfileIncludeControlsNotArray`] /
///   `ProfileExcludeControlsNotArray` — directive value is not an
///   array.
/// * [`ParseError::ProfileWithIdsNotArray`] — a
///   `with-ids` slot is not an array of strings.
/// * [`ParseError::ProfileSetParameterMissingId` /
///   `ProfileSetParameterValuesNotArray` /
///   `ProfileSetParameterValuesEmpty`] — a `set-parameters` entry is
///   malformed.
/// * Plus any [`ParseError`] surfaced from
///   [`lint_ids_from_catalog`] when an imported Catalog is malformed.
///
/// # OSCAL spec references
///
/// - NIST OSCAL v1.1.2 Profile model:
///   <https://pages.nist.gov/OSCAL/concepts/layer/control/profile/>
pub fn resolve_profile(
    profile: &Value,
    sources: &HashMap<String, Value>,
) -> Result<ResolvedProfile, ParseError> {
    let mut stack: HashSet<String> = HashSet::new();
    resolve_profile_inner(profile, sources, &mut stack)
}

fn resolve_profile_inner(
    profile: &Value,
    sources: &HashMap<String, Value>,
    stack: &mut HashSet<String>,
) -> Result<ResolvedProfile, ParseError> {
    let obj = profile.as_object().ok_or(ParseError::ProfileNotObject)?;
    let prof = obj
        .get("profile")
        .and_then(|p| p.as_object())
        .ok_or(ParseError::ProfileMissingWrapper)?;
    let imports = prof
        .get("imports")
        .and_then(|i| i.as_array())
        .ok_or(ParseError::ProfileImportsNotArray)?;

    let mut control_ids: Vec<String> = Vec::new();
    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut parameter_overrides: Vec<ParameterOverride> = Vec::new();

    for (import_index, import) in imports.iter().enumerate() {
        let import_obj = import
            .as_object()
            .ok_or(ParseError::ProfileImportNotObject {
                index: import_index,
            })?;
        let href_value = import_obj
            .get("href")
            .ok_or(ParseError::ProfileImportMissingHref {
                index: import_index,
            })?;
        let href = href_value
            .as_str()
            .ok_or(ParseError::ProfileImportHrefNotString {
                index: import_index,
            })?;
        if href.is_empty() {
            return Err(ParseError::ProfileImportHrefEmpty {
                index: import_index,
            });
        }

        let source = sources
            .get(href)
            .ok_or_else(|| ParseError::ProfileImportUnresolved {
                index: import_index,
                href: href.to_owned(),
            })?;

        // Recurse if the source is itself a Profile; otherwise treat as a
        // Catalog. Distinguish via the wrapper key.
        let source_obj =
            source
                .as_object()
                .ok_or_else(|| ParseError::ProfileImportSourceUnknown {
                    index: import_index,
                    href: href.to_owned(),
                })?;

        let (mut available_ids, mut nested_overrides) = if source_obj.contains_key("profile") {
            if !stack.insert(href.to_owned()) {
                return Err(ParseError::ProfileImportCycle {
                    href: href.to_owned(),
                });
            }
            let nested = resolve_profile_inner(source, sources, stack)?;
            stack.remove(href);
            (nested.control_ids, nested.parameter_overrides)
        } else if source_obj.contains_key("catalog") {
            let ids = lint_ids_from_catalog(source)?;
            (ids, Vec::new())
        } else {
            return Err(ParseError::ProfileImportSourceUnknown {
                index: import_index,
                href: href.to_owned(),
            });
        };

        // Apply include filters. `include-all` includes everything from
        // the source; otherwise `include-controls[].with-ids[]` selects
        // explicit ids. Absent either, OSCAL semantics include nothing
        // from this import.
        let include_all = import_obj.get("include-all").is_some();
        let include_directives = import_obj.get("include-controls");
        let included: Vec<String> = if include_all {
            available_ids.clone()
        } else if let Some(directives) = include_directives {
            let entries =
                directives
                    .as_array()
                    .ok_or(ParseError::ProfileIncludeControlsNotArray {
                        index: import_index,
                    })?;
            let mut wanted: HashSet<String> = HashSet::new();
            for (entry_index, entry) in entries.iter().enumerate() {
                let entry_obj =
                    entry
                        .as_object()
                        .ok_or(ParseError::ProfileWithIdsEntryNotObject {
                            index: import_index,
                            entry_index,
                        })?;
                if let Some(with_ids) = entry_obj.get("with-ids") {
                    let ids = with_ids
                        .as_array()
                        .ok_or(ParseError::ProfileWithIdsNotArray {
                            index: import_index,
                            entry_index,
                        })?;
                    for id_val in ids {
                        let id_str = id_val.as_str().ok_or(ParseError::ProfileWithIdNotString {
                            index: import_index,
                            entry_index,
                        })?;
                        wanted.insert(id_str.to_owned());
                    }
                }
            }
            // Preserve the source order; only keep ids present in the
            // source (silently drop wanted ids that aren't in the
            // source — operators see this via the `filter_to_ids`
            // round-trip failing later if it matters).
            available_ids.retain(|id| wanted.contains(id));
            available_ids.clone()
        } else {
            // Neither `include-all` nor `include-controls` present:
            // nothing included from this import.
            Vec::new()
        };

        // Apply exclude filters after include.
        let mut excluded: HashSet<String> = HashSet::new();
        if let Some(directives) = import_obj.get("exclude-controls") {
            let entries =
                directives
                    .as_array()
                    .ok_or(ParseError::ProfileExcludeControlsNotArray {
                        index: import_index,
                    })?;
            for (entry_index, entry) in entries.iter().enumerate() {
                let entry_obj =
                    entry
                        .as_object()
                        .ok_or(ParseError::ProfileWithIdsEntryNotObject {
                            index: import_index,
                            entry_index,
                        })?;
                if let Some(with_ids) = entry_obj.get("with-ids") {
                    let ids = with_ids
                        .as_array()
                        .ok_or(ParseError::ProfileWithIdsNotArray {
                            index: import_index,
                            entry_index,
                        })?;
                    for id_val in ids {
                        let id_str = id_val.as_str().ok_or(ParseError::ProfileWithIdNotString {
                            index: import_index,
                            entry_index,
                        })?;
                        excluded.insert(id_str.to_owned());
                    }
                }
            }
        }

        for id in included {
            if excluded.contains(&id) {
                continue;
            }
            if seen_ids.insert(id.clone()) {
                control_ids.push(id);
            }
        }

        // Inner Profile overrides precede outer overrides — so set_parameter
        // applied in the outer-loop order will leave the outermost value
        // last-set, which matches OSCAL "outer wins" semantics for layered
        // Profiles.
        parameter_overrides.append(&mut nested_overrides);
    }

    // Walk modify.set-parameters[] on this Profile (outermost layer).
    if let Some(modify) = prof.get("modify").and_then(|m| m.as_object()) {
        if let Some(set_params) = modify.get("set-parameters") {
            let entries = set_params
                .as_array()
                .ok_or(ParseError::ProfileSetParametersNotArray)?;
            for (entry_index, entry) in entries.iter().enumerate() {
                let entry_obj = entry
                    .as_object()
                    .ok_or(ParseError::ProfileSetParameterNotObject { entry_index })?;
                let param_id = entry_obj
                    .get("param-id")
                    .and_then(|v| v.as_str())
                    .ok_or(ParseError::ProfileSetParameterMissingId { entry_index })?;
                if param_id.is_empty() {
                    return Err(ParseError::ProfileSetParameterIdEmpty { entry_index });
                }
                let values = entry_obj
                    .get("values")
                    .and_then(|v| v.as_array())
                    .ok_or(ParseError::ProfileSetParameterValuesNotArray { entry_index })?;
                if values.is_empty() {
                    return Err(ParseError::ProfileSetParameterValuesEmpty { entry_index });
                }
                let value = values[0]
                    .as_str()
                    .ok_or(ParseError::ProfileSetParameterValueNotString { entry_index })?;
                parameter_overrides.push(ParameterOverride {
                    param_id: param_id.to_owned(),
                    value: value.to_owned(),
                });
            }
        }
    }

    Ok(ResolvedProfile {
        control_ids,
        parameter_overrides,
    })
}

#[cfg(test)]
mod tests {
    //! Independent oracles:
    //!
    //! * The Profile JSON shapes are hand-constructed in tests and assert
    //!   on the output `control_ids` ordering and `parameter_overrides`
    //!   list. Within each individual test the hand-written Profile JSON
    //!   serves as the test oracle — the parser under test produces the
    //!   resolution, and the test compares against an independently
    //!   computed expected output (the set of ids the test author of
    //!   that JSON intended). This per-test oracle role does not imply
    //!   anything about OSCAL Profiles as a global workspace source of
    //!   truth; see `pkix-lint/src/oscal/mod.rs` for the stance.
    //! * Catalog inputs are constructed via the catalog emitter
    //!   ([`crate::oscal::catalog::catalog_from_lints`]) over known
    //!   `Lint` impls, so the Control id set of each Catalog is fixed by
    //!   the impls themselves (themselves tested independently).
    //! * Negative tests exercise each [`ParseError`] variant introduced
    //!   by Profile composition by passing a deliberately malformed JSON
    //!   shape and asserting the matching error type.
    //!
    //! End-to-end execution (Catalog → Profile resolve →
    //! `apply_parameter_overrides` → `filter_to_ids` → `run_chain`) is
    //! covered separately in pkix-lint-cabf's integration tests; here we
    //! focus on the resolver itself.

    use super::*;
    use crate::oscal::catalog::catalog_from_lints;
    use crate::rfc5280::Rfc5280MaxSerialLengthLint;
    use crate::{Lint, LintResult, Scope, Severity, SubjectKind};
    use serde_json::json;
    use x509_cert::Certificate;

    /// Minimal policy-shaped fixture Lint used as the "second catalog"
    /// in cross-catalog Profile tests. Mirrors the metadata shape of a
    /// CA/B Forum lint (spec_section_id set, spec_url None) without
    /// depending on pkix-lint-cabf content.
    struct PolicyShapedLint;
    impl Lint for PolicyShapedLint {
        fn id(&self) -> &'static str {
            "test.policy.shaped"
        }
        fn citation(&self) -> &'static str {
            "Test Policy §1.2.3"
        }
        fn severity(&self) -> Severity {
            Severity::Error
        }
        fn scope(&self) -> Scope {
            Scope::Certificate
        }
        fn applies_to(&self) -> SubjectKind {
            SubjectKind::Leaf
        }
        fn spec_section_id(&self) -> Option<&str> {
            Some("test-policy-1.2.3")
        }
        fn check_cert(
            &self,
            _cert: &Certificate,
            _kind: SubjectKind,
            _now_unix: u64,
        ) -> LintResult {
            LintResult::Pass
        }
    }

    fn rfc_catalog() -> Value {
        let lints: Vec<Box<dyn Lint>> = vec![Box::new(Rfc5280MaxSerialLengthLint::default())];
        catalog_from_lints(&lints, "rs.pkix.rfc5280", "0.1.0")
    }

    /// Stand-in second-catalog used by the layered-profile tests. Previously
    /// keyed off the CA/B Forum `ValidityMaxLint`; now uses a self-contained
    /// fixture so pkix-lint's tests do not depend on pkix-lint-cabf content.
    fn policy_catalog() -> Value {
        let lints: Vec<Box<dyn Lint>> = vec![Box::new(PolicyShapedLint)];
        catalog_from_lints(&lints, "rs.pkix.policy.fixture", "0.1.0")
    }

    // -- Example 1: plain Profile, include-all from one Catalog --------

    #[test]
    fn plain_profile_include_all() {
        let mut sources = HashMap::new();
        sources.insert("#rs.pkix.rfc5280".to_owned(), rfc_catalog());

        let profile = json!({
            "profile": {
                "uuid": "00000000-0000-0000-0000-000000000001",
                "metadata": { "title": "plain" },
                "imports": [
                    { "href": "#rs.pkix.rfc5280", "include-all": {} }
                ],
                "back-matter": {}
            }
        });

        let resolved = resolve_profile(&profile, &sources).expect("resolve");
        assert_eq!(
            resolved.control_ids,
            vec!["rfc5280.cert.serial_number.max_octets".to_owned()]
        );
        assert!(resolved.parameter_overrides.is_empty());
    }

    #[test]
    fn plain_profile_explicit_include_controls() {
        let mut sources = HashMap::new();
        sources.insert("#rs.pkix.rfc5280".to_owned(), rfc_catalog());

        let profile = json!({
            "profile": {
                "uuid": "00000000-0000-0000-0000-000000000002",
                "metadata": { "title": "explicit" },
                "imports": [
                    {
                        "href": "#rs.pkix.rfc5280",
                        "include-controls": [
                            { "with-ids": ["rfc5280.cert.serial_number.max_octets"] }
                        ]
                    }
                ]
            }
        });

        let resolved = resolve_profile(&profile, &sources).expect("resolve");
        assert_eq!(
            resolved.control_ids,
            vec!["rfc5280.cert.serial_number.max_octets".to_owned()]
        );
    }

    // -- Example 2: layered Profile across two Catalogs ----------------

    #[test]
    fn layered_profile_imports_two_catalogs_with_overrides() {
        let mut sources = HashMap::new();
        sources.insert("#rs.pkix.rfc5280".to_owned(), rfc_catalog());
        sources.insert("#rs.pkix.policy.fixture".to_owned(), policy_catalog());

        let profile = json!({
            "profile": {
                "uuid": "00000000-0000-0000-0000-000000000003",
                "metadata": { "title": "policy-fixture" },
                "imports": [
                    {
                        "href": "#rs.pkix.rfc5280",
                        "include-all": {}
                    },
                    {
                        "href": "#rs.pkix.policy.fixture",
                        "include-all": {}
                    }
                ],
                "modify": {
                    "set-parameters": [
                        {
                            "param-id": "rfc5280.cert.serial_number.max_octets.max-octets",
                            "values": ["16"]
                        }
                    ]
                }
            }
        });

        let resolved = resolve_profile(&profile, &sources).expect("resolve");
        assert_eq!(
            resolved.control_ids,
            vec![
                "rfc5280.cert.serial_number.max_octets".to_owned(),
                "test.policy.shaped".to_owned(),
            ]
        );
        assert_eq!(
            resolved.parameter_overrides,
            vec![ParameterOverride {
                param_id: "rfc5280.cert.serial_number.max_octets.max-octets".to_owned(),
                value: "16".to_owned(),
            }]
        );
    }

    // -- Example 3: override Profile imports another Profile -----------

    #[test]
    fn override_profile_imports_profile_and_excludes_one_control() {
        let mut sources = HashMap::new();
        sources.insert("#rs.pkix.rfc5280".to_owned(), rfc_catalog());
        sources.insert("#rs.pkix.policy.fixture".to_owned(), policy_catalog());

        // Inner Profile: layered selection across the two Catalogs.
        let inner = json!({
            "profile": {
                "uuid": "00000000-0000-0000-0000-00000000abcd",
                "metadata": { "title": "inner" },
                "imports": [
                    { "href": "#rs.pkix.rfc5280", "include-all": {} },
                    { "href": "#rs.pkix.policy.fixture", "include-all": {} }
                ]
            }
        });
        sources.insert("#pkix.profile.inner".to_owned(), inner);

        // Outer Profile: import inner, drop the policy-fixture control.
        let outer = json!({
            "profile": {
                "uuid": "00000000-0000-0000-0000-00000000ef00",
                "metadata": { "title": "outer-customer-deviation" },
                "imports": [
                    {
                        "href": "#pkix.profile.inner",
                        "include-all": {},
                        "exclude-controls": [
                            { "with-ids": ["test.policy.shaped"] }
                        ]
                    }
                ],
                "modify": {
                    "set-parameters": [
                        {
                            "param-id": "rfc5280.cert.serial_number.max_octets.max-octets",
                            "values": ["8"]
                        }
                    ]
                }
            }
        });

        let resolved = resolve_profile(&outer, &sources).expect("resolve");
        assert_eq!(
            resolved.control_ids,
            vec!["rfc5280.cert.serial_number.max_octets".to_owned()]
        );
        assert_eq!(
            resolved.parameter_overrides,
            vec![ParameterOverride {
                param_id: "rfc5280.cert.serial_number.max_octets.max-octets".to_owned(),
                value: "8".to_owned(),
            }]
        );
    }

    #[test]
    fn override_profile_inherits_inner_overrides_before_its_own() {
        let mut sources = HashMap::new();
        sources.insert("#rs.pkix.rfc5280".to_owned(), rfc_catalog());

        let inner = json!({
            "profile": {
                "uuid": "00000000-0000-0000-0000-00000000a1a1",
                "metadata": { "title": "inner-with-override" },
                "imports": [
                    { "href": "#rs.pkix.rfc5280", "include-all": {} }
                ],
                "modify": {
                    "set-parameters": [
                        {
                            "param-id": "rfc5280.cert.serial_number.max_octets.max-octets",
                            "values": ["16"]
                        }
                    ]
                }
            }
        });
        sources.insert("#pkix.profile.inner".to_owned(), inner);

        let outer = json!({
            "profile": {
                "uuid": "00000000-0000-0000-0000-00000000a2a2",
                "metadata": { "title": "outer-with-tighter-override" },
                "imports": [
                    { "href": "#pkix.profile.inner", "include-all": {} }
                ],
                "modify": {
                    "set-parameters": [
                        {
                            "param-id": "rfc5280.cert.serial_number.max_octets.max-octets",
                            "values": ["8"]
                        }
                    ]
                }
            }
        });

        let resolved = resolve_profile(&outer, &sources).expect("resolve");
        // Inner override appears first, outer second — caller applies in
        // order so outer wins.
        assert_eq!(
            resolved.parameter_overrides,
            vec![
                ParameterOverride {
                    param_id: "rfc5280.cert.serial_number.max_octets.max-octets".to_owned(),
                    value: "16".to_owned(),
                },
                ParameterOverride {
                    param_id: "rfc5280.cert.serial_number.max_octets.max-octets".to_owned(),
                    value: "8".to_owned(),
                },
            ]
        );
    }

    // -- Filter semantics ----------------------------------------------

    #[test]
    fn exclude_after_include_drops_id() {
        let mut sources = HashMap::new();
        sources.insert("#rs.pkix.rfc5280".to_owned(), rfc_catalog());

        let profile = json!({
            "profile": {
                "uuid": "00000000-0000-0000-0000-00000000ccdd",
                "metadata": { "title": "exclude-test" },
                "imports": [
                    {
                        "href": "#rs.pkix.rfc5280",
                        "include-all": {},
                        "exclude-controls": [
                            { "with-ids": ["rfc5280.cert.serial_number.max_octets"] }
                        ]
                    }
                ]
            }
        });

        let resolved = resolve_profile(&profile, &sources).expect("resolve");
        assert!(resolved.control_ids.is_empty());
    }

    #[test]
    fn import_without_include_directive_yields_no_controls() {
        let mut sources = HashMap::new();
        sources.insert("#rs.pkix.rfc5280".to_owned(), rfc_catalog());

        let profile = json!({
            "profile": {
                "uuid": "00000000-0000-0000-0000-00000000bbcc",
                "metadata": { "title": "no-include" },
                "imports": [
                    { "href": "#rs.pkix.rfc5280" }
                ]
            }
        });

        let resolved = resolve_profile(&profile, &sources).expect("resolve");
        assert!(resolved.control_ids.is_empty());
    }

    #[test]
    fn duplicate_id_across_imports_dedup_first_wins() {
        let mut sources = HashMap::new();
        sources.insert("#rs.pkix.rfc5280".to_owned(), rfc_catalog());
        sources.insert("#rs.pkix.rfc5280.alt".to_owned(), rfc_catalog());

        let profile = json!({
            "profile": {
                "uuid": "00000000-0000-0000-0000-00000000dd11",
                "metadata": { "title": "dup" },
                "imports": [
                    { "href": "#rs.pkix.rfc5280", "include-all": {} },
                    { "href": "#rs.pkix.rfc5280.alt", "include-all": {} }
                ]
            }
        });

        let resolved = resolve_profile(&profile, &sources).expect("resolve");
        assert_eq!(
            resolved.control_ids,
            vec!["rfc5280.cert.serial_number.max_octets".to_owned()],
            "duplicate id from two imports should appear once"
        );
    }

    // -- Negative tests: each new ParseError variant -------------------

    #[test]
    fn err_profile_not_object() {
        let sources = HashMap::new();
        let err = resolve_profile(&Value::Null, &sources).unwrap_err();
        assert!(matches!(err, ParseError::ProfileNotObject));
    }

    #[test]
    fn err_profile_missing_wrapper() {
        let sources = HashMap::new();
        let v = json!({ "not-a-profile": {} });
        let err = resolve_profile(&v, &sources).unwrap_err();
        assert!(matches!(err, ParseError::ProfileMissingWrapper));
    }

    #[test]
    fn err_imports_not_array() {
        let sources = HashMap::new();
        let v = json!({ "profile": { "imports": {} } });
        let err = resolve_profile(&v, &sources).unwrap_err();
        assert!(matches!(err, ParseError::ProfileImportsNotArray));
    }

    #[test]
    fn err_import_missing_href() {
        let sources = HashMap::new();
        let v = json!({ "profile": { "imports": [ {} ] } });
        let err = resolve_profile(&v, &sources).unwrap_err();
        assert!(matches!(
            err,
            ParseError::ProfileImportMissingHref { index: 0 }
        ));
    }

    #[test]
    fn err_import_href_not_string() {
        let sources = HashMap::new();
        let v = json!({ "profile": { "imports": [ { "href": 7 } ] } });
        let err = resolve_profile(&v, &sources).unwrap_err();
        assert!(matches!(
            err,
            ParseError::ProfileImportHrefNotString { index: 0 }
        ));
    }

    #[test]
    fn err_import_href_empty() {
        let sources = HashMap::new();
        let v = json!({ "profile": { "imports": [ { "href": "" } ] } });
        let err = resolve_profile(&v, &sources).unwrap_err();
        assert!(matches!(
            err,
            ParseError::ProfileImportHrefEmpty { index: 0 }
        ));
    }

    #[test]
    fn err_import_unresolved() {
        let sources = HashMap::new();
        let v = json!({ "profile": { "imports": [ { "href": "#nope" } ] } });
        let err = resolve_profile(&v, &sources).unwrap_err();
        match err {
            ParseError::ProfileImportUnresolved { index: 0, href } => {
                assert_eq!(href, "#nope");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn err_import_source_unknown() {
        let mut sources = HashMap::new();
        sources.insert(
            "#weird".to_owned(),
            json!({ "neither-catalog-nor-profile": {} }),
        );
        let v = json!({ "profile": { "imports": [ { "href": "#weird" } ] } });
        let err = resolve_profile(&v, &sources).unwrap_err();
        match err {
            ParseError::ProfileImportSourceUnknown { index: 0, href } => {
                assert_eq!(href, "#weird");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn err_import_cycle() {
        let mut sources = HashMap::new();
        // Profile A imports Profile B; Profile B imports Profile A.
        sources.insert(
            "#a".to_owned(),
            json!({ "profile": { "imports": [ { "href": "#b" } ] } }),
        );
        sources.insert(
            "#b".to_owned(),
            json!({ "profile": { "imports": [ { "href": "#a" } ] } }),
        );
        let outer = json!({ "profile": { "imports": [ { "href": "#a" } ] } });
        let err = resolve_profile(&outer, &sources).unwrap_err();
        match err {
            ParseError::ProfileImportCycle { href } => {
                assert!(href == "#a" || href == "#b");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn err_include_controls_not_array() {
        let mut sources = HashMap::new();
        sources.insert("#rs.pkix.rfc5280".to_owned(), rfc_catalog());

        let v = json!({
            "profile": {
                "imports": [
                    { "href": "#rs.pkix.rfc5280", "include-controls": {} }
                ]
            }
        });
        let err = resolve_profile(&v, &sources).unwrap_err();
        assert!(matches!(
            err,
            ParseError::ProfileIncludeControlsNotArray { index: 0 }
        ));
    }

    #[test]
    fn err_exclude_controls_not_array() {
        let mut sources = HashMap::new();
        sources.insert("#rs.pkix.rfc5280".to_owned(), rfc_catalog());

        let v = json!({
            "profile": {
                "imports": [
                    {
                        "href": "#rs.pkix.rfc5280",
                        "include-all": {},
                        "exclude-controls": "string-not-array"
                    }
                ]
            }
        });
        let err = resolve_profile(&v, &sources).unwrap_err();
        assert!(matches!(
            err,
            ParseError::ProfileExcludeControlsNotArray { index: 0 }
        ));
    }

    #[test]
    fn err_with_ids_not_array() {
        let mut sources = HashMap::new();
        sources.insert("#rs.pkix.rfc5280".to_owned(), rfc_catalog());

        let v = json!({
            "profile": {
                "imports": [
                    {
                        "href": "#rs.pkix.rfc5280",
                        "include-controls": [ { "with-ids": "not-an-array" } ]
                    }
                ]
            }
        });
        let err = resolve_profile(&v, &sources).unwrap_err();
        assert!(matches!(
            err,
            ParseError::ProfileWithIdsNotArray {
                index: 0,
                entry_index: 0
            }
        ));
    }

    #[test]
    fn err_with_id_not_string() {
        let mut sources = HashMap::new();
        sources.insert("#rs.pkix.rfc5280".to_owned(), rfc_catalog());

        let v = json!({
            "profile": {
                "imports": [
                    {
                        "href": "#rs.pkix.rfc5280",
                        "include-controls": [ { "with-ids": [42] } ]
                    }
                ]
            }
        });
        let err = resolve_profile(&v, &sources).unwrap_err();
        assert!(matches!(
            err,
            ParseError::ProfileWithIdNotString {
                index: 0,
                entry_index: 0
            }
        ));
    }

    #[test]
    fn err_set_parameters_not_array() {
        let mut sources = HashMap::new();
        sources.insert("#rs.pkix.rfc5280".to_owned(), rfc_catalog());

        let v = json!({
            "profile": {
                "imports": [
                    { "href": "#rs.pkix.rfc5280", "include-all": {} }
                ],
                "modify": { "set-parameters": "nope" }
            }
        });
        let err = resolve_profile(&v, &sources).unwrap_err();
        assert!(matches!(err, ParseError::ProfileSetParametersNotArray));
    }

    #[test]
    fn err_set_parameter_missing_id() {
        let mut sources = HashMap::new();
        sources.insert("#rs.pkix.rfc5280".to_owned(), rfc_catalog());

        let v = json!({
            "profile": {
                "imports": [
                    { "href": "#rs.pkix.rfc5280", "include-all": {} }
                ],
                "modify": { "set-parameters": [ { "values": ["x"] } ] }
            }
        });
        let err = resolve_profile(&v, &sources).unwrap_err();
        assert!(matches!(
            err,
            ParseError::ProfileSetParameterMissingId { entry_index: 0 }
        ));
    }

    #[test]
    fn err_set_parameter_values_empty() {
        let mut sources = HashMap::new();
        sources.insert("#rs.pkix.rfc5280".to_owned(), rfc_catalog());

        let v = json!({
            "profile": {
                "imports": [
                    { "href": "#rs.pkix.rfc5280", "include-all": {} }
                ],
                "modify": { "set-parameters": [ { "param-id": "x", "values": [] } ] }
            }
        });
        let err = resolve_profile(&v, &sources).unwrap_err();
        assert!(matches!(
            err,
            ParseError::ProfileSetParameterValuesEmpty { entry_index: 0 }
        ));
    }

    #[test]
    fn err_set_parameter_value_not_string() {
        let mut sources = HashMap::new();
        sources.insert("#rs.pkix.rfc5280".to_owned(), rfc_catalog());

        let v = json!({
            "profile": {
                "imports": [
                    { "href": "#rs.pkix.rfc5280", "include-all": {} }
                ],
                "modify": { "set-parameters": [ { "param-id": "x", "values": [7] } ] }
            }
        });
        let err = resolve_profile(&v, &sources).unwrap_err();
        assert!(matches!(
            err,
            ParseError::ProfileSetParameterValueNotString { entry_index: 0 }
        ));
    }

    // -- End-to-end: Profile → resolve → apply → filter → run --------

    /// Drives the full composition path against a real fixture cert,
    /// independent of the Profile-parsing layer. Oracle: the fixture's
    /// serial length is independently established by
    /// `rfc5280::tests::default_lint_accepts_20_octet_serial` (20
    /// octets). Default lint must Pass; same lint with override
    /// max-octets=10 must Error. The Error variant comes from the
    /// rfc5280 lint impl, which is tested independently in its own
    /// module — this test asserts the *plumbing* from Profile JSON to
    /// lint state.
    #[test]
    fn end_to_end_profile_override_changes_runner_behavior() {
        use crate::{LintResult, LintRunner, SubjectKind};
        use x509_cert::Certificate;

        let fixture_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../pkix-path/tests/fixtures/policy-checks/")
            .join("leaf-rsa2048-sha1.der");
        let der = std::fs::read(&fixture_path)
            .unwrap_or_else(|e| panic!("read fixture {}: {e}", fixture_path.display()));
        let cert = <Certificate as der::Decode>::from_der(&der).expect("decode fixture");
        assert_eq!(
            cert.tbs_certificate.serial_number.as_bytes().len(),
            20,
            "fixture invariant: leaf-rsa2048-sha1.der has a 20-octet serial",
        );

        // Build a runner with the default rfc5280 max-serial-length
        // lint (default max-octets = 20).
        let lints: Vec<Box<dyn Lint>> = vec![Box::new(Rfc5280MaxSerialLengthLint::default())];
        let mut runner = LintRunner::new(lints);

        // Default runner: 20-octet serial passes the 20-octet cap.
        let baseline = runner.run_cert(&cert, SubjectKind::Leaf, 0, 0);
        let baseline_result = baseline
            .iter()
            .find(|f| f.lint_id == "rfc5280.cert.serial_number.max_octets")
            .map(|f| f.result.clone())
            .expect("rfc5280 finding present");
        assert!(
            matches!(baseline_result, LintResult::Pass),
            "default cap (20) must pass a 20-octet serial; got {baseline_result:?}",
        );

        // Compose a Profile that tightens max-octets to 10.
        let mut sources = HashMap::new();
        sources.insert("#rs.pkix.rfc5280".to_owned(), rfc_catalog());
        let profile = json!({
            "profile": {
                "uuid": "00000000-0000-0000-0000-000000000099",
                "metadata": { "title": "e2e-tighten" },
                "imports": [
                    { "href": "#rs.pkix.rfc5280", "include-all": {} }
                ],
                "modify": {
                    "set-parameters": [
                        {
                            "param-id": "rfc5280.cert.serial_number.max_octets.max-octets",
                            "values": ["10"]
                        }
                    ]
                }
            }
        });
        let resolved = resolve_profile(&profile, &sources).expect("resolve");
        assert_eq!(resolved.parameter_overrides.len(), 1);

        runner
            .apply_parameter_overrides(&resolved.parameter_overrides)
            .expect("apply overrides");
        let filtered = runner
            .filter_to_ids(&resolved.control_ids)
            .expect("filter to ids");

        // Tightened runner: 20-octet serial must now Error.
        let findings = filtered.run_cert(&cert, SubjectKind::Leaf, 0, 0);
        let tightened_result = findings
            .iter()
            .find(|f| f.lint_id == "rfc5280.cert.serial_number.max_octets")
            .map(|f| f.result.clone())
            .expect("rfc5280 finding present");
        match tightened_result {
            LintResult::Error(detail) => {
                assert!(detail.contains("20 octets"));
                assert!(detail.contains("10 octets"));
            }
            other => panic!("tightened cap (10) must error on a 20-octet serial; got {other:?}"),
        }
    }

    #[test]
    fn apply_parameter_overrides_unknown_lint_errors() {
        use crate::LintRunner;

        let lints: Vec<Box<dyn Lint>> = vec![Box::new(Rfc5280MaxSerialLengthLint::default())];
        let mut runner = LintRunner::new(lints);
        let overrides = vec![ParameterOverride {
            param_id: "no.such.lint.somewhere.max-octets".to_owned(),
            value: "1".to_owned(),
        }];
        let err = runner.apply_parameter_overrides(&overrides).unwrap_err();
        match err {
            ParseError::UnknownParameterOverride { param_id } => {
                assert_eq!(param_id, "no.such.lint.somewhere.max-octets");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn apply_parameter_overrides_unknown_param_id_errors() {
        use crate::LintRunner;

        let lints: Vec<Box<dyn Lint>> = vec![Box::new(Rfc5280MaxSerialLengthLint::default())];
        let mut runner = LintRunner::new(lints);
        let overrides = vec![ParameterOverride {
            param_id: "rfc5280.cert.serial_number.max_octets.no-such-param".to_owned(),
            value: "1".to_owned(),
        }];
        let err = runner.apply_parameter_overrides(&overrides).unwrap_err();
        match err {
            ParseError::InvalidParameterOverride { param_id, .. } => {
                assert_eq!(
                    param_id,
                    "rfc5280.cert.serial_number.max_octets.no-such-param"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn apply_parameter_overrides_invalid_value_wraps_parameter_error() {
        use crate::LintRunner;

        let lints: Vec<Box<dyn Lint>> = vec![Box::new(Rfc5280MaxSerialLengthLint::default())];
        let mut runner = LintRunner::new(lints);
        let overrides = vec![ParameterOverride {
            param_id: "rfc5280.cert.serial_number.max_octets.max-octets".to_owned(),
            value: "not-a-number".to_owned(),
        }];
        let err = runner.apply_parameter_overrides(&overrides).unwrap_err();
        match err {
            ParseError::InvalidParameterOverride { param_id, source } => {
                assert_eq!(param_id, "rfc5280.cert.serial_number.max_octets.max-octets");
                assert!(matches!(source, crate::ParameterError::InvalidValue { .. }));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn apply_parameter_overrides_id_without_dot_errors() {
        use crate::LintRunner;

        let lints: Vec<Box<dyn Lint>> = vec![Box::new(Rfc5280MaxSerialLengthLint::default())];
        let mut runner = LintRunner::new(lints);
        let overrides = vec![ParameterOverride {
            param_id: "no_dot_separator".to_owned(),
            value: "1".to_owned(),
        }];
        let err = runner.apply_parameter_overrides(&overrides).unwrap_err();
        assert!(matches!(err, ParseError::UnknownParameterOverride { .. }));
    }

    // -----------------------------------------------------------------------
    // PKIX-hy2e.3 regression: dotted parameter ids must resolve via
    // longest-prefix-match against the registered lints, not via a
    // rightmost-dot split that assumes parameter ids have no dot.
    // -----------------------------------------------------------------------

    /// Test fixture: a lint whose only valid parameter id contains a dot.
    /// `set_parameter` returns `Ok` exclusively when `id == "thresholds.warn"`;
    /// any other id surfaces `ParameterError::UnknownParameter`. The runner
    /// wraps that as `InvalidParameterOverride`, so a successful
    /// `apply_parameter_overrides` call proves the composite id was split
    /// at the correct boundary.
    struct DottedParamLint;
    impl Lint for DottedParamLint {
        fn id(&self) -> &'static str {
            "test.dotted.param"
        }
        fn citation(&self) -> &'static str {
            "PKIX-hy2e.3 fixture"
        }
        fn severity(&self) -> crate::Severity {
            crate::Severity::Warn
        }
        fn scope(&self) -> crate::Scope {
            crate::Scope::Certificate
        }
        fn applies_to(&self) -> crate::SubjectKind {
            crate::SubjectKind::Leaf
        }
        fn set_parameter(
            &mut self,
            id: &str,
            _value: &str,
        ) -> Result<(), crate::ParameterError> {
            if id == "thresholds.warn" {
                Ok(())
            } else {
                Err(crate::ParameterError::UnknownParameter(id.to_owned()))
            }
        }
        fn check_cert(
            &self,
            _cert: &x509_cert::Certificate,
            _kind: crate::SubjectKind,
            _now_unix: u64,
        ) -> crate::LintResult {
            crate::LintResult::Pass
        }
    }

    #[test]
    fn apply_parameter_overrides_resolves_dotted_param_id() {
        // Regression for PKIX-hy2e.3. Composite param_id =
        // "test.dotted.param.thresholds.warn". Lint id =
        // "test.dotted.param". Parameter id = "thresholds.warn" (contains
        // a dot). Longest-prefix matching against the registered lint id
        // must yield param_id "thresholds.warn". The pre-fix
        // rsplit-once-on-dot logic would yield param_id "warn" instead,
        // which the fixture lint's set_parameter rejects, surfacing as
        // InvalidParameterOverride.
        use crate::LintRunner;

        let lints: Vec<Box<dyn Lint>> = vec![Box::new(DottedParamLint)];
        let mut runner = LintRunner::new(lints);
        let overrides = vec![ParameterOverride {
            param_id: "test.dotted.param.thresholds.warn".to_owned(),
            value: "5".to_owned(),
        }];
        runner.apply_parameter_overrides(&overrides).expect(
            "longest-prefix match must split composite id at the lint-id boundary; \
             rsplit-once-on-dot would have produced param_id='warn' and triggered \
             InvalidParameterOverride",
        );
    }

    #[test]
    fn apply_parameter_overrides_longest_prefix_wins_on_lint_id_collision() {
        // Regression: when two registered lint ids overlap by prefix
        // (one is a strict prefix of the other), the longest prefix
        // must win.
        use crate::LintRunner;

        // First registered: short prefix lint.
        struct ShortPrefixLint;
        impl Lint for ShortPrefixLint {
            fn id(&self) -> &'static str {
                "test.prefix"
            }
            fn citation(&self) -> &'static str {
                "fixture"
            }
            fn severity(&self) -> crate::Severity {
                crate::Severity::Warn
            }
            fn scope(&self) -> crate::Scope {
                crate::Scope::Certificate
            }
            fn applies_to(&self) -> crate::SubjectKind {
                crate::SubjectKind::Leaf
            }
            fn set_parameter(
                &mut self,
                id: &str,
                _value: &str,
            ) -> Result<(), crate::ParameterError> {
                // The short-prefix lint rejects every id so we can
                // detect if longest-prefix-match accidentally routed
                // the override here.
                Err(crate::ParameterError::UnknownParameter(format!(
                    "short-prefix lint received id={id} — longest-prefix-match should have \
                     routed to test.prefix.long instead"
                )))
            }
            fn check_cert(
                &self,
                _cert: &x509_cert::Certificate,
                _kind: crate::SubjectKind,
                _now_unix: u64,
            ) -> crate::LintResult {
                crate::LintResult::Pass
            }
        }

        // Second registered: long prefix lint, accepts "knob".
        struct LongPrefixLint;
        impl Lint for LongPrefixLint {
            fn id(&self) -> &'static str {
                "test.prefix.long"
            }
            fn citation(&self) -> &'static str {
                "fixture"
            }
            fn severity(&self) -> crate::Severity {
                crate::Severity::Warn
            }
            fn scope(&self) -> crate::Scope {
                crate::Scope::Certificate
            }
            fn applies_to(&self) -> crate::SubjectKind {
                crate::SubjectKind::Leaf
            }
            fn set_parameter(
                &mut self,
                id: &str,
                _value: &str,
            ) -> Result<(), crate::ParameterError> {
                if id == "knob" {
                    Ok(())
                } else {
                    Err(crate::ParameterError::UnknownParameter(id.to_owned()))
                }
            }
            fn check_cert(
                &self,
                _cert: &x509_cert::Certificate,
                _kind: crate::SubjectKind,
                _now_unix: u64,
            ) -> crate::LintResult {
                crate::LintResult::Pass
            }
        }

        let lints: Vec<Box<dyn Lint>> =
            vec![Box::new(ShortPrefixLint), Box::new(LongPrefixLint)];
        let mut runner = LintRunner::new(lints);
        let overrides = vec![ParameterOverride {
            param_id: "test.prefix.long.knob".to_owned(),
            value: "v".to_owned(),
        }];
        runner.apply_parameter_overrides(&overrides).expect(
            "longest-prefix match must route to test.prefix.long not test.prefix",
        );
    }

    #[test]
    fn apply_parameter_overrides_fails_fast_before_mutation() {
        // Regression for the Phase 1 / Phase 2 separation in
        // apply_parameter_overrides (closes part of PKIX-hy2e.3's scope;
        // PKIX-hy2e.6 covers the InvalidParameterOverride-atomicity
        // surface). A batch with one valid override followed by one
        // UnknownParameterOverride must surface the
        // UnknownParameterOverride WITHOUT calling set_parameter on the
        // first lint. The pre-fix code applied the valid one and then
        // errored on the unknown one mid-loop, leaving the runner
        // partially mutated.
        use crate::LintRunner;
        use std::sync::atomic::{AtomicBool, Ordering};

        // Per-test static. Re-runs in the same process must reset it.
        static APPLIED: AtomicBool = AtomicBool::new(false);
        APPLIED.store(false, Ordering::SeqCst);

        struct ObservableLint;
        impl Lint for ObservableLint {
            fn id(&self) -> &'static str {
                "test.observable.lint"
            }
            fn citation(&self) -> &'static str {
                "PKIX-hy2e.3 fail-fast fixture"
            }
            fn severity(&self) -> crate::Severity {
                crate::Severity::Warn
            }
            fn scope(&self) -> crate::Scope {
                crate::Scope::Certificate
            }
            fn applies_to(&self) -> crate::SubjectKind {
                crate::SubjectKind::Leaf
            }
            fn set_parameter(
                &mut self,
                _id: &str,
                _value: &str,
            ) -> Result<(), crate::ParameterError> {
                APPLIED.store(true, Ordering::SeqCst);
                Ok(())
            }
            fn check_cert(
                &self,
                _cert: &x509_cert::Certificate,
                _kind: crate::SubjectKind,
                _now_unix: u64,
            ) -> crate::LintResult {
                crate::LintResult::Pass
            }
        }

        let lints: Vec<Box<dyn Lint>> = vec![Box::new(ObservableLint)];
        let mut runner = LintRunner::new(lints);
        let overrides = vec![
            ParameterOverride {
                param_id: "test.observable.lint.any".to_owned(),
                value: "v".to_owned(),
            },
            ParameterOverride {
                param_id: "no.such.lint.id.anywhere".to_owned(),
                value: "v".to_owned(),
            },
        ];
        let err = runner.apply_parameter_overrides(&overrides).unwrap_err();
        assert!(matches!(err, ParseError::UnknownParameterOverride { .. }));
        assert!(
            !APPLIED.load(Ordering::SeqCst),
            "Phase 1 must surface UnknownParameterOverride before any set_parameter call"
        );
    }
}
