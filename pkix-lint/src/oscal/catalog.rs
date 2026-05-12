//! OSCAL Catalog JSON emitter for a registered set of [`Lint`][crate::Lint]
//! implementations.
//!
//! The output is a [`serde_json::Value`] whose top-level shape matches the
//! NIST OSCAL Catalog v1.1.2 JSON Schema. Each [`Lint`][crate::Lint] maps
//! to one OSCAL `Control` carrying the lint's id, title, citation,
//! standards-body section pointer, RFC URL, severity / scope / applies-to
//! props, and tunable parameters.
//!
//! # OSCAL spec references
//!
//! - NIST OSCAL v1.1.2 Catalog model:
//!   <https://pages.nist.gov/OSCAL/concepts/layer/control/catalog/>
//! - JSON Schema definition (`oscal_catalog_schema.json`):
//!   <https://github.com/usnistgov/OSCAL/tree/main/json/schema>
//!
//! # Mapping
//!
//! | `Lint` accessor              | OSCAL Control field                                |
//! |------------------------------|----------------------------------------------------|
//! | [`Lint::id`]                 | `control.id` (also kept as `pkix-lint.lint-id` prop)|
//! | [`Lint::title`]              | `control.title`                                    |
//! | [`Lint::citation`]           | `control.props[name="pkix-lint.citation"]`         |
//! | [`Lint::severity`]           | `control.props[name="pkix-lint.severity"]`         |
//! | [`Lint::scope`]              | `control.props[name="pkix-lint.scope"]`            |
//! | [`Lint::applies_to`]         | `control.props[name="pkix-lint.applies-to"]`       |
//! | [`Lint::spec_section_id`]    | `control.props[name="pkix-lint.section-id"]`       |
//! | [`Lint::spec_url`]           | `control.links[rel="reference"].href`              |
//! | [`Lint::description`]        | `control.parts[name="statement"]` (`prose`)        |
//! | [`Lint::parameters`]         | `control.params[]`                                 |
//!
//! [`Lint::id`]: crate::Lint::id
//! [`Lint::title`]: crate::Lint::title
//! [`Lint::citation`]: crate::Lint::citation
//! [`Lint::severity`]: crate::Lint::severity
//! [`Lint::scope`]: crate::Lint::scope
//! [`Lint::applies_to`]: crate::Lint::applies_to
//! [`Lint::spec_section_id`]: crate::Lint::spec_section_id
//! [`Lint::spec_url`]: crate::Lint::spec_url
//! [`Lint::description`]: crate::Lint::description
//! [`Lint::parameters`]: crate::Lint::parameters
//!
//! # OSCAL Control id validity
//!
//! OSCAL Control ids are XML NCName-shaped tokens (`[A-Za-z_][A-Za-z0-9_.\-]*`).
//! The dot-separated lowercase identifiers pkix-lint already uses
//! (`cabf.br.tls.validity.max`, `rfc5280.cert.serial_number.max_octets`)
//! satisfy this. We pass them through verbatim; verifying via this
//! constraint is left to the caller's OSCAL toolchain.
//!
//! # Determinism
//!
//! Output is byte-deterministic across runs with the same input. UUIDs
//! are derived via [`crate::oscal::emit::uuid_v8`] from
//! `(catalog_id, catalog_version, lint id)` so identical catalog inputs
//! produce identical OSCAL bytes — important for CI diffability and
//! evidence-pack reproducibility.
//!
//! `metadata.last-modified` is emitted as a fixed epoch
//! (`1970-01-01T00:00:00Z`) for the same reason; callers that need a
//! wall-clock timestamp should post-edit the returned Value.
//!
//! # Provenance
//!
//! Added in PKIX-9vnx.6.2. Parameters are emitted as part of the Control
//! shape (see [`Lint::parameters`] mapping above) rather than deferred to
//! PKIX-9vnx.6.5 — `.6.5` covers the Profile-side `modify` directive that
//! *overrides* parameter values at composition time, which is a distinct
//! concern from declaring the parameter in the Catalog.

use serde_json::{json, Value};

use super::emit::{prop, scope_label, severity_label, subject_kind_label, uuid_v8};
use crate::Lint;

/// Fixed `metadata.last-modified` for deterministic output. See module
/// rustdoc for rationale.
const CATALOG_LAST_MODIFIED: &str = "1970-01-01T00:00:00Z";

/// OSCAL version this emitter targets. Tied to NIST OSCAL v1.1.2.
const OSCAL_VERSION: &str = "1.1.2";

/// UUID-v8 salt namespaces, parallel to those in `emit.rs`. Distinct
/// namespaces keep Catalog UUIDs from colliding with Assessment Results
/// UUIDs derived from the same seed bytes.
const NS_CATALOG: &str = "pkix-lint.oscal.catalog";
const NS_CONTROL: &str = "pkix-lint.oscal.catalog.control";
const NS_PARAM: &str = "pkix-lint.oscal.catalog.param";

/// Emit an OSCAL Catalog v1.1.2 JSON Value from a slice of `Box<dyn Lint>`.
///
/// `catalog_id` is a stable identifier (typically reverse-DNS-shaped, e.g.
/// `"rs.pkix.rfc5280"`); `catalog_version` is a free-form version string
/// (semver, date, or commit hash — the OSCAL Catalog model treats it as
/// opaque metadata). Both are stamped into UUID derivation, so changing
/// either changes every UUID in the output.
///
/// The Controls in the returned Catalog appear in the same order as the
/// input slice, preserving the caller's lint ordering.
#[must_use]
pub fn catalog_from_lints(
    lints: &[Box<dyn Lint>],
    catalog_id: &str,
    catalog_version: &str,
) -> Value {
    let catalog_seed = catalog_seed(catalog_id, catalog_version);
    let catalog_uuid = uuid_v8(NS_CATALOG, &catalog_seed);

    let mut controls: Vec<Value> = Vec::with_capacity(lints.len());
    for lint in lints {
        controls.push(control_for_lint(lint.as_ref(), catalog_id, catalog_version));
    }

    // OSCAL Catalog metadata.props carry catalog-level identifiers.
    // We expose `pkix-lint.catalog-id` and `pkix-lint.catalog-version`
    // so downstream consumers can read them without parsing the UUID.
    let mut metadata_props = Vec::with_capacity(2);
    if !catalog_id.is_empty() {
        metadata_props.push(prop("pkix-lint.catalog-id", catalog_id));
    }
    if !catalog_version.is_empty() {
        metadata_props.push(prop("pkix-lint.catalog-version", catalog_version));
    }

    let metadata = json!({
        "title": "pkix-lint Lint Catalog",
        "last-modified": CATALOG_LAST_MODIFIED,
        "version": catalog_version,
        "oscal-version": OSCAL_VERSION,
        "props": metadata_props,
    });

    json!({
        "catalog": {
            "uuid": catalog_uuid,
            "metadata": metadata,
            "controls": controls,
        }
    })
}

/// Render one OSCAL Control from a single `Lint`.
fn control_for_lint(lint: &dyn Lint, catalog_id: &str, catalog_version: &str) -> Value {
    let control_seed = control_seed(catalog_id, catalog_version, lint.id());
    let control_uuid = uuid_v8(NS_CONTROL, &control_seed);

    // Build props in a stable order so byte-deterministic output survives
    // refactors of the source ordering. We never sort lexicographically —
    // OSCAL consumers commonly treat the first prop as primary, so the
    // semantic-priority order (citation → severity → scope → applies-to
    // → section-id → lint-id + uuid pin) is preferable.
    let mut props = Vec::with_capacity(6);
    props.push(prop("pkix-lint.citation", lint.citation()));
    props.push(prop("pkix-lint.severity", severity_label(lint.severity())));
    props.push(prop("pkix-lint.scope", scope_label(lint.scope())));
    props.push(prop(
        "pkix-lint.applies-to",
        subject_kind_label(lint.applies_to()),
    ));
    if let Some(section_id) = lint.spec_section_id() {
        props.push(prop("pkix-lint.section-id", section_id));
    }
    // Carry the lint id as a prop too so OSCAL consumers that key off
    // props (rather than the OSCAL Control.id) still find it.
    props.push(prop("pkix-lint.lint-id", lint.id()));
    // UUID pin: documents the deterministic UUID derivation for
    // post-hoc verification by tools that recompute UUIDs.
    props.push(prop("pkix-lint.control-uuid", &control_uuid));

    let mut links: Vec<Value> = Vec::new();
    if let Some(url) = lint.spec_url() {
        links.push(json!({
            "href": url,
            "rel": "reference",
        }));
    }

    let mut parts: Vec<Value> = Vec::new();
    if let Some(description) = lint.description() {
        parts.push(json!({
            "id": format!("{}_smt", lint.id()),
            "name": "statement",
            "prose": description,
        }));
    }

    let params: Vec<Value> = lint
        .parameters()
        .iter()
        .map(|p| param_value(p, catalog_id, catalog_version, lint.id()))
        .collect();

    // Assemble the Control object. Empty optional collections are omitted
    // to keep the output lean; OSCAL allows their absence.
    let mut control = serde_json::Map::new();
    control.insert("id".to_string(), json!(lint.id()));
    control.insert("class".to_string(), json!("pkix-lint"));
    control.insert("title".to_string(), json!(lint.title()));
    if !params.is_empty() {
        control.insert("params".to_string(), Value::Array(params));
    }
    control.insert("props".to_string(), Value::Array(props));
    if !links.is_empty() {
        control.insert("links".to_string(), Value::Array(links));
    }
    if !parts.is_empty() {
        control.insert("parts".to_string(), Value::Array(parts));
    }
    Value::Object(control)
}

/// Render one OSCAL Parameter from a [`crate::LintParameter`].
fn param_value(
    p: &crate::LintParameter,
    catalog_id: &str,
    catalog_version: &str,
    lint_id: &str,
) -> Value {
    // Parameter UUID is informational (pinned as a prop) — OSCAL itself
    // does not require Parameters to have UUIDs, but tools that
    // cross-reference Profile modify directives often want a stable
    // anchor. We use the seed (catalog_id, catalog_version, lint_id,
    // param.id) so identical inputs always produce the same UUID.
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(catalog_id.as_bytes());
    seed.push(0);
    seed.extend_from_slice(catalog_version.as_bytes());
    seed.push(0);
    seed.extend_from_slice(lint_id.as_bytes());
    seed.push(0);
    seed.extend_from_slice(p.id.as_bytes());
    let param_uuid = uuid_v8(NS_PARAM, &seed);

    let mut props = Vec::with_capacity(2);
    props.push(prop("pkix-lint.param-uuid", &param_uuid));
    // The OSCAL `values` field below carries the *default* — operators
    // pass overrides via Profile `modify` directives at composition
    // time (PKIX-9vnx.6.5). Expose the same default as a prop too for
    // consumers that read props only.
    props.push(prop("pkix-lint.param-default", p.default_value.as_ref()));

    json!({
        // Compose the OSCAL param id as `<lint_id>.<param_id>` so two
        // lints exposing a parameter with the same local id (e.g.
        // "max-octets") do not collide in the catalog's flat param
        // namespace.
        "id": format!("{}.{}", lint_id, p.id),
        "label": p.label.as_ref(),
        "values": [p.default_value.as_ref()],
        "props": props,
    })
}

// ---------------------------------------------------------------------------
// Seed helpers
// ---------------------------------------------------------------------------

fn catalog_seed(catalog_id: &str, catalog_version: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(catalog_id.len() + catalog_version.len() + 1);
    buf.extend_from_slice(catalog_id.as_bytes());
    buf.push(0);
    buf.extend_from_slice(catalog_version.as_bytes());
    buf
}

fn control_seed(catalog_id: &str, catalog_version: &str, lint_id: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(catalog_id.len() + catalog_version.len() + lint_id.len() + 2);
    buf.extend_from_slice(catalog_id.as_bytes());
    buf.push(0);
    buf.extend_from_slice(catalog_version.as_bytes());
    buf.push(0);
    buf.extend_from_slice(lint_id.as_bytes());
    buf
}

#[cfg(test)]
mod tests {
    //! Independent oracle: assertions are anchored to the OSCAL Catalog
    //! v1.1.2 JSON Schema's required-field set (`uuid`, `metadata`,
    //! `controls` at the catalog root; `id`, `title` on each Control) and
    //! to the rfc5280 / fixture lint's own metadata methods (which are
    //! themselves tested independently in their own modules). The UUID
    //! derivation is verified by recomputing it with the same `uuid_v8`
    //! salt + seed in the test, providing a second-path oracle.
    //!
    //! Cross-crate round-trip coverage against the substantive
    //! `pkix-lint-cabf::cabf_tls_br` lint set lives in that crate's
    //! integration tests (`pkix-lint-cabf/tests/oscal_catalog_round_trip.rs`)
    //! so this module stays independent of CA/B Forum policy content.

    use super::*;
    use crate::rfc5280::Rfc5280MaxSerialLengthLint;
    use crate::{Lint, LintResult, Scope, Severity, SubjectKind};
    use x509_cert::Certificate;

    /// Fixture lint that mirrors the metadata shape of a CA/B Forum-style
    /// policy lint: `spec_section_id` overridden to a non-RFC string,
    /// `spec_url` left as `None`. Used to pin the "lint without spec_url
    /// omits the OSCAL links array" contract without depending on
    /// pkix-lint-cabf content.
    struct PolicyShapedLint {
        id: &'static str,
        section_id: &'static str,
    }
    impl Lint for PolicyShapedLint {
        fn id(&self) -> &'static str {
            self.id
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
        fn title(&self) -> &str {
            "Policy-shaped fixture lint (no RFC URL)"
        }
        fn spec_section_id(&self) -> Option<&str> {
            Some(self.section_id)
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

    /// Default `PolicyShapedLint` for the two-element `sample_lints()` set.
    const POLICY_SHAPED_DEFAULT: PolicyShapedLint = PolicyShapedLint {
        id: "test.policy.shaped",
        section_id: "test-policy-1.2.3",
    };

    fn sample_lints() -> Vec<Box<dyn Lint>> {
        vec![
            Box::new(Rfc5280MaxSerialLengthLint::default()),
            Box::new(POLICY_SHAPED_DEFAULT),
        ]
    }

    /// Multi-lint fixture used by `filter_to_ids` / round-trip tests where
    /// the count and ordering matter. Six lints with distinct ids mirrors
    /// the historical CABF TLS BR bundle size; the content is pkix-lint
    /// internal so the catalog/profile tests stay free of CA/B Forum
    /// policy dependencies.
    fn multi_lint_fixture() -> Vec<Box<dyn Lint>> {
        vec![
            Box::new(Rfc5280MaxSerialLengthLint::default()),
            Box::new(PolicyShapedLint {
                id: "test.policy.one",
                section_id: "test-policy-1",
            }),
            Box::new(PolicyShapedLint {
                id: "test.policy.two",
                section_id: "test-policy-2",
            }),
            Box::new(PolicyShapedLint {
                id: "test.policy.three",
                section_id: "test-policy-3",
            }),
            Box::new(PolicyShapedLint {
                id: "test.policy.four",
                section_id: "test-policy-4",
            }),
            Box::new(PolicyShapedLint {
                id: "test.policy.five",
                section_id: "test-policy-5",
            }),
        ]
    }

    #[test]
    fn catalog_has_required_top_level_fields() {
        let catalog = catalog_from_lints(&sample_lints(), "rs.pkix.test", "0.1.0");
        let cat = catalog.get("catalog").expect("catalog wrapper");
        assert!(cat.get("uuid").is_some(), "catalog.uuid required");
        assert!(cat.get("metadata").is_some(), "catalog.metadata required");
        assert!(cat.get("controls").is_some(), "catalog.controls required");

        let metadata = cat.get("metadata").unwrap();
        // OSCAL Catalog Metadata required: title, last-modified, version,
        // oscal-version.
        for required in ["title", "last-modified", "version", "oscal-version"] {
            assert!(
                metadata.get(required).is_some(),
                "catalog.metadata.{required} required"
            );
        }
        assert_eq!(metadata["oscal-version"], "1.1.2");
        assert_eq!(metadata["last-modified"], CATALOG_LAST_MODIFIED);
        assert_eq!(metadata["version"], "0.1.0");
    }

    #[test]
    fn rfc5280_lint_maps_to_control() {
        let catalog = catalog_from_lints(&sample_lints(), "rs.pkix.test", "0.1.0");
        let controls = catalog["catalog"]["controls"].as_array().unwrap();
        assert_eq!(controls.len(), 2);

        let rfc_control = &controls[0]; // first input = first output
        assert_eq!(
            rfc_control["id"],
            "rfc5280.cert.serial_number.max_octets"
        );
        assert_eq!(rfc_control["class"], "pkix-lint");
        assert_eq!(
            rfc_control["title"],
            "Certificate serialNumber must not exceed 20 octets"
        );

        // Props: citation, severity, scope, applies-to, section-id,
        // lint-id, control-uuid.
        let props = rfc_control["props"].as_array().expect("props array");
        let names: Vec<&str> = props.iter().map(|p| p["name"].as_str().unwrap()).collect();
        for expected in [
            "pkix-lint.citation",
            "pkix-lint.severity",
            "pkix-lint.scope",
            "pkix-lint.applies-to",
            "pkix-lint.section-id",
            "pkix-lint.lint-id",
            "pkix-lint.control-uuid",
        ] {
            assert!(
                names.contains(&expected),
                "missing prop {expected}; got: {names:?}"
            );
        }

        // RFC URL surfaces as a reference link.
        let links = rfc_control["links"].as_array().expect("links array");
        assert_eq!(links.len(), 1);
        assert_eq!(links[0]["rel"], "reference");
        assert_eq!(
            links[0]["href"],
            "https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.2"
        );

        // Parameters: the rfc5280 lint exposes max-octets.
        let params = rfc_control["params"].as_array().expect("params array");
        assert_eq!(params.len(), 1);
        assert_eq!(
            params[0]["id"],
            "rfc5280.cert.serial_number.max_octets.max-octets"
        );
        assert_eq!(params[0]["values"][0], "20");
    }

    #[test]
    fn policy_lint_without_spec_url_omits_links_array() {
        // PolicyShapedLint overrides spec_section_id but leaves spec_url
        // as None — the Catalog must therefore omit any `links` array
        // (we don't emit empty arrays). This pins the documented
        // behaviour from the trait rustdoc for any policy-style lint
        // that cites a non-RFC source (CA/B Forum, vendor CPS, etc.).
        let catalog = catalog_from_lints(&sample_lints(), "rs.pkix.test", "0.1.0");
        let controls = catalog["catalog"]["controls"].as_array().unwrap();
        let policy = &controls[1];
        assert_eq!(policy["id"], "test.policy.shaped");
        assert!(
            policy.get("links").is_none(),
            "Lint without spec_url must not emit links array; got: {policy}",
        );
        // section-id is still present (PolicyShapedLint overrides it).
        let props = policy["props"].as_array().unwrap();
        let section_id_prop = props
            .iter()
            .find(|p| p["name"] == "pkix-lint.section-id")
            .expect("section-id prop");
        assert_eq!(section_id_prop["value"], "test-policy-1.2.3");
    }

    #[test]
    fn output_is_byte_deterministic() {
        // Same input → identical serialised bytes across two independent
        // catalog_from_lints invocations.
        let c1 = catalog_from_lints(&sample_lints(), "rs.pkix.test", "0.1.0");
        let c2 = catalog_from_lints(&sample_lints(), "rs.pkix.test", "0.1.0");
        let s1 = serde_json::to_string(&c1).unwrap();
        let s2 = serde_json::to_string(&c2).unwrap();
        assert_eq!(s1, s2, "catalog output must be byte-deterministic");
    }

    #[test]
    fn catalog_uuid_is_uuid_v8_of_seed() {
        // Independent oracle: recompute the catalog UUID using uuid_v8
        // directly. If catalog_from_lints derives a different UUID for
        // the same seed inputs, the test fails — this pins the public
        // UUID derivation contract documented in the module rustdoc.
        let catalog = catalog_from_lints(&sample_lints(), "rs.pkix.test", "0.1.0");
        let observed = catalog["catalog"]["uuid"].as_str().unwrap();

        let mut expected_seed = Vec::new();
        expected_seed.extend_from_slice(b"rs.pkix.test");
        expected_seed.push(0);
        expected_seed.extend_from_slice(b"0.1.0");
        let expected = uuid_v8(NS_CATALOG, &expected_seed);

        assert_eq!(observed, expected);
    }

    #[test]
    fn changing_catalog_version_changes_all_uuids() {
        let v1 = catalog_from_lints(&sample_lints(), "rs.pkix.test", "0.1.0");
        let v2 = catalog_from_lints(&sample_lints(), "rs.pkix.test", "0.2.0");
        assert_ne!(
            v1["catalog"]["uuid"], v2["catalog"]["uuid"],
            "catalog UUID must change with version"
        );
        let c1 = &v1["catalog"]["controls"][0];
        let c2 = &v2["catalog"]["controls"][0];
        // Compare control-uuid props from each (control id stays the
        // same; only the UUID prop differs).
        let uuid_prop = |c: &Value| -> String {
            c["props"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["name"] == "pkix-lint.control-uuid")
                .unwrap()["value"]
                .as_str()
                .unwrap()
                .to_string()
        };
        assert_ne!(
            uuid_prop(c1),
            uuid_prop(c2),
            "control UUID must change with catalog version"
        );
    }

    #[test]
    fn empty_lint_list_yields_empty_controls_array() {
        let catalog = catalog_from_lints(&[], "rs.pkix.empty", "0.0.0");
        let controls = catalog["catalog"]["controls"].as_array().unwrap();
        assert!(controls.is_empty());
        // Required fields still present.
        assert!(catalog["catalog"]["uuid"].as_str().is_some());
    }

    #[test]
    fn parameter_id_is_namespaced_by_lint_id() {
        // Two lints exposing a parameter with the same local id ("foo")
        // must not collide in the catalog's flat parameter namespace.
        // We assert the rfc5280 lint's parameter id is namespaced with
        // the lint id; a future second parametric lint with the same
        // local "max-octets" id would then have a different OSCAL id.
        let catalog = catalog_from_lints(&sample_lints(), "rs.pkix.test", "0.1.0");
        let params = catalog["catalog"]["controls"][0]["params"]
            .as_array()
            .unwrap();
        let pid = params[0]["id"].as_str().unwrap();
        assert!(pid.starts_with("rfc5280.cert.serial_number.max_octets."));
        assert!(pid.ends_with(".max-octets"));
    }

    // -----------------------------------------------------------------
    // PKIX-9vnx.6.3 round-trip closure: catalog_from_lints → serde_json
    // → lint_ids_from_catalog → LintRunner::filter_to_ids → identical
    // Findings on a fixture chain. Uses the in-crate `multi_lint_fixture`
    // so the round-trip is exercised without depending on pkix-lint-cabf.
    // -----------------------------------------------------------------

    use super::super::parse::{lint_ids_from_catalog, ParseError};
    use crate::LintRunner;

    /// Load a fixture cert from the workspace pkix-path test corpus.
    fn load_cert(name: &str) -> x509_cert::Certificate {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../pkix-path/tests/fixtures/policy-checks/")
            .join(name);
        let der = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()));
        <x509_cert::Certificate as der::Decode>::from_der(&der)
            .unwrap_or_else(|e| panic!("decode {name}: {e}"))
    }

    #[test]
    fn lint_ids_from_catalog_extracts_in_order() {
        let lints = multi_lint_fixture();
        let expected_ids: Vec<String> = lints.iter().map(|l| l.id().to_string()).collect();
        let catalog = catalog_from_lints(&lints, "rs.pkix.test", "2.0.0");
        // Round-trip through serde to mimic real on-disk use.
        let serialized = serde_json::to_string(&catalog).expect("serialise");
        let parsed: Value = serde_json::from_str(&serialized).expect("deserialise");
        let ids = lint_ids_from_catalog(&parsed).expect("extract ids");
        assert_eq!(ids, expected_ids);
    }

    #[test]
    fn round_trip_preserves_findings_on_fixture() {
        // Independent oracle: run two runners — one direct from
        // `multi_lint_fixture`, one reconstructed from the OSCAL Catalog
        // round-trip — on the same fixture chain. The pkix-lint engine
        // itself is the *common substrate*; the test verifies the
        // round-trip preserves the *configured lint set*, not the
        // engine's correctness. Cross-crate round-trip coverage against
        // pkix-lint-cabf's real lint set lives in that crate's
        // integration tests.

        let cert = load_cert("leaf-rsa2048-sha1.der");

        let runner_direct = LintRunner::new(multi_lint_fixture());

        // Round-tripped runner: emit Catalog → serialise → parse → ids →
        // filter a fresh fixture set by those ids.
        let catalog = catalog_from_lints(&multi_lint_fixture(), "rs.pkix.test", "2.0.0");
        let serialised = serde_json::to_string(&catalog).expect("serialise");
        let parsed: Value = serde_json::from_str(&serialised).expect("parse");
        let ids = lint_ids_from_catalog(&parsed).expect("extract ids");
        let runner_round_trip = LintRunner::new(multi_lint_fixture())
            .filter_to_ids(&ids)
            .expect("filter to ids");

        assert_eq!(runner_round_trip.lints().len(), runner_direct.lints().len());

        let now_unix = 1_700_000_000u64;
        let direct = runner_direct.run_cert(&cert, crate::SubjectKind::Leaf, 0, now_unix);
        let round = runner_round_trip.run_cert(&cert, crate::SubjectKind::Leaf, 0, now_unix);

        // Compare findings sorted by lint_id (independent of evaluation
        // order, which round-trip preserves but we don't want to rely on).
        let mut direct_sorted: Vec<_> = direct.iter().collect();
        let mut round_sorted: Vec<_> = round.iter().collect();
        direct_sorted.sort_by(|a, b| a.lint_id.cmp(&b.lint_id));
        round_sorted.sort_by(|a, b| a.lint_id.cmp(&b.lint_id));

        assert_eq!(direct_sorted.len(), round_sorted.len());
        for (d, r) in direct_sorted.iter().zip(round_sorted.iter()) {
            assert_eq!(d.lint_id, r.lint_id);
            assert_eq!(d.result, r.result);
        }
    }

    #[test]
    fn filter_to_ids_errors_on_unknown_id() {
        let runner = LintRunner::new(multi_lint_fixture());
        let ids = vec!["test.policy.one".to_string(), "not.a.real.lint".to_string()];
        match runner.filter_to_ids(&ids) {
            Err(ParseError::UnknownLintId { id }) => {
                assert_eq!(id, "not.a.real.lint");
            }
            other => panic!("expected UnknownLintId error; got: {other:?}"),
        }
    }

    #[test]
    fn filter_to_ids_preserves_id_order() {
        // Reverse the natural order — filter_to_ids must produce a runner
        // whose lints are in the order *ids* requests, not the source order.
        let direct = multi_lint_fixture();
        let mut reversed_ids: Vec<String> = direct.iter().map(|l| l.id().to_string()).collect();
        reversed_ids.reverse();

        let runner = LintRunner::new(multi_lint_fixture())
            .filter_to_ids(&reversed_ids)
            .expect("filter ok");

        let observed: Vec<&str> = runner.lints().iter().map(|l| l.id()).collect();
        let expected: Vec<&str> = reversed_ids.iter().map(String::as_str).collect();
        assert_eq!(observed, expected);
    }

    #[test]
    fn filter_to_ids_subset_drops_other_lints() {
        let runner = LintRunner::new(multi_lint_fixture());
        let ids = vec!["test.policy.one".to_string()];
        let filtered = runner.filter_to_ids(&ids).expect("filter ok");
        assert_eq!(filtered.lints().len(), 1);
        assert_eq!(filtered.lints()[0].id(), "test.policy.one");
    }

    #[test]
    fn filter_to_ids_preserves_bundle_version() {
        let runner = LintRunner::with_bundle_version(multi_lint_fixture(), "v9.9.9");
        let ids = vec!["test.policy.one".to_string()];
        let filtered = runner.filter_to_ids(&ids).expect("filter ok");
        assert_eq!(filtered.bundle_version(), "v9.9.9");
    }

    #[test]
    fn lint_ids_from_catalog_rejects_non_object_root() {
        let v: Value = serde_json::from_str("[]").unwrap();
        match lint_ids_from_catalog(&v) {
            Err(ParseError::CatalogNotObject) => {}
            other => panic!("expected CatalogNotObject; got: {other:?}"),
        }
    }

    #[test]
    fn lint_ids_from_catalog_rejects_missing_wrapper() {
        let v: Value = serde_json::json!({"not-catalog": {}});
        match lint_ids_from_catalog(&v) {
            Err(ParseError::CatalogMissingWrapper) => {}
            other => panic!("expected CatalogMissingWrapper; got: {other:?}"),
        }
    }

    #[test]
    fn lint_ids_from_catalog_rejects_non_array_controls() {
        let v: Value = serde_json::json!({"catalog": {"controls": "not-an-array"}});
        match lint_ids_from_catalog(&v) {
            Err(ParseError::ControlsNotArray) => {}
            other => panic!("expected ControlsNotArray; got: {other:?}"),
        }
    }

    #[test]
    fn lint_ids_from_catalog_rejects_control_missing_id() {
        let v: Value = serde_json::json!({"catalog": {"controls": [{"title": "no id here"}]}});
        match lint_ids_from_catalog(&v) {
            Err(ParseError::ControlMissingId { index: 0 }) => {}
            other => panic!("expected ControlMissingId; got: {other:?}"),
        }
    }
}
