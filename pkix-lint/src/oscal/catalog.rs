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
//! | [`Lint::rfc_section_id`]     | `control.props[name="pkix-lint.section-id"]`       |
//! | [`Lint::rfc_url`]            | `control.links[rel="reference"].href`              |
//! | [`Lint::description`]        | `control.parts[name="statement"]` (`prose`)        |
//! | [`Lint::parameters`]         | `control.params[]`                                 |
//!
//! [`Lint::id`]: crate::Lint::id
//! [`Lint::title`]: crate::Lint::title
//! [`Lint::citation`]: crate::Lint::citation
//! [`Lint::severity`]: crate::Lint::severity
//! [`Lint::scope`]: crate::Lint::scope
//! [`Lint::applies_to`]: crate::Lint::applies_to
//! [`Lint::rfc_section_id`]: crate::Lint::rfc_section_id
//! [`Lint::rfc_url`]: crate::Lint::rfc_url
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
    if let Some(section_id) = lint.rfc_section_id() {
        props.push(prop("pkix-lint.section-id", section_id));
    }
    // Carry the lint id as a prop too so OSCAL consumers that key off
    // props (rather than the OSCAL Control.id) still find it.
    props.push(prop("pkix-lint.lint-id", lint.id()));
    // UUID pin: documents the deterministic UUID derivation for
    // post-hoc verification by tools that recompute UUIDs.
    props.push(prop("pkix-lint.control-uuid", &control_uuid));

    let mut links: Vec<Value> = Vec::new();
    if let Some(url) = lint.rfc_url() {
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
    //! to the rfc5280 / cabf_tls_br lint's own metadata methods (which
    //! are themselves tested independently in their own modules). The
    //! UUID derivation is verified by recomputing it with the same
    //! `uuid_v8` salt + seed in the test, providing a second-path
    //! oracle.

    use super::*;
    use crate::cabf_tls_br::ValidityMaxLint;
    use crate::rfc5280::Rfc5280MaxSerialLengthLint;
    use crate::Lint;

    fn sample_lints() -> Vec<Box<dyn Lint>> {
        vec![
            Box::new(Rfc5280MaxSerialLengthLint::default()),
            Box::new(ValidityMaxLint),
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
    fn cabf_lint_omits_rfc_url_link() {
        // ValidityMaxLint overrides rfc_section_id but leaves rfc_url
        // as None — the Catalog must therefore omit any `links` array
        // (we don't emit empty arrays). This pins the documented CABF
        // behaviour from the trait rustdoc.
        let catalog = catalog_from_lints(&sample_lints(), "rs.pkix.test", "0.1.0");
        let controls = catalog["catalog"]["controls"].as_array().unwrap();
        let cabf = &controls[1];
        assert_eq!(cabf["id"], "cabf.br.tls.validity.max");
        assert!(
            cabf.get("links").is_none(),
            "CABF lint without rfc_url must not emit links array; got: {}",
            cabf
        );
        // section-id is still present (CABF lint overrides it).
        let props = cabf["props"].as_array().unwrap();
        let section_id_prop = props
            .iter()
            .find(|p| p["name"] == "pkix-lint.section-id")
            .expect("section-id prop");
        assert_eq!(section_id_prop["value"], "cabf-tls-br-6.3.2");
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
}
