//! RFC 5280 conformance lints.
//!
//! This module ships [`Lint`] implementations that enforce structural and
//! semantic rules from [RFC 5280][rfc5280]. Each lint is keyed by an OSCAL
//! Control-id-shaped identifier (`rfc5280-<section>`) and cites the
//! relevant section in its rustdoc.
//!
//! The lints here are intentionally lean and parameterless except where
//! the underlying RFC explicitly admits an operator-tunable threshold;
//! see [`Rfc5280MaxSerialLengthLint`] for the first such case.
//!
//! [rfc5280]: https://www.rfc-editor.org/rfc/rfc5280
//!
//! # Provenance
//!
//! Added in PKIX-9vnx.6.4 as the demonstration vehicle for the
//! [`Lint::parameters`] / [`Lint::set_parameter`] OSCAL Parameter
//! mechanism. CABF-shaped lints now live in the `pkix-lint-cabf`
//! crate ([`cabf_tls_br`][cabf_tls_br]); project policy (see workspace
//! `AGENTS.md` and the PKIX-amgn / PKIX-9vnx alignment epics) is that
//! RFC-conformance lints stay in `pkix-lint` while CA/B Forum policy
//! lints live in `pkix-lint-cabf`.
//!
//! [cabf_tls_br]: https://docs.rs/pkix-lint-cabf/latest/pkix_lint_cabf/cabf_tls_br/

use std::borrow::Cow;

use x509_cert::Certificate;

use crate::{
    Lint, LintParameter, LintResult, ParameterError, Scope, Severity, SubjectKind,
};

// ---------------------------------------------------------------------------
// rfc5280.cert.serial_number.max_octets
// ---------------------------------------------------------------------------

/// RFC 5280 §4.1.2.2: serialNumber must not exceed 20 octets.
///
/// > Conforming CAs MUST NOT use serialNumber values longer than 20
/// > octets.  Conforming CAs MUST NOT use the value zero for the
/// > serialNumber field.
///
/// This lint enforces the upper-bound clause. The 20-octet cap is the
/// default; operators may tighten it via the `max-octets` OSCAL parameter
/// (e.g., to model a more restrictive in-house issuance policy). Setting
/// `max-octets` above 20 is permitted but advertises a deliberate
/// deviation from RFC 5280 baseline.
///
/// # OSCAL parameters
///
/// | id            | label                                            | default |
/// |---------------|--------------------------------------------------|--------:|
/// | `max-octets`  | Maximum allowed serial number length in octets   | `20`    |
///
/// # Provenance
///
/// First parametric Lint added under PKIX-9vnx.6.4. Doubles as the
/// pkix-lint built-in fixture that tests OSCAL parameter overrides.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rfc5280MaxSerialLengthLint {
    max_octets: usize,
    parameters: Vec<LintParameter>,
}

impl Default for Rfc5280MaxSerialLengthLint {
    fn default() -> Self {
        // RFC 5280 §4.1.2.2 baseline cap.
        Self::with_max_octets(20)
    }
}

impl Rfc5280MaxSerialLengthLint {
    /// Construct the lint with an explicit `max_octets` cap.
    ///
    /// Equivalent to calling [`Default::default`] followed by
    /// [`Lint::set_parameter`] with id `"max-octets"`; provided as a typed
    /// constructor for callers configuring the lint at compile time.
    #[must_use]
    pub fn with_max_octets(max_octets: usize) -> Self {
        let parameters = vec![LintParameter {
            id: Cow::Borrowed("max-octets"),
            label: Cow::Borrowed("Maximum allowed serial number length in octets"),
            default_value: Cow::Borrowed("20"),
        }];
        Self {
            max_octets,
            parameters,
        }
    }

    /// Current `max_octets` cap. Useful for round-trip OSCAL emit tests.
    #[must_use]
    pub fn max_octets(&self) -> usize {
        self.max_octets
    }
}

impl Lint for Rfc5280MaxSerialLengthLint {
    fn id(&self) -> &'static str {
        "rfc5280.cert.serial_number.max_octets"
    }

    fn citation(&self) -> &'static str {
        "RFC 5280 §4.1.2.2"
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

    fn title(&self) -> &str {
        "Certificate serialNumber must not exceed 20 octets"
    }

    fn rfc_section_id(&self) -> Option<&str> {
        Some("rfc5280-4.1.2.2")
    }

    fn rfc_url(&self) -> Option<&str> {
        Some("https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.2")
    }

    fn parameters(&self) -> &[LintParameter] {
        &self.parameters
    }

    fn set_parameter(&mut self, id: &str, value: &str) -> Result<(), ParameterError> {
        match id {
            "max-octets" => {
                let parsed: usize = value.parse().map_err(|_| ParameterError::InvalidValue {
                    id: id.to_owned(),
                    reason: format!("expected non-negative integer, got '{value}'"),
                })?;
                if parsed == 0 {
                    return Err(ParameterError::InvalidValue {
                        id: id.to_owned(),
                        reason: "max-octets must be at least 1".to_string(),
                    });
                }
                self.max_octets = parsed;
                Ok(())
            }
            other => Err(ParameterError::UnknownParameter(other.to_owned())),
        }
    }

    fn check_cert(&self, cert: &Certificate, _kind: SubjectKind, _now_unix: u64) -> LintResult {
        // `SerialNumber::as_bytes` returns the canonical big-endian unsigned
        // bytes (DER content of the INTEGER, with any leading 0x00 sign
        // padding byte already stripped per the SerialNumber type's invariant
        // in the x509-cert crate).  The RFC 5280 "20 octets" cap is on the
        // ENCODED INTEGER content, which is exactly what `as_bytes` reports;
        // confirmed against the x509-cert SerialNumber rustdoc.
        let len = cert.tbs_certificate.serial_number.as_bytes().len();
        if len > self.max_octets {
            // Dynamic detail (Cow::Owned): include the actual length so
            // the audit trail attributes the failure to a specific value.
            LintResult::error(format!(
                "certificate serialNumber is {} octets, exceeds cap of {} octets",
                len, self.max_octets
            ))
        } else {
            LintResult::Pass
        }
    }
}

#[cfg(test)]
mod tests {
    //! Independent oracle for serial-length assertions:
    //!
    //! ```text
    //! openssl x509 -in <fixture> -inform DER -noout -serial \
    //!   | sed 's/serial=//' \
    //!   | awk '{ print length($0)/2 " octets" }'
    //! ```
    //!
    //! Fixture serial-length oracle values (verified 2026-05-11):
    //!
    //! | fixture                                 | serial octets |
    //! |-----------------------------------------|--------------:|
    //! | leaf-rsa2047-365d-san-eku.der           |             3 |
    //! | leaf-p256-50d-post-sc081-100d.der       |            20 |
    //! | leaf-rsa2048-sha1.der                   |            20 |
    //!
    //! These values are the OS `openssl` reading of the certificate's
    //! `tbsCertificate.serialNumber` INTEGER content, independent of the
    //! code under test (which uses the `x509-cert` Rust crate's parser).
    //!
    //! Note on "21-octet" boundary: the `x509-cert` `SerialNumber::new`
    //! constructor refuses inputs longer than 20 bytes (`Overlength`
    //! error), and the `Rfc5280` Profile's decode-time check rejects
    //! anything beyond 21 bytes — so a real-world cert with a > 21-octet
    //! serial cannot be loaded through this stack at all. We exercise
    //! the lint's `> max_octets` branch by tightening the parameter (cap
    //! < the fixture's serial length) rather than constructing an
    //! oversize synthetic cert; the comparison is the same
    //! `len > self.max_octets` integer test either way.
    //!
    //! No test uses the code under test as its own oracle.

    use super::*;
    use x509_cert::Certificate;

    fn load_cert(name: &str) -> Certificate {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../pkix-path/tests/fixtures/policy-checks/")
            .join(name);
        let der = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()));
        <Certificate as der::Decode>::from_der(&der)
            .unwrap_or_else(|e| panic!("decode fixture {name}: {e}"))
    }

    #[test]
    fn default_lint_accepts_20_octet_serial() {
        // Oracle: `openssl x509 -serial` on leaf-p256-50d-post-sc081-100d.der
        // reports 20 octets.
        let lint = Rfc5280MaxSerialLengthLint::default();
        assert_eq!(lint.max_octets(), 20);
        let cert = load_cert("leaf-p256-50d-post-sc081-100d.der");
        assert_eq!(cert.tbs_certificate.serial_number.as_bytes().len(), 20);
        assert_eq!(
            lint.check_cert(&cert, SubjectKind::Leaf, 0),
            LintResult::Pass
        );
    }

    #[test]
    fn default_lint_accepts_short_serial() {
        // Oracle: leaf-rsa2047-365d-san-eku.der has a 3-octet serial.
        let lint = Rfc5280MaxSerialLengthLint::default();
        let cert = load_cert("leaf-rsa2047-365d-san-eku.der");
        assert_eq!(cert.tbs_certificate.serial_number.as_bytes().len(), 3);
        assert_eq!(
            lint.check_cert(&cert, SubjectKind::Leaf, 0),
            LintResult::Pass
        );
    }

    #[test]
    fn tightened_cap_rejects_20_octet_serial_with_attribution() {
        // Tighten the cap below the fixture's 20-octet serial — same code
        // path as the RFC-baseline rejection of a hypothetical > 20-octet
        // serial, but constructible from real fixtures (see module-level
        // oracle note).
        let mut lint = Rfc5280MaxSerialLengthLint::default();
        lint.set_parameter("max-octets", "10")
            .expect("set_parameter ok");
        let cert = load_cert("leaf-rsa2048-sha1.der");
        assert_eq!(cert.tbs_certificate.serial_number.as_bytes().len(), 20);
        match lint.check_cert(&cert, SubjectKind::Leaf, 0) {
            LintResult::Error(detail) => {
                assert!(
                    detail.contains("20 octets"),
                    "error detail must name the actual length 20; got: {detail}"
                );
                assert!(
                    detail.contains("10 octets"),
                    "error detail must name the cap 10; got: {detail}"
                );
            }
            other => panic!("expected Error, got: {other:?}"),
        }
    }

    #[test]
    fn set_parameter_to_3_keeps_3_octet_serial_passing() {
        // Boundary case: a 3-octet serial must pass when the cap is set
        // to exactly 3. Verifies the comparison is `>` not `>=`.
        let mut lint = Rfc5280MaxSerialLengthLint::default();
        lint.set_parameter("max-octets", "3").expect("set ok");
        let cert = load_cert("leaf-rsa2047-365d-san-eku.der");
        assert_eq!(cert.tbs_certificate.serial_number.as_bytes().len(), 3);
        assert_eq!(
            lint.check_cert(&cert, SubjectKind::Leaf, 0),
            LintResult::Pass
        );
    }

    #[test]
    fn set_parameter_to_2_rejects_3_octet_serial() {
        // Tighten one octet below the fixture; expect Error with both
        // actual (3) and cap (2) reported.
        let mut lint = Rfc5280MaxSerialLengthLint::default();
        lint.set_parameter("max-octets", "2").expect("set ok");
        let cert = load_cert("leaf-rsa2047-365d-san-eku.der");
        match lint.check_cert(&cert, SubjectKind::Leaf, 0) {
            LintResult::Error(detail) => {
                assert!(detail.contains("3 octets"));
                assert!(detail.contains("2 octets"));
            }
            other => panic!("expected Error, got: {other:?}"),
        }
    }

    #[test]
    fn set_parameter_unknown_id_errors() {
        let mut lint = Rfc5280MaxSerialLengthLint::default();
        let err = lint
            .set_parameter("not-a-real-parameter", "1")
            .expect_err("unknown id must error");
        match err {
            ParameterError::UnknownParameter(id) => {
                assert_eq!(id, "not-a-real-parameter");
            }
            other => panic!("expected UnknownParameter, got: {other:?}"),
        }
    }

    #[test]
    fn set_parameter_invalid_value_errors() {
        let mut lint = Rfc5280MaxSerialLengthLint::default();
        // Non-numeric input.
        let err = lint
            .set_parameter("max-octets", "not-a-number")
            .expect_err("non-numeric value must error");
        match err {
            ParameterError::InvalidValue { id, .. } => assert_eq!(id, "max-octets"),
            other => panic!("expected InvalidValue, got: {other:?}"),
        }
        // Zero is rejected (a zero cap would reject every serialNumber,
        // including valid ones — almost certainly an operator typo).
        let err_zero = lint
            .set_parameter("max-octets", "0")
            .expect_err("zero value must error");
        match err_zero {
            ParameterError::InvalidValue { id, reason } => {
                assert_eq!(id, "max-octets");
                assert!(reason.contains("at least 1"));
            }
            other => panic!("expected InvalidValue, got: {other:?}"),
        }
    }

    #[test]
    fn parameters_advertises_max_octets() {
        let lint = Rfc5280MaxSerialLengthLint::default();
        let params = lint.parameters();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].id, "max-octets");
        assert_eq!(params[0].default_value, "20");
        assert!(!params[0].label.is_empty());
    }

    #[test]
    fn metadata_matches_rfc_section() {
        let lint = Rfc5280MaxSerialLengthLint::default();
        assert_eq!(lint.id(), "rfc5280.cert.serial_number.max_octets");
        assert_eq!(lint.citation(), "RFC 5280 §4.1.2.2");
        assert_eq!(lint.rfc_section_id(), Some("rfc5280-4.1.2.2"));
        assert_eq!(
            lint.rfc_url(),
            Some("https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.2")
        );
    }
}
