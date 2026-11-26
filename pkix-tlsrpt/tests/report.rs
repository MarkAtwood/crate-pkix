//! The report schema — RFC 8460 §4.4 — and the filename — §5.1.

use pkix_tlsrpt::{
    rfc3339_utc, sts_policy_string, DateRange, FailureDetail, ReportFilename, ResultType,
};

// The report-building types are only reachable from the tests that
// serialise one, and `to_json_string` / `from_json` live behind the `json`
// feature — so in a default build this file would otherwise import names it
// never uses. PKIX-6vfq.
#[cfg(feature = "json")]
use pkix_tlsrpt::{PolicyBlock, PolicyDescriptor, PolicyType, Report, Summary};

/// A report built from the RFC's own schema example, with the field values
/// from §4.4's prose and §4.5's policy sample.
#[cfg(feature = "json")]
fn example_report() -> Report {
    Report {
        organization_name: String::from("Company-X"),
        date_range: DateRange {
            start_datetime: String::from("2016-04-01T00:00:00Z"),
            end_datetime: String::from("2016-04-01T23:59:59Z"),
        },
        contact_info: String::from("sts-reporting@company-x.example"),
        report_id: String::from("5065427c-23d3-47ca-b6e0-946ea0e8c4be"),
        policies: vec![PolicyBlock {
            policy: PolicyDescriptor {
                policy_type: PolicyType::Sts,
                policy_string: Some(sts_policy_string(
                    "testing",
                    &[
                        String::from("mx1.example.com"),
                        String::from("mx2.example.com"),
                        String::from("mx.backup-example.com"),
                    ],
                    604_800,
                )),
                policy_domain: String::from("example.com"),
                mx_host: Some(vec![String::from("*.example.com")]),
            },
            summary: Summary {
                total_successful_session_count: 5326,
                total_failure_session_count: 303,
            },
            failure_details: vec![FailureDetail::new(ResultType::CertificateExpired, 100)
                .with_receiving_mx_hostname("mx1.example.com")
                .with_sending_mta_ip("2001:db8:abcd:0012::1")],
        }],
    }
}

// ---------------------------------------------------------------------------
// §4.4 JSON round trip
// ---------------------------------------------------------------------------

/// The schema round-trips without loss.
#[cfg(feature = "json")]
#[test]
fn a_report_round_trips_through_json() {
    let original = example_report();
    let json = original.to_json_string().expect("serialises");
    let parsed = Report::from_json(&json).expect("deserialises");
    assert_eq!(parsed, original);
}

/// The field names are §4.4's exactly.
///
/// Kebab-case with specific spellings, and a receiver matches on them
/// literally — a report with `policy_type` instead of `policy-type` is not a
/// report, however well-formed the JSON.
#[cfg(feature = "json")]
#[test]
fn the_field_names_are_the_rfcs_own() {
    let json = example_report().to_json_string().expect("serialises");
    for field in [
        "organization-name",
        "date-range",
        "start-datetime",
        "end-datetime",
        "contact-info",
        "report-id",
        "policies",
        "policy",
        "policy-type",
        "policy-string",
        "policy-domain",
        "mx-host",
        "summary",
        "total-successful-session-count",
        "total-failure-session-count",
        "failure-details",
        "result-type",
        "failed-session-count",
        "receiving-mx-hostname",
        "sending-mta-ip",
    ] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "§4.4 field {field:?} missing from the serialised report"
        );
    }
    // Every JSON *key* must be kebab-case. Checked by walking the keys
    // rather than scanning the whole document, because `policy-string`
    // legitimately contains MTA-STS policy text including `max_age:` — the
    // policy's own field name, not this schema's.
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    fn assert_keys_are_kebab(v: &serde_json::Value) {
        match v {
            serde_json::Value::Object(map) => {
                for (k, inner) in map {
                    assert!(
                        !k.contains('_'),
                        "JSON key {k:?} is snake_case; §4.4 uses kebab-case"
                    );
                    assert_keys_are_kebab(inner);
                }
            }
            serde_json::Value::Array(items) => items.iter().for_each(assert_keys_are_kebab),
            _ => {}
        }
    }
    assert_keys_are_kebab(&value);
}

/// A report parsed from §4.4's literal document shape.
///
/// Written as the RFC prints it rather than produced by this crate, so the
/// deserialiser is tested against the spec rather than against the
/// serialiser.
#[cfg(feature = "json")]
#[test]
fn a_report_in_the_rfcs_literal_shape_parses() {
    let json = r#"{
      "organization-name": "Company-X",
      "date-range": {
        "start-datetime": "2016-04-01T00:00:00Z",
        "end-datetime": "2016-04-01T23:59:59Z"
      },
      "contact-info": "sts-reporting@company-x.example",
      "report-id": "5065427c-23d3-47ca-b6e0-946ea0e8c4be",
      "policies": [{
        "policy": {
          "policy-type": "sts",
          "policy-string": ["version: STSv1","mode: testing",
                "mx: *.mail.company-y.example","max_age: 86400"],
          "policy-domain": "company-y.example",
          "mx-host": ["*.mail.company-y.example"]
        },
        "summary": {
          "total-successful-session-count": 5326,
          "total-failure-session-count": 303
        },
        "failure-details": [{
          "result-type": "certificate-expired",
          "sending-mta-ip": "2001:db8:abcd:0012::1",
          "receiving-mx-hostname": "mx1.mail.company-y.example",
          "failed-session-count": 100
        }, {
          "result-type": "starttls-not-supported",
          "sending-mta-ip": "2001:db8:abcd:0013::1",
          "receiving-mx-hostname": "mx2.mail.company-y.example",
          "receiving-ip": "203.0.113.56",
          "failed-session-count": 200,
          "additional-information": "https://reports.company-x.example/report_info?id=5065427c-23d3#StarttlsNotSupported"
        }, {
          "result-type": "validation-failure",
          "sending-mta-ip": "198.51.100.62",
          "receiving-ip": "203.0.113.58",
          "receiving-mx-hostname": "mx-backup.mail.company-y.example",
          "failed-session-count": 3,
          "failure-reason-code": "X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED"
        }]
      }]
    }"#;
    let report = Report::from_json(json).expect("the RFC's own report shape should parse");

    assert_eq!(report.organization_name, "Company-X");
    assert_eq!(report.policies.len(), 1);
    assert_eq!(report.total_successful_sessions(), 5326);
    assert_eq!(report.total_failed_sessions(), 303);

    let details = &report.policies[0].failure_details;
    assert_eq!(details.len(), 3);
    assert_eq!(details[0].result_type, ResultType::CertificateExpired);
    assert_eq!(details[1].result_type, ResultType::StarttlsNotSupported);
    assert_eq!(details[2].result_type, ResultType::ValidationFailure);
    assert_eq!(
        details[2].failure_reason_code.as_deref(),
        Some("X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED"),
        "§4.3.3's own example of a reason code"
    );
    assert_eq!(details[1].receiving_ip.as_deref(), Some("203.0.113.56"));

    // And it round-trips back out.
    let again = Report::from_json(&report.to_json_string().unwrap()).unwrap();
    assert_eq!(again, report);
}

/// Optional fields are omitted rather than serialised as null.
///
/// A receiver parsing `"receiving-ip": null` where §4.4 expects a string may
/// reject the report, so absence is expressed by absence.
#[test]
fn absent_optional_fields_are_omitted_not_null() {
    let minimal = FailureDetail::new(ResultType::StarttlsNotSupported, 1);
    let json = serde_json::to_string(&minimal).expect("serialises");
    assert!(!json.contains("null"), "{json}");
    assert!(!json.contains("receiving-ip"), "{json}");
    assert!(
        json.contains("\"result-type\":\"starttls-not-supported\""),
        "{json}"
    );
    assert!(json.contains("\"failed-session-count\":1"), "{json}");
}

/// A result type this version does not know round-trips unchanged.
///
/// §4.3: the list "is expected to grow over time based on real-world
/// experience", so a report from a newer sender must survive a parse rather
/// than being rejected or silently relabelled.
#[test]
fn an_unknown_result_type_round_trips() {
    let json = r#"{"result-type":"some-future-type","failed-session-count":7}"#;
    let detail: FailureDetail = serde_json::from_str(json).expect("parses");
    assert_eq!(
        detail.result_type,
        ResultType::Other(String::from("some-future-type"))
    );
    assert_eq!(
        serde_json::to_string(&detail).unwrap(),
        json,
        "and serialises back to exactly what arrived"
    );
}

// ---------------------------------------------------------------------------
// §4.5 policy samples
// ---------------------------------------------------------------------------

/// §4.5: "where there are multiple `mx` values, they must be listed as
/// separate `mx` elements in the policy array rather than as a single nested
/// `mx` sub-array."
///
/// The trap the RFC calls out by name, because the obvious encoding groups
/// them.
#[test]
fn each_mx_pattern_is_its_own_policy_string_element() {
    let lines = sts_policy_string(
        "testing",
        &[
            String::from("mx1.example.com"),
            String::from("mx2.example.com"),
            String::from("mx.backup-example.com"),
        ],
        604_800,
    );
    assert_eq!(
        lines,
        [
            "version: STSv1",
            "mode: testing",
            "mx: mx1.example.com",
            "mx: mx2.example.com",
            "mx: mx.backup-example.com",
            "max_age: 604800",
        ],
        "§4.5's sample, exactly"
    );
    assert_eq!(
        lines.iter().filter(|l| l.starts_with("mx: ")).count(),
        3,
        "three separate mx elements, not one nested array"
    );
}

// ---------------------------------------------------------------------------
// §5.1 filename
// ---------------------------------------------------------------------------

/// §5.1's own example filename.
#[test]
fn the_rfc_example_filename_is_produced() {
    let name = ReportFilename::new(
        "mail.sndr.example.com",
        "example.net",
        1_470_013_207,
        1_470_186_007,
    )
    .with_unique_id("001")
    .compressed();
    assert_eq!(
        name.to_string(),
        "mail.sndr.example.com!example.net!1470013207!1470186007!001.json.gz"
    );
}

/// §5.1: the extension "MUST be `json` for a plain JSON file or `json.gz` for
/// a JSON file compressed using gzip".
#[test]
fn the_extension_follows_whether_the_body_is_compressed() {
    let plain = ReportFilename::new("s.example", "d.example", 1, 2);
    assert_eq!(plain.extension(), "json");
    assert_eq!(plain.to_string(), "s.example!d.example!1!2.json");

    let gz = plain.clone().compressed();
    assert_eq!(gz.extension(), "json.gz");
    assert_eq!(gz.to_string(), "s.example!d.example!1!2.json.gz");
}

/// The unique id is optional and omitted cleanly.
#[test]
fn the_unique_id_is_optional() {
    let name = ReportFilename::new("s.example", "d.example", 100, 200);
    assert_eq!(name.to_string(), "s.example!d.example!100!200.json");
    assert!(
        !name.to_string().contains("!!"),
        "no empty field is left behind"
    );
}

/// A unique id is filtered to §5.1's `1*(ALPHA / DIGIT)`.
///
/// `!` and `.` are the filename's own delimiters, so letting them through
/// would make the name ambiguous to a receiver splitting on them — it would
/// read a timestamp or an extension where the id was.
#[test]
fn a_unique_id_is_filtered_to_alphanumerics() {
    let name = ReportFilename::new("s.example", "d.example", 1, 2).with_unique_id("ab!c.d-e_1");
    assert_eq!(name.unique_id.as_deref(), Some("abcde1"));
    assert_eq!(name.to_string(), "s.example!d.example!1!2!abcde1.json");
}

/// An id with nothing alphanumeric in it is dropped rather than left empty.
#[test]
fn an_entirely_punctuation_unique_id_is_dropped() {
    let name = ReportFilename::new("s.example", "d.example", 1, 2).with_unique_id("!!..--");
    assert_eq!(name.unique_id, None);
    assert_eq!(name.to_string(), "s.example!d.example!1!2.json");
}

// ---------------------------------------------------------------------------
// §4.4 timestamps
// ---------------------------------------------------------------------------

/// §4.4 wants RFC 3339 UTC.
#[test]
fn timestamps_are_rfc3339_utc() {
    assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
    assert_eq!(rfc3339_utc(1_470_013_207), "2016-08-01T01:00:07Z");
    assert_eq!(rfc3339_utc(1_700_000_000), "2023-11-14T22:13:20Z");
}

/// Leap years and month boundaries, which a hand-written date conversion is
/// exactly where it would go wrong.
#[test]
fn the_date_conversion_handles_leap_years_and_boundaries() {
    assert_eq!(
        rfc3339_utc(951_782_400),
        "2000-02-29T00:00:00Z",
        "2000 was a leap year"
    );
    assert_eq!(
        rfc3339_utc(1_709_164_800),
        "2024-02-29T00:00:00Z",
        "so was 2024"
    );
    assert_eq!(
        rfc3339_utc(4_107_542_400),
        "2100-03-01T00:00:00Z",
        "2100 is NOT a leap year — the century rule"
    );
    assert_eq!(rfc3339_utc(1_709_251_199), "2024-02-29T23:59:59Z");
    assert_eq!(rfc3339_utc(1_709_251_200), "2024-03-01T00:00:00Z");
    assert_eq!(rfc3339_utc(1_735_689_599), "2024-12-31T23:59:59Z");
    assert_eq!(rfc3339_utc(1_735_689_600), "2025-01-01T00:00:00Z");
}

/// A full UTC day, as §4.1 asks for.
#[test]
fn a_date_range_spans_a_utc_day() {
    let start = 1_470_009_600; // 2016-08-01T00:00:00Z
    let range = DateRange::from_unix(start, start + 86_399);
    assert_eq!(range.start_datetime, "2016-08-01T00:00:00Z");
    assert_eq!(range.end_datetime, "2016-08-01T23:59:59Z");
}

// ---------------------------------------------------------------------------
// Summary helpers
// ---------------------------------------------------------------------------

/// A report with no failures is still a report worth sending.
///
/// It tells a domain in MTA-STS `testing` mode that enforcing is safe, which
/// is the entire purpose of that mode.
#[cfg(feature = "json")]
#[test]
fn an_all_successful_report_has_no_failures_but_still_counts_sessions() {
    let report = Report {
        organization_name: String::from("Org"),
        date_range: DateRange::from_unix(0, 86_399),
        contact_info: String::from("a@example.com"),
        report_id: String::from("1"),
        policies: vec![PolicyBlock {
            policy: PolicyDescriptor {
                policy_type: PolicyType::NoPolicyFound,
                policy_string: None,
                policy_domain: String::from("example.com"),
                mx_host: None,
            },
            summary: Summary {
                total_successful_session_count: 42,
                total_failure_session_count: 0,
            },
            failure_details: Vec::new(),
        }],
    };
    assert!(!report.has_failures());
    assert_eq!(report.total_successful_sessions(), 42);
    assert_eq!(report.total_failed_sessions(), 0);

    // no-policy-found omits the policy-string and mx-host entirely.
    let json = report.to_json_string().expect("serialises");
    assert!(!json.contains("policy-string"), "{json}");
    assert!(!json.contains("mx-host"), "{json}");
    assert!(
        json.contains("\"policy-type\":\"no-policy-found\""),
        "{json}"
    );
}

/// The result-type predicates group the §4.3 sections correctly.
#[test]
fn the_result_type_predicates_match_the_rfcs_sections() {
    for t in [
        ResultType::TlsaInvalid,
        ResultType::DnssecInvalid,
        ResultType::DaneRequired,
    ] {
        assert!(t.is_dane_policy_failure(), "{t} is §4.3.2.1");
        assert!(!t.is_sts_policy_failure(), "{t}");
    }
    for t in [
        ResultType::StsPolicyFetchError,
        ResultType::StsPolicyInvalid,
        ResultType::StsWebpkiInvalid,
    ] {
        assert!(t.is_sts_policy_failure(), "{t} is §4.3.2.2");
        assert!(!t.is_dane_policy_failure(), "{t}");
    }
    // §4.3.1 negotiation failures are neither.
    for t in [
        ResultType::StarttlsNotSupported,
        ResultType::CertificateHostMismatch,
        ResultType::CertificateExpired,
    ] {
        assert!(
            !t.is_dane_policy_failure() && !t.is_sts_policy_failure(),
            "{t}"
        );
    }
}

/// The two broad labels are the ones §4.3 asks for a reason code with.
#[test]
fn only_the_broad_labels_want_a_reason_code() {
    assert!(ResultType::CertificateNotTrusted.wants_reason_code());
    assert!(ResultType::ValidationFailure.wants_reason_code());
    assert!(!ResultType::CertificateExpired.wants_reason_code());
    assert!(!ResultType::StarttlsNotSupported.wants_reason_code());
}
