//! The `_smtp._tls` TXT record — RFC 8460 §3.

use pkix_tlsrpt::{txt_name, ReportingEndpoint, TlsRptError, TlsRptRecord};

fn rec(text: &str) -> TlsRptRecord {
    TlsRptRecord::parse(text).expect("record should parse")
}

// ---------------------------------------------------------------------------
// §3.1 the RFC's own examples
// ---------------------------------------------------------------------------

/// §3.1.1, verbatim.
#[test]
fn the_rfc_mailto_example_parses() {
    let r = rec("v=TLSRPTv1;rua=mailto:reports@example.com");
    assert_eq!(
        r.endpoints(),
        [ReportingEndpoint::Mailto(String::from(
            "reports@example.com"
        ))]
    );
}

/// §3.1.2, verbatim.
#[test]
fn the_rfc_https_example_parses() {
    let r = rec("v=TLSRPTv1; rua=https://reporting.example.com/v1/tlsrpt");
    assert_eq!(
        r.endpoints(),
        [ReportingEndpoint::Https(String::from(
            "https://reporting.example.com/v1/tlsrpt"
        ))]
    );
}

#[test]
fn the_txt_name_follows_the_rfc() {
    assert_eq!(txt_name("example.com"), "_smtp._tls.example.com");
    assert_eq!(txt_name("example.com."), "_smtp._tls.example.com");
    assert_eq!(txt_name("mail.example.com"), "_smtp._tls.mail.example.com");
}

// ---------------------------------------------------------------------------
// §3 rua lists
// ---------------------------------------------------------------------------

/// "As with DMARC, the Policy Domain can specify a comma-separated list."
#[test]
fn a_comma_separated_rua_list_keeps_every_endpoint_in_order() {
    let r = rec("v=TLSRPTv1; rua=mailto:a@example.com,https://r.example.com/x");
    assert_eq!(
        r.endpoints(),
        [
            ReportingEndpoint::Mailto(String::from("a@example.com")),
            ReportingEndpoint::Https(String::from("https://r.example.com/x")),
        ],
        "order is preserved, since §3 lets a sender stop at the first that \
         accepts delivery"
    );
}

#[test]
fn whitespace_around_list_entries_is_ignored() {
    let r = rec("v=TLSRPTv1; rua= mailto:a@example.com , https://r.example.com/x ");
    assert_eq!(r.endpoints().len(), 2);
}

/// One unusable URI does not discard the usable ones.
///
/// §3 has a sender deliver to "each of the supported rua destinations", so a
/// domain that published one bad URI alongside a good one should still get
/// its reports.
#[test]
fn an_unsupported_scheme_alongside_a_usable_one_keeps_the_usable_one() {
    let r = rec("v=TLSRPTv1; rua=ftp://nope.example.com,mailto:a@example.com");
    assert_eq!(
        r.endpoints(),
        [ReportingEndpoint::Mailto(String::from("a@example.com"))]
    );
}

/// Only unusable URIs is reported as such, not as an absent record.
///
/// An operator who published only an `ftp:` endpoint needs to know why no
/// reports arrive; "this domain does not implement TLSRPT" would be wrong and
/// unactionable.
#[test]
fn only_unsupported_schemes_is_reported_as_a_scheme_error() {
    assert_eq!(
        TlsRptRecord::parse("v=TLSRPTv1; rua=ftp://nope.example.com"),
        Err(TlsRptError::UnsupportedUriScheme(String::from(
            "ftp://nope.example.com"
        )))
    );
}

/// §3 supports exactly `mailto` and `https`, so plain HTTP is refused.
///
/// Worth asserting: a report sent over plaintext HTTP would expose which of a
/// domain's hosts have broken TLS to anyone on the path, which is §7's
/// concern.
#[test]
fn plain_http_is_not_a_supported_scheme() {
    assert!(matches!(
        TlsRptRecord::parse("v=TLSRPTv1; rua=http://reporting.example.com/x"),
        Err(TlsRptError::UnsupportedUriScheme(_))
    ));
}

/// URI schemes are case-insensitive per RFC 3986 §3.1.
#[test]
fn uri_schemes_are_matched_case_insensitively() {
    assert_eq!(
        rec("v=TLSRPTv1; rua=MAILTO:a@example.com").endpoints(),
        [ReportingEndpoint::Mailto(String::from("a@example.com"))]
    );
    assert_eq!(
        rec("v=TLSRPTv1; rua=HTTPS://r.example.com/x")
            .endpoints()
            .len(),
        1
    );
}

#[test]
fn an_empty_mailto_address_is_refused() {
    assert!(matches!(
        TlsRptRecord::parse("v=TLSRPTv1; rua=mailto:"),
        Err(TlsRptError::UnsupportedUriScheme(_))
    ));
}

// ---------------------------------------------------------------------------
// §3 required fields and the version tag
// ---------------------------------------------------------------------------

/// `rua` is required; a record without one names nowhere to report.
#[test]
fn rua_is_required() {
    assert_eq!(
        TlsRptRecord::parse("v=TLSRPTv1;"),
        Err(TlsRptError::MissingRua)
    );
    assert_eq!(
        TlsRptRecord::parse("v=TLSRPTv1"),
        Err(TlsRptError::MissingRua)
    );
}

#[test]
fn an_empty_rua_is_refused() {
    assert_eq!(
        TlsRptRecord::parse("v=TLSRPTv1; rua="),
        Err(TlsRptError::EmptyRua)
    );
}

/// The record MUST begin with the version field.
#[test]
fn a_record_not_beginning_with_the_version_tag_is_not_a_tlsrpt_record() {
    for bad in [
        "rua=mailto:a@example.com; v=TLSRPTv1",
        "v=spf1 -all",
        "v=TLSRPTv2; rua=mailto:a@example.com",
        "v=STSv1; id=abc123;",
        "",
    ] {
        assert_eq!(
            TlsRptRecord::parse(bad),
            Err(TlsRptError::NoTlsRptRecord),
            "{bad:?} is not a TLSRPT record"
        );
    }
}

/// §3: "Parsers MUST accept TXT records that are syntactically valid ... and
/// implement a superset of this specification, in which case unknown fields
/// SHALL be ignored."
///
/// A MUST rather than a nicety, so a sender that rejected unknown fields
/// would be non-conformant, not merely strict.
#[test]
fn unknown_fields_must_be_ignored() {
    let r = rec("v=TLSRPTv1; rua=mailto:a@example.com; future=whatever; x_y.z=1");
    assert_eq!(r.endpoints().len(), 1);
}

#[test]
fn a_line_without_an_equals_is_malformed() {
    assert_eq!(
        TlsRptRecord::parse("v=TLSRPTv1; rua=mailto:a@example.com; garbage"),
        Err(TlsRptError::MalformedField(String::from("garbage")))
    );
}

// ---------------------------------------------------------------------------
// §3 selecting among several records
// ---------------------------------------------------------------------------

#[test]
fn other_txt_records_at_the_same_name_are_discarded() {
    let r = TlsRptRecord::select([
        "v=spf1 -all",
        "google-site-verification=xyz",
        "v=TLSRPTv1; rua=mailto:a@example.com",
    ])
    .expect("the one TLSRPT record is selected");
    assert_eq!(r.endpoints().len(), 1);
}

/// "If the number of resulting records is not one, senders MUST assume the
/// recipient domain does not implement TLSRPT."
///
/// Not resolved by picking one: a domain with two reporting policies has not
/// said where reports go, and guessing could send its failure reports to
/// whichever endpoint happened to sort first.
#[test]
fn two_tlsrpt_records_are_ambiguous_rather_than_resolved() {
    assert_eq!(
        TlsRptRecord::select([
            "v=TLSRPTv1; rua=mailto:a@example.com",
            "v=TLSRPTv1; rua=mailto:b@example.com",
        ]),
        Err(TlsRptError::MultipleTlsRptRecords(2))
    );
}

#[test]
fn no_tlsrpt_record_among_several_is_reported_as_none() {
    assert_eq!(
        TlsRptRecord::select(["v=spf1 -all", "unrelated"]),
        Err(TlsRptError::NoTlsRptRecord)
    );
    assert_eq!(TlsRptRecord::select([]), Err(TlsRptError::NoTlsRptRecord));
}

// ---------------------------------------------------------------------------
// §3 multiple character-strings
// ---------------------------------------------------------------------------

/// "If the resulting TXT record contains multiple strings ... the record MUST
/// be treated as if those strings are concatenated without adding spaces."
///
/// A record with several `rua` URIs exceeds a 255-byte character-string and
/// arrives split. Joining with a space would corrupt whichever URI straddles
/// the boundary and the reports would go nowhere.
#[test]
fn multiple_character_strings_are_joined_without_spaces() {
    let r = TlsRptRecord::from_txt_strings(&[b"v=TLSRPTv1; rua=mailto:repo", b"rts@example.com"])
        .expect("the halves join into one record");
    assert_eq!(
        r.endpoints(),
        [ReportingEndpoint::Mailto(String::from(
            "reports@example.com"
        ))],
        "the address straddled the split and must come back whole"
    );
}

/// And the join really inserts nothing.
///
/// Without this, a space-joining implementation would pass the test above
/// whenever the split happened to fall between fields.
#[test]
fn the_join_inserts_nothing_at_the_boundary() {
    let joined =
        TlsRptRecord::from_txt_strings(&[b"v=TLSRPTv1; rua=https://r.example.com/aaa", b"bbb"])
            .expect("parses");
    assert_eq!(
        joined.endpoints(),
        [ReportingEndpoint::Https(String::from(
            "https://r.example.com/aaabbb"
        ))]
    );
}

#[test]
fn the_discard_test_applies_to_split_strings() {
    assert!(TlsRptRecord::is_tlsrpt_txt_strings(&[
        b"v=TLSRP",
        b"Tv1; rua=mailto:a@example.com"
    ]));
    assert!(!TlsRptRecord::is_tlsrpt_txt_strings(&[b"v=spf1 ", b"-all"]));
    assert!(!TlsRptRecord::is_tlsrpt_txt_strings(&[]));
}

#[test]
fn a_non_utf8_record_is_not_a_tlsrpt_record() {
    assert_eq!(
        TlsRptRecord::from_txt_strings(&[b"v=TLSRPTv1; rua=mailto:\xff\xfe"]),
        Err(TlsRptError::NoTlsRptRecord)
    );
}

/// The endpoint round-trips back to its published URI form.
#[test]
fn an_endpoint_renders_back_to_its_uri() {
    assert_eq!(
        ReportingEndpoint::Mailto(String::from("a@example.com")).as_uri(),
        "mailto:a@example.com"
    );
    assert_eq!(
        ReportingEndpoint::Https(String::from("https://r.example.com/x")).as_uri(),
        "https://r.example.com/x"
    );
}
