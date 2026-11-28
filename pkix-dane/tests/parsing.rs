//! TLSA RDATA parsing, field-octet round-trips, and owner-name construction.

use pkix_dane::{
    record::TlsaRecord, DaneError, TlsaMatchingType, TlsaName, TlsaProtocol, TlsaSelector,
    TlsaUsage,
};

// -------------------------------------------------------------------------
// RDATA wire format
// -------------------------------------------------------------------------

#[test]
fn parses_the_three_octet_header_and_association_data() {
    // usage 3 (DANE-EE), selector 1 (SPKI), matching type 1 (SHA2-256).
    let mut rdata = vec![3, 1, 1];
    rdata.extend_from_slice(&[0xab; 32]);

    let rec = TlsaRecord::from_rdata(&rdata).expect("well-formed RDATA should parse");
    assert_eq!(rec.usage(), TlsaUsage::DaneEe);
    assert_eq!(rec.selector(), TlsaSelector::Spki);
    assert_eq!(rec.matching_type(), TlsaMatchingType::Sha256);
    assert_eq!(rec.association_data(), &[0xab; 32]);
    assert!(rec.is_usable());
}

#[test]
fn rdata_round_trips() {
    let mut rdata = vec![2, 0, 2];
    rdata.extend_from_slice(&[0x5c; 64]);

    let rec = TlsaRecord::from_rdata(&rdata).expect("well-formed RDATA should parse");
    assert_eq!(rec.to_rdata(), rdata);
}

/// RDATA shorter than the fixed header is malformed — an error, unlike a
/// record that merely carries parameters this crate does not implement.
#[test]
fn rdata_shorter_than_the_header_is_an_error() {
    for len in 0..3_usize {
        let rdata = vec![0u8; len];
        assert_eq!(
            TlsaRecord::from_rdata(&rdata),
            Err(DaneError::RecordTruncated { len }),
            "RDATA of {len} octet(s) should be rejected as truncated"
        );
    }
}

/// Exactly three octets parses: the association data is empty, which makes the
/// record unusable but not malformed. The distinction is deliberate — see
/// `TlsaRecord::is_usable`.
#[test]
fn header_only_rdata_parses_but_is_unusable() {
    let rec = TlsaRecord::from_rdata(&[3, 0, 1]).expect("a bare header should parse");
    assert!(rec.association_data().is_empty());
    assert!(!rec.is_usable());
}

/// Unrecognized field values must survive parsing so the caller can skip the
/// record rather than fail the connection.
#[test]
fn unrecognized_field_values_parse_into_unassigned_variants() {
    let mut rdata = vec![42, 43, 44];
    rdata.extend_from_slice(&[0x01; 32]);

    let rec = TlsaRecord::from_rdata(&rdata).expect("unrecognized values should still parse");
    assert_eq!(rec.usage(), TlsaUsage::Unassigned(42));
    assert_eq!(rec.selector(), TlsaSelector::Unassigned(43));
    assert_eq!(rec.matching_type(), TlsaMatchingType::Unassigned(44));
    assert!(!rec.is_usable());
    assert_eq!(rec.to_rdata(), rdata);
}

// -------------------------------------------------------------------------
// Field octet round-trips over the whole octet range
// -------------------------------------------------------------------------

/// Every one of the 256 octet values must round-trip through each field type.
/// This is what makes the `Unassigned` / `PrivateUse` variants a faithful
/// model of the wire format rather than a lossy approximation.
#[test]
fn every_octet_round_trips_through_each_field() {
    for octet in 0..=u8::MAX {
        assert_eq!(TlsaUsage::from_octet(octet).to_octet(), octet);
        assert_eq!(TlsaSelector::from_octet(octet).to_octet(), octet);
        assert_eq!(TlsaMatchingType::from_octet(octet).to_octet(), octet);
    }
}

#[test]
fn assigned_ranges_match_the_iana_registries() {
    let assigned_usages = [
        (0, TlsaUsage::PkixTa),
        (1, TlsaUsage::PkixEe),
        (2, TlsaUsage::DaneTa),
        (3, TlsaUsage::DaneEe),
    ];
    for (octet, expected) in assigned_usages {
        assert_eq!(TlsaUsage::from_octet(octet), expected);
        assert!(expected.is_assigned());
    }
    for octet in 4..=254_u8 {
        assert_eq!(TlsaUsage::from_octet(octet), TlsaUsage::Unassigned(octet));
        assert!(!TlsaUsage::from_octet(octet).is_assigned());
    }
    assert_eq!(TlsaUsage::from_octet(255), TlsaUsage::PrivateUse);
    assert!(!TlsaUsage::PrivateUse.is_assigned());

    assert_eq!(TlsaSelector::from_octet(0), TlsaSelector::Cert);
    assert_eq!(TlsaSelector::from_octet(1), TlsaSelector::Spki);
    for octet in 2..=254_u8 {
        assert!(!TlsaSelector::from_octet(octet).is_assigned());
    }
    assert_eq!(TlsaSelector::from_octet(255), TlsaSelector::PrivateUse);

    assert_eq!(TlsaMatchingType::from_octet(0), TlsaMatchingType::Full);
    assert_eq!(TlsaMatchingType::from_octet(1), TlsaMatchingType::Sha256);
    assert_eq!(TlsaMatchingType::from_octet(2), TlsaMatchingType::Sha512);
    for octet in 3..=254_u8 {
        assert!(!TlsaMatchingType::from_octet(octet).is_assigned());
    }
    assert_eq!(
        TlsaMatchingType::from_octet(255),
        TlsaMatchingType::PrivateUse
    );
}

#[test]
fn digest_lengths_are_the_rfc_values() {
    assert_eq!(TlsaMatchingType::Sha256.digest_len(), Some(32));
    assert_eq!(TlsaMatchingType::Sha512.digest_len(), Some(64));
    assert_eq!(TlsaMatchingType::Full.digest_len(), None);
    assert_eq!(TlsaMatchingType::Unassigned(7).digest_len(), None);
    assert_eq!(TlsaMatchingType::PrivateUse.digest_len(), None);
}

/// Only the two PKIX usages require the caller to also run path validation.
#[test]
fn pkix_usages_are_the_ones_requiring_path_validation() {
    assert!(TlsaUsage::PkixTa.requires_pkix_validation());
    assert!(TlsaUsage::PkixEe.requires_pkix_validation());
    assert!(!TlsaUsage::DaneTa.requires_pkix_validation());
    assert!(!TlsaUsage::DaneEe.requires_pkix_validation());
}

// -------------------------------------------------------------------------
// Owner names
// -------------------------------------------------------------------------

#[test]
fn renders_the_rfc_6698_owner_name_form() {
    let cases = [
        (
            443,
            TlsaProtocol::Tcp,
            "www.example.com",
            "_443._tcp.www.example.com",
        ),
        (
            25,
            TlsaProtocol::Tcp,
            "mail.example.com",
            "_25._tcp.mail.example.com",
        ),
        (
            853,
            TlsaProtocol::Udp,
            "dns.example.net",
            "_853._udp.dns.example.net",
        ),
        (1, TlsaProtocol::Sctp, "a.example", "_1._sctp.a.example"),
    ];
    for (port, proto, host, expected) in cases {
        let name = TlsaName::new(port, &proto, host).expect("valid inputs");
        assert_eq!(name.as_str(), expected);
    }
}

/// Port numbers are rendered in decimal without leading zeros, across the
/// whole u16 range including both ends.
#[test]
fn ports_render_in_plain_decimal() {
    assert_eq!(
        TlsaName::new(0, &TlsaProtocol::Tcp, "a.example")
            .expect("port 0 is syntactically fine")
            .as_str(),
        "_0._tcp.a.example"
    );
    assert_eq!(
        TlsaName::new(65535, &TlsaProtocol::Tcp, "a.example")
            .expect("valid")
            .as_str(),
        "_65535._tcp.a.example"
    );
    for port in [1_u16, 9, 10, 99, 100, 999, 1000, 9999, 10000] {
        let name = TlsaName::new(port, &TlsaProtocol::Tcp, "a.example").expect("valid");
        let rendered = name.as_str();
        let digits = &rendered["_".len()..rendered.find("._tcp").expect("has proto")];
        assert_eq!(digits.parse::<u16>().expect("decimal digits"), port);
        assert!(!digits.starts_with('0') || digits == "0");
    }
}

/// A trailing dot is the explicit root label and must be preserved: querying
/// `example.com.` and `example.com` are the same lookup only after the
/// resolver applies its search list, which is not this type's business.
#[test]
fn a_trailing_root_label_is_preserved() {
    let name = TlsaName::new(443, &TlsaProtocol::Tcp, "example.com.").expect("valid");
    assert_eq!(name.as_str(), "_443._tcp.example.com.");
}

#[test]
fn underscore_and_wildcard_labels_are_accepted_in_hosts() {
    assert!(TlsaName::new(443, &TlsaProtocol::Tcp, "_service.example.com").is_ok());
    assert!(TlsaName::new(443, &TlsaProtocol::Tcp, "*.example.com").is_ok());
}

#[test]
fn malformed_hosts_are_rejected() {
    let bad = [
        "",               // empty
        ".",              // root only
        ".example.com",   // leading empty label
        "a..example.com", // interior empty label
        "example.com..",  // two trailing dots
        "exa mple.com",   // space
        "exa/mple.com",   // slash
        "exämple.com",    // non-ASCII; caller must convert to A-label
    ];
    for host in bad {
        assert_eq!(
            TlsaName::new(443, &TlsaProtocol::Tcp, host),
            Err(DaneError::InvalidHost),
            "host {host:?} should be rejected"
        );
    }
}

#[test]
fn over_long_labels_and_names_are_rejected() {
    let long_label = "a".repeat(64);
    assert_eq!(
        TlsaName::new(443, &TlsaProtocol::Tcp, &long_label),
        Err(DaneError::InvalidHost)
    );

    // 63 is the limit, so this one is fine.
    let max_label = "a".repeat(63);
    assert!(TlsaName::new(443, &TlsaProtocol::Tcp, &max_label).is_ok());

    // Four maximal labels plus separators overflow the 253-octet name limit,
    // while every individual label is legal.
    let long_name = [max_label.as_str(); 4].join(".");
    assert!(matches!(
        TlsaName::new(443, &TlsaProtocol::Tcp, &long_name),
        Err(DaneError::NameTooLong { .. })
    ));
}

#[test]
fn malformed_protocol_labels_are_rejected() {
    for proto in ["", "TCP", "tc p", "tcp.udp", "tcp-"] {
        assert_eq!(
            TlsaName::new(443, &TlsaProtocol::Other(proto.into()), "example.com"),
            Err(DaneError::InvalidProtocol),
            "protocol {proto:?} should be rejected"
        );
    }
    assert!(TlsaName::new(443, &TlsaProtocol::Other("quic".into()), "example.com").is_ok());
}

#[test]
fn display_renders_the_same_text_as_as_str() {
    let name = TlsaName::new(443, &TlsaProtocol::Tcp, "example.com").expect("valid");
    assert_eq!(alloc_format(&name), name.as_str());
}

fn alloc_format(name: &TlsaName) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    write!(out, "{name}").expect("writing to a String cannot fail");
    out
}

/// A protocol label may be 63 octets, and not 64.
///
/// 63 is the DNS label limit (RFC 1035 §2.3.4), so a label exactly that
/// long is legal and one octet more cannot be put in a query at all.
/// `malformed_protocol_labels_are_rejected` covers the short and
/// ill-formed cases and nothing approached the limit, so `> MAX_LABEL_LEN`
/// read as `>=` or `==` refuses a legal label -- and read as `==`, a
/// 64-octet one is accepted and builds a name no resolver will take.
///
/// The labels are all-lowercase so length is the only thing in question.
#[test]
fn a_protocol_label_may_be_sixty_three_octets_but_not_sixty_four() {
    let at_limit = "a".repeat(63);
    let name = TlsaName::new(443, &TlsaProtocol::Other(at_limit.clone()), "example.com")
        .expect("63 octets is a legal DNS label");
    assert!(
        name.as_str().contains(&at_limit),
        "the label appears in the query name"
    );

    let over_limit = "a".repeat(64);
    assert_eq!(
        TlsaName::new(443, &TlsaProtocol::Other(over_limit), "example.com"),
        Err(DaneError::InvalidProtocol),
        "64 octets exceeds the DNS label limit"
    );
}
