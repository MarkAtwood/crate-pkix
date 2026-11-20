//! Review regression tests for `pkix-identity`.
//!
//! Fixtures in `tests/fixtures/review/` are produced by `gen.py` there
//! (unsigned-in-effect leaves; pkix-identity never verifies signatures):
//!
//! - `smtputf8_ascii_local_leaf.der`: only SAN is
//!   otherName(SmtpUTF8Mailbox, UTF8String "alice@evil.com").
//! - `smtputf8_intl_ulabel_leaf.der`: only SAN is
//!   otherName(SmtpUTF8Mailbox, UTF8String "用户@bücher.example").

use der::Decode as _;
use pkix_identity::{verify_mailbox, IdentityError, MailboxName, ServerName};
use x509_cert::Certificate;

fn load(name: &str) -> Certificate {
    let path = format!(
        "{}/tests/fixtures/review/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let der = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    Certificate::from_der(&der).unwrap_or_else(|e| panic!("bad DER {path}: {e}"))
}

/// The rustdoc of `verify_mailbox` says: "An ASCII [`MailboxName`] matches
/// `rfc822Name` only ... the two SAN forms encode disjoint identity
/// spaces", and RFC 8398 §3 says SmtpUTF8Mailbox MUST only be used when the
/// local-part contains non-ASCII characters (ASCII local-parts MUST use
/// rfc822Name). `san_entry_matches_mailbox` does not gate the otherName arm
/// on `is_internationalized`, so an ASCII target binds to a (non-conformant)
/// SmtpUTF8Mailbox SAN. Combined with pkix-path ignoring otherName for
/// rfc822Name name constraints, this lets a CA constrained to
/// `example.com` mint a working S/MIME identity for `alice@evil.com`.
#[test]
fn review_ascii_mailbox_must_not_match_smtputf8mailbox_san() {
    let cert = load("smtputf8_ascii_local_leaf.der");
    let target = MailboxName::parse("alice@evil.com").unwrap();
    assert_eq!(
        verify_mailbox(&cert, &target),
        Err(IdentityError::NoMatchingSan)
    );
}

/// `parse_ipv4` uses `u32::from_str`, which accepts a leading '+'.
#[test]
fn review_ipv4_rejects_plus_sign() {
    assert_eq!(
        ServerName::ip_address("+1.+2.+3.+4").err(),
        Some(IdentityError::MalformedInput)
    );
}

/// `parse_ipv6` uses `u16::from_str_radix`, which also accepts a leading '+'.
#[test]
fn review_ipv6_rejects_plus_sign() {
    assert_eq!(
        ServerName::ip_address("+1::").err(),
        Some(IdentityError::MalformedInput)
    );
    assert_eq!(
        ServerName::ip_address("2001:db8::+1").err(),
        Some(IdentityError::MalformedInput)
    );
}

/// A conformant SmtpUTF8Mailbox (non-ASCII local-part) with a U-label
/// domain still binds, for both U-label and A-label targets.
#[test]
fn review_internationalized_mailbox_u_label_domain_still_matches() {
    let cert = load("smtputf8_intl_ulabel_leaf.der");
    for t in ["用户@bücher.example", "用户@xn--bcher-kva.example"] {
        let target = MailboxName::parse(t).unwrap();
        assert_eq!(verify_mailbox(&cert, &target), Ok(()), "{t}");
    }
}
