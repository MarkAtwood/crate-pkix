//! Review regression tests: RFC 5280 §4.2.1.10 / §6.1.3(b)(c) / §6.1.4(g)
//! NameConstraints processing.
//!
//! Fixtures live in `tests/fixtures/review/nc/` and are produced by `gen.py`
//! there (stdlib DER builder + `openssl dgst -sign`, ECDSA P-256). Every
//! chain is `root (anchor, no NC) -> int1 [-> int2] -> leaf`. The OpenSSL
//! 3.0 verdict for each chain is recorded in the fixture README as an
//! independent oracle.
//!
//! Tests prefixed `ctl_` are controls. Every `review_nc_*` test reproduced
//! a defect found in review A1 (it failed before the fix); the
//! `review_nc_fix_*` tests pin the boundaries of those fixes.

#![cfg(feature = "p256")]

use der::Decode as _;
use pkix_path::{DefaultVerifier, Error, TrustAnchor, ValidationPolicy};
use x509_cert::Certificate;

/// 2025-01-01T00:00:00Z — inside the 2000..2050 fixture validity window.
const NOW: u64 = 1_735_689_600;

fn load(name: &str) -> Option<Certificate> {
    let path = format!(
        "{}/tests/fixtures/review/nc/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let der = std::fs::read(&path).ok()?;
    Some(Certificate::from_der(&der).unwrap_or_else(|e| panic!("bad DER {path}: {e}")))
}

/// Validate `<tag>_leaf.der`, `[<tag>_int2.der]`, `<tag>_int1.der` against `root.der`.
fn run(tag: &str) -> Result<(), Error> {
    let root = load("root.der").expect("root.der");
    let mut chain = vec![load(&format!("{tag}_leaf.der")).expect("leaf")];
    if let Some(int2) = load(&format!("{tag}_int2.der")) {
        chain.push(int2);
    }
    chain.push(load(&format!("{tag}_int1.der")).expect("int1"));
    let anchor = TrustAnchor::try_from(root).expect("anchor");
    pkix_path::validate_path(
        &chain,
        &[anchor],
        &ValidationPolicy::new(NOW),
        &DefaultVerifier,
    )
    .map(|_| ())
}

fn assert_rejected(tag: &str) {
    match run(tag) {
        Err(Error::NameConstraintViolation { .. }) => {}
        other => panic!("{tag}: expected NameConstraintViolation, got {other:?}"),
    }
}

fn assert_accepted(tag: &str) {
    if let Err(e) = run(tag) {
        panic!("{tag}: expected Ok, got Err({e:?})");
    }
}

// ----------------------------------------------------------------- controls

#[test]
fn ctl_dns_excluded_is_enforced() {
    assert_rejected("ctl_dns_excl");
}

#[test]
fn ctl_uri_permitted_accepts_matching_host() {
    assert_accepted("ctl_uri_perm");
}

#[test]
fn ctl_uri_permitted_rejects_other_host() {
    assert_rejected("ctl_uri_bad");
}

#[test]
fn ctl_ip_single_permitted_accepts() {
    assert_accepted("ctl_ip_single");
}

#[test]
fn ctl_rfc822_permitted_rejects_other_domain() {
    assert_rejected("ctl_rfc822_perm");
}

// ------------------------------------------------- formerly false accepts

/// int1 excludes dNSName `evil.com`; leaf SAN is `www.evil.com.` (absolute
/// form). `matches_dns_name` compares the raw string, so the trailing dot
/// defeats the suffix match, while `pkix_identity::verify_dns_name` strips
/// the dot and binds the cert to `www.evil.com`. RFC 5280 §4.2.1.6 requires
/// dNSName in RFC 1034 preferred syntax (no trailing dot), so the name is
/// either malformed (reject) or must be normalized before NC matching.
#[test]
fn review_nc_dns_trailing_dot_escapes_excluded_subtree() {
    assert_rejected("dns_trailing_dot");
}

/// int1 excludes dNSName "" (zero labels). RFC 5280 §4.2.1.10: "Any DNS
/// name that can be constructed by simply adding zero or more labels to the
/// left-hand side of the name satisfies the name constraint", so "" covers
/// every DNS name; `matches_dns_name` returns false for an empty constraint.
/// OpenSSL rejects this chain (excluded subtree violation).
#[test]
fn review_nc_empty_excluded_dns_constraint_ignored() {
    assert_rejected("dns_empty_excluded");
}

/// int1 permits URI host `good.com`; leaf SAN URI is
/// `https://evil.com/@good.com`. `matches_uri` splits on the first '@'
/// anywhere after "://" (including the path), so it compares `good.com`.
/// The RFC 3986 authority is `evil.com`. OpenSSL rejects.
#[test]
fn review_nc_uri_at_in_path_spoofs_permitted_host() {
    assert_rejected("uri_at_in_path_perm");
}

/// Same parsing defect against an excluded URI host: `https://evil.com/a@b.example`
/// is judged to have host `b.example`. OpenSSL rejects.
#[test]
fn review_nc_uri_at_in_path_escapes_excluded_host() {
    assert_rejected("uri_at_in_path_excl");
}

/// int1 has an excluded URI constraint; leaf SAN URI `urn:example:evil`
/// has no authority. RFC 5280 §4.2.1.10: "If the URI doesn't include an
/// authority component with a host name specified as a fully qualified
/// domain name ... the application MUST reject the certificate."
/// `matches_uri` returns false (no match), so with only excluded subtrees
/// the cert is accepted. OpenSSL rejects.
#[test]
fn review_nc_uri_without_authority_must_be_rejected() {
    assert_rejected("uri_no_authority");
}

/// Same RFC 5280 §4.2.1.10 MUST for a URI whose host is an IP address
/// (`https://192.0.2.1/`). (OpenSSL 3.0 accepts this one; the RFC text is
/// explicit.)
#[test]
fn review_nc_uri_with_ip_host_must_be_rejected() {
    assert_rejected("uri_ip_host");
}

/// int1 permits rfc822Name `example.com`; leaf has only an
/// otherName/SmtpUTF8Mailbox `alice@evil.com`. RFC 8398 §6 extends
/// rfc822Name constraints to SmtpUTF8Mailbox SANs. `name_type_bit` maps
/// otherName to EMPTY, so the SAN is treated as unconstrained, and
/// `pkix_identity::verify_mailbox` then binds the cert to
/// `alice@evil.com`. OpenSSL rejects (permitted subtree violation).
#[test]
fn review_nc_smtputf8mailbox_escapes_rfc822_permitted_subtree() {
    assert_rejected("smtputf8_vs_rfc822");
}

/// int1 has a *critical* NC excluding otherName(UPN admin@corp.example);
/// leaf SAN carries exactly that UPN. RFC 5280 §4.2.1.10: "If a name
/// constraints extension that is marked as critical imposes constraints on
/// a particular name form, and an instance of that name form appears in
/// the subject field or subjectAltName extension of a subsequent
/// certificate, then the application MUST either process the constraint or
/// reject the certificate." pkix-path does neither. OpenSSL rejects
/// ("unsupported name constraint type").
#[test]
fn review_nc_unsupported_name_form_excluded_silently_ignored() {
    match run("othername_excluded") {
        Err(_) => {}
        Ok(()) => {
            panic!("othername_excluded: critical otherName exclusion ignored; chain accepted")
        }
    }
}

/// Permitted-subtree variant of the above (UPN permitted = user@corp.example,
/// leaf UPN = admin@other.example).
#[test]
fn review_nc_unsupported_name_form_permitted_silently_ignored() {
    match run("othername_permitted") {
        Err(_) => {}
        Ok(()) => panic!("othername_permitted: critical otherName permitted subtree ignored"),
    }
}

/// int1 excludes rfc822Name domain `evil.com`; leaf SAN rfc822Name is the
/// valid RFC 5322 addr-spec `"x@good.com"@evil.com` (quoted local-part).
/// `matches_rfc822_name` uses `split_once('@')`, taking `good.com"@evil.com`
/// as the domain. The mailbox domain is the text after the *last* '@'.
/// OpenSSL rejects (excluded subtree violation).
#[test]
fn review_nc_rfc822_quoted_local_part_escapes_excluded_domain() {
    assert_rejected("rfc822_quoted_at");
}

/// int1 permits rfc822Name `example.com`; leaf has no SAN and its subject
/// carries `emailAddress = alice@evil.com` encoded as UTF8String instead of
/// IA5String. `check_name_constraints` does `let Ok(..) = decode_as::<Ia5StringRef>
/// else { continue }`, silently skipping the RFC 5280 §4.2.1.10 emailAddress
/// check (fail-open on malformed input). OpenSSL rejects ("unsupported or
/// invalid name syntax").
#[test]
fn review_nc_dn_email_address_non_ia5_skips_rfc822_check() {
    match run("dn_email_utf8") {
        Err(_) => {}
        Ok(()) => panic!("dn_email_utf8: emailAddress outside permitted subtree accepted"),
    }
}

// ------------------------------------------------- formerly false rejects

/// int1 and int2 both permit iPAddress 10.0.0.0/8; leaf SAN is 10.1.2.3.
/// The intersection (RFC 5280 §6.1.4(g)(1)) reuses `name_matches_subtree`
/// with a *constraint* (8-byte addr+mask) in the "name" position;
/// `matches_ip_address` requires a 4-byte subject, so every IP entry is
/// dropped, the intersection is empty and all IP SANs are forbidden.
/// OpenSSL accepts.
#[test]
fn review_nc_ip_permitted_intersection_wrongly_empty() {
    assert_accepted("ip_intersect");
}

/// int1 and int2 both permit URI host `example.com`; leaf SAN URI
/// `https://example.com/x`. `matches_uri("example.com", "example.com")`
/// returns false (no "://"), so the intersection of two identical URI
/// constraints is empty. OpenSSL accepts.
#[test]
fn review_nc_uri_permitted_intersection_wrongly_empty() {
    assert_accepted("uri_intersect");
}

/// int1 permits rfc822 `.example.com`, int2 permits rfc822 `host.example.com`;
/// leaf `a@host.example.com` is inside both. `matches_rfc822_name` treats a
/// host constraint used as a "name" as a malformed mailbox (no '@'), so the
/// intersection is empty. OpenSSL accepts.
#[test]
fn review_nc_rfc822_permitted_intersection_wrongly_empty() {
    assert_accepted("rfc822_intersect");
}

// ------------------------------------------------------- fix boundaries

/// SmtpUTF8Mailbox inside the rfc822 permitted subtree (`ü@example.com`) is
/// accepted: RFC 8398 §6 processing, not blanket rejection.
#[test]
fn review_nc_fix_smtputf8mailbox_inside_permitted_accepted() {
    assert_accepted("smtputf8_ok");
}

/// SmtpUTF8Mailbox `ü@evil.com` is caught by an excluded rfc822 `evil.com`.
#[test]
fn review_nc_fix_smtputf8mailbox_excluded() {
    assert_rejected("smtputf8_excluded");
}

/// SmtpUTF8Mailbox with a U-label domain cannot be compared without IDNA
/// (pkix-path is no_std, no IDNA tables), so it fails closed when rfc822
/// constraints are in effect.
#[test]
fn review_nc_fix_smtputf8mailbox_ulabel_domain_fails_closed() {
    assert_rejected("smtputf8_idn_domain");
}

/// An otherName SAN is fine when no otherName constraint is in effect.
#[test]
fn review_nc_fix_othername_without_othername_constraint_accepted() {
    assert_accepted("othername_unconstrained");
}

/// Userinfo, port, and '@' in path/query/fragment: host is `good.com`.
/// (OpenSSL 3.0 rejects this: it does not strip userinfo.)
#[test]
fn review_nc_fix_uri_userinfo_port_and_at_in_path_accepted() {
    assert_accepted("uri_userinfo_ok");
}

/// IPv6-literal URI host under a URI constraint must be rejected.
#[test]
fn review_nc_fix_uri_ipv6_literal_host_rejected() {
    assert_rejected("uri_ipv6_host");
}

/// URI host `evil.com.` is normalized like a dNSName and caught by `evil.com`.
#[test]
fn review_nc_fix_uri_trailing_dot_host_excluded() {
    assert_rejected("uri_trailing_dot");
}

/// Trailing-dot normalization also applies to permitted subtrees.
#[test]
fn review_nc_fix_dns_trailing_dot_permitted_accepted() {
    assert_accepted("dns_trailing_dot_permitted");
}

/// Wildcard with trailing dot (`*.evil.com.`) is caught by excluded `evil.com`.
#[test]
fn review_nc_fix_dns_wildcard_trailing_dot_excluded() {
    assert_rejected("dns_wildcard_trailing_dot");
}

/// Quoted local-part with '@' under a permitted domain: the mailbox domain
/// is `good.com` (text after the last '@').
#[test]
fn review_nc_fix_rfc822_quoted_local_part_permitted_accepted() {
    assert_accepted("rfc822_quoted_at_ok");
}

/// dNSName `example.com` ∩ `.example.com` = `.example.com`; `www.example.com`
/// is inside.
#[test]
fn review_nc_fix_dns_intersection_with_leading_dot() {
    assert_accepted("dns_dot_intersect");
}

/// 10.0.0.0/8 ∩ 10.1.0.0/16: 10.2.0.1 is outside the narrower range.
#[test]
fn review_nc_fix_ip_intersection_narrows_out() {
    assert_rejected("ip_intersect_narrow_out");
}

/// 10.0.0.0/8 ∩ 10.1.0.0/16: 10.1.9.9 is inside.
#[test]
fn review_nc_fix_ip_intersection_narrows_in() {
    assert_accepted("ip_intersect_narrow_in");
}

/// Disjoint URI hosts intersect to the empty set.
#[test]
fn review_nc_fix_uri_disjoint_intersection_empty() {
    assert_rejected("uri_intersect_disjoint");
}

/// `.example.com` ∩ mailbox `alice@host.example.com` = that mailbox only.
#[test]
fn review_nc_fix_rfc822_intersection_to_single_mailbox() {
    assert_rejected("rfc822_intersect_mailbox");
}
