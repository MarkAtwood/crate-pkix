//! What each profile says it is.
//!
//! `Profile::id`, `version` and `policy_oids` are the metadata a caller
//! reads to decide which profile it has, to record which one validated a
//! chain, and to discover what certificate policies the profile requires.
//! Nothing in this crate consumes them -- `policy()` is what validation
//! uses -- so none of the eight implementations was exercised by any
//! test, and all three accessors fail quietly: an `id` or `version` can
//! return the wrong string and a `policy_oids` can return nothing, with
//! no error anywhere.
//!
//! An audit log naming the wrong profile, or two profiles that cannot be
//! told apart, is the failure this covers.
//!
//! The expected strings are written out here rather than read from the
//! code under test, so this is a statement about what the values are and
//! not merely that they are self-consistent. `id` is a stable
//! identifier -- reverse-domain style, standards body plus spec scope --
//! so changing one is an API break and belongs in a deliberate edit to
//! this table.

use pkix_profiles::{
    BasicCodeSigningProfile, BasicOcspResponderProfile, BasicSmimeProfile, BasicSmtpMtaProfile,
    BasicTimeStampingProfile, BasicTlsClientProfile, BasicTlsProfile, Profile, Rfc5280Profile,
};

/// Every profile, with the identity it reports.
fn expected() -> Vec<(&'static str, &'static str, Box<dyn Profile>)> {
    vec![
        (
            "ietf.rfc5280",
            "RFC 5280",
            Box::new(Rfc5280Profile) as Box<dyn Profile>,
        ),
        (
            "ietf.tls-basic",
            "RFC 5280 + RFC 6125",
            Box::new(BasicTlsProfile),
        ),
        (
            "ietf.smtp-mta-dane",
            "RFC 5280 + RFC 7672 + RFC 7671",
            Box::new(BasicSmtpMtaProfile),
        ),
        (
            "ietf.tls-client-basic",
            "RFC 5280 §4.2.1.12",
            Box::new(BasicTlsClientProfile),
        ),
        ("ietf.smime-basic", "RFC 8551", Box::new(BasicSmimeProfile)),
        (
            "ietf.code-signing-basic",
            "RFC 5280 §4.2.1.12",
            Box::new(BasicCodeSigningProfile),
        ),
        (
            "ietf.time-stamping-basic",
            "RFC 3161 §2.3",
            Box::new(BasicTimeStampingProfile),
        ),
        (
            "ietf.ocsp-responder-basic",
            "RFC 6960 §4.2.2.2",
            Box::new(BasicOcspResponderProfile),
        ),
    ]
}

/// Each profile reports the id and version this table names.
#[test]
fn every_profile_reports_its_own_identity() {
    for (id, version, profile) in expected() {
        assert_eq!(profile.id(), id, "id of the profile named {id}");
        assert_eq!(profile.version(), version, "version of {id}");
    }
}

/// And no two profiles share an id.
///
/// The id is what distinguishes them to a caller. Two profiles reporting
/// the same one cannot be told apart, which matters most where it is
/// least visible: a log line saying which profile accepted a chain.
#[test]
fn no_two_profiles_share_an_id() {
    let table = expected();
    for (i, (id_a, _, a)) in table.iter().enumerate() {
        for (id_b, _, b) in table.iter().skip(i + 1) {
            assert_ne!(
                a.id(),
                b.id(),
                "{id_a} and {id_b} must not report the same id"
            );
        }
    }
}

/// None of these profiles requires a certificate policy OID.
///
/// They are structural profiles -- key usage, extended key usage, name
/// forms -- and deliberately name no policy. Asserting the empty set is
/// not asserting nothing: `policy_oids` feeds
/// `ValidationPolicy::required_leaf_policy_oids`, so a profile that
/// started returning OIDs here would refuse every certificate that does
/// not assert them, and one of these returning a stale list after an
/// edit would do so silently.
#[test]
fn these_profiles_require_no_policy_oids() {
    for (id, _, profile) in expected() {
        assert!(
            profile.policy_oids().is_empty(),
            "{id} names no certificate policy; got {:?}",
            profile.policy_oids()
        );
    }
}
