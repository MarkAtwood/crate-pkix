//! `tbs_certificate_der` and `cert_is_ca`: public, and called by nothing
//! inside this crate.
//!
//! Both exist for consumers -- `pkix-revocation` re-encodes a TBS to check
//! a CRL signer, `pkix-chain` asks whether a pool candidate may act as a
//! CA -- so a sweep scoped to this crate cannot reach either by
//! construction, and every mutant in both survived. A body replaced by
//! `Ok(vec![])` or `Ok(true)` is invisible here however thorough the rest
//! of the suite is.
//!
//! The fixtures are this crate's existing self-signed and chain
//! certificates; neither helper needs a shape they do not already have.

use pkix_path::{cert_is_ca, tbs_certificate_der, DefaultVerifier, SignatureVerifier};
use spki::der::referenced::OwnedToRef as _;
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

fn load(name: &str) -> Certificate {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let der = std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
    Certificate::from_der(&der).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

/// The bytes `tbs_certificate_der` returns are the ones the issuer signed.
///
/// A self-signed certificate is its own oracle for this: the key in it
/// verifies the signature on it, and only over the right message. Any other
/// assertion -- that the result is non-empty, that it starts with a
/// SEQUENCE tag -- would pass for bytes that are not the signed ones, which
/// is the failure that matters, because a caller uses this to decide
/// whether a signature is valid.
///
/// Three algorithms, so the test is about the encoding and not about one
/// verifier backend.
#[test]
fn the_reencoded_tbs_is_what_the_signature_covers() {
    for name in [
        "ec-p256-sha256.der",
        "ec-p384-sha384.der",
        "rsa-pkcs1v15-sha256.der",
        "rsa-pkcs1v15-sha512.der",
    ] {
        let cert = load(name);
        assert_eq!(
            cert.tbs_certificate().subject(),
            cert.tbs_certificate().issuer(),
            "{name} must be self-signed for this to be a closed check"
        );

        let tbs = tbs_certificate_der(&cert).unwrap_or_else(|e| panic!("{name}: {e}"));
        DefaultVerifier
            .verify_signature(
                cert.signature_algorithm().owned_to_ref(),
                cert.tbs_certificate()
                    .subject_public_key_info()
                    .owned_to_ref(),
                &tbs,
                cert.signature().raw_bytes(),
            )
            .unwrap_or_else(|e| panic!("{name}: the re-encoded TBS is not what was signed: {e:?}"));
    }
}

/// `cert_is_ca` answers from `basicConstraints`, and answers both ways.
///
/// Returning a constant is the whole risk in a predicate like this: `true`
/// lets an end-entity certificate act as an issuer, `false` stops every CA
/// from acting as one. Both directions are asserted on the same chain, so
/// neither can be satisfied by a fixture choice.
#[test]
fn cert_is_ca_distinguishes_a_ca_from_an_end_entity() {
    assert!(
        cert_is_ca(&load("gry-root.der")).expect("basicConstraints decodes"),
        "a root with cA=TRUE is a CA"
    );
    assert!(
        cert_is_ca(&load("gry-int.der")).expect("basicConstraints decodes"),
        "an intermediate with cA=TRUE is a CA"
    );
    assert!(
        !cert_is_ca(&load("gry-leaf.der")).expect("basicConstraints decodes"),
        "an end-entity certificate is not a CA"
    );
}

/// An undecodable `basicConstraints` is an error, not a `false`.
///
/// Answering `false` would read as "this is an end-entity certificate",
/// which is a claim about a certificate nothing can parse. The caller has
/// to be able to tell the two apart: one is a certificate that may not
/// issue, the other is a certificate that cannot be understood.
///
/// Only the intermediate of the `corrupt-bc-*` trio carries the broken
/// extension -- its value is `0xff 0xff` -- and the other two are there as
/// its chain. They serve here as the controls: the same call on them
/// answers rather than failing, so the error is attributable to the
/// extension and not to the helper refusing whatever it is handed.
#[test]
fn an_undecodable_basic_constraints_is_an_error() {
    let r = cert_is_ca(&load("corrupt-bc-int.der"));
    assert!(
        r.is_err(),
        "corrupt-bc-int.der's basicConstraints value is 0xff 0xff, got: {r:?}"
    );

    for name in ["corrupt-bc-root.der", "corrupt-bc-leaf.der"] {
        cert_is_ca(&load(name))
            .unwrap_or_else(|e| panic!("{name}'s basicConstraints is intact: {e}"));
    }
}
