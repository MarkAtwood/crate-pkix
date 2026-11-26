//! `PkixServerCertVerifier` driven through rustls's own trait.
//!
//! The point of these tests is that they call
//! [`ServerCertVerifier::verify_server_cert`] rather than
//! `pkix_chain::verify_tls_server` directly: what matters here is the
//! adapter — the DER conversion, the name conversion, the clock, and
//! the error mapping — not the path validation underneath, which has
//! its own suites.
//!
//! Fixtures are pkix-chain's RFC 6125 corpus, read by relative path so
//! there is one copy and it cannot drift. See
//! `pkix-chain/tests/fixtures/gen.py`.

use rustls::client::danger::ServerCertVerifier;
use rustls::{CertificateError, Error as RustlsError};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

use pkix_chain::TrustAnchor;
use pkix_rustls::PkixServerCertVerifier;

/// A timestamp inside every fixture's validity window (2026-06-01 UTC),
/// the same constant pkix-chain's corpus uses.
const NOW: u64 = 1_780_272_000;

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../pkix-chain/tests/fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn parse(der: &[u8]) -> x509_cert::Certificate {
    use x509_cert::der::Decode as _;
    x509_cert::Certificate::from_der(der).expect("fixture parses")
}

fn verifier() -> PkixServerCertVerifier {
    // No CryptoProvider: the chain and the handshake signatures both go
    // through pkix-path, so rustls's crypto is not consulted here.
    PkixServerCertVerifier::new(vec![TrustAnchor::from_cert(parse(&fixture("root.der")))])
}

fn verify(v: &PkixServerCertVerifier, leaf: &str, name: &str, now: u64) -> Result<(), RustlsError> {
    let leaf_der = fixture(leaf);
    let name = ServerName::try_from(name)
        .expect("test name parses as a rustls ServerName")
        .to_owned();
    v.verify_server_cert(
        &CertificateDer::from(leaf_der.as_slice()),
        &[],
        &name,
        &[],
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(now)),
    )
    .map(|_| ())
}

/// The whole point: a chain rustls would have handed to rustls-webpki
/// is accepted by PKIX instead, through rustls's own trait.
#[test]
fn a_good_chain_verifies_through_the_rustls_trait() {
    verify(&verifier(), "host-exact-foo.der", "foo.example.com", NOW)
        .expect("the corpus's exact-match leaf is valid for its own name");
}

/// A name the certificate does not present must come back as rustls's
/// name error, not as a generic failure — this is the error an
/// application shows the user most often.
#[test]
fn a_name_mismatch_maps_to_not_valid_for_name() {
    let err = verify(&verifier(), "host-exact-foo.der", "bar.example.com", NOW)
        .expect_err("the leaf is not valid for bar.example.com");
    assert!(
        matches!(
            err,
            RustlsError::InvalidCertificate(CertificateError::NotValidForName)
        ),
        "expected NotValidForName, got {err:?}"
    );
}

/// With no trust anchor there is no path, which is rustls's
/// `UnknownIssuer` — distinct from the name and signature failures, and
/// the one that tells an operator their trust store is wrong.
#[test]
fn an_untrusted_chain_maps_to_unknown_issuer() {
    let v = PkixServerCertVerifier::new(Vec::new());
    let err = verify(&v, "host-exact-foo.der", "foo.example.com", NOW)
        .expect_err("no anchors means no path");
    assert!(
        matches!(
            err,
            RustlsError::InvalidCertificate(CertificateError::UnknownIssuer)
        ),
        "expected UnknownIssuer, got {err:?}"
    );
}

/// `pkix-path` has one error for both ends of the validity window while
/// rustls has two, so the adapter re-examines the chain to say which.
/// A clock far past the fixtures' window must read as `Expired`.
#[test]
fn a_clock_after_the_window_maps_to_expired() {
    // 2099-01-01. The fixtures' notAfter is 2050-01-01.
    let err = verify(
        &verifier(),
        "host-exact-foo.der",
        "foo.example.com",
        4_070_908_800,
    )
    .expect_err("expired");
    assert!(
        matches!(
            err,
            RustlsError::InvalidCertificate(CertificateError::Expired)
        ),
        "expected Expired, got {err:?}"
    );
}

/// And a clock before it must read as `NotValidYet`. The fixtures run
/// from 2000-01-01, and that instant is *inside* the window, so this
/// has to reach back further than the obvious choice. Collapsing these
/// two into one answer would tell half of all callers the wrong thing:
/// an expired certificate needs renewing, a not-yet-valid one is almost
/// always a wrong clock.
#[test]
fn a_clock_before_the_window_maps_to_not_valid_yet() {
    // 1990-01-01. The fixtures' notBefore is 2000-01-01, and passing
    // that exact second would be inside the window, not before it.
    let err = verify(
        &verifier(),
        "host-exact-foo.der",
        "foo.example.com",
        631_152_000,
    )
    .expect_err("not yet valid");
    assert!(
        matches!(
            err,
            RustlsError::InvalidCertificate(CertificateError::NotValidYet)
        ),
        "expected NotValidYet, got {err:?}"
    );
}

/// Garbage in the DER position must be a certificate encoding error and
/// must not reach path validation at all.
#[test]
fn malformed_der_maps_to_bad_encoding() {
    let v = verifier();
    let name = ServerName::try_from("foo.example.com").unwrap().to_owned();
    let err = v
        .verify_server_cert(
            &CertificateDer::from(&b"not a certificate"[..]),
            &[],
            &name,
            &[],
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(NOW)),
        )
        .expect_err("not DER");
    assert!(
        matches!(
            err,
            RustlsError::InvalidCertificate(CertificateError::BadEncoding)
        ),
        "expected BadEncoding, got {err:?}"
    );
}

/// An IP literal reaches the matcher as an IP identity, not as a
/// hostname that happens to look numeric. rustls hands IPs over as a
/// different `ServerName` variant, so this exercises the other half of
/// the name conversion.
#[test]
fn an_ip_address_name_is_converted_as_an_ip() {
    let leaf = fixture("host-ipv4.der");
    let name = ServerName::try_from("192.0.2.5")
        .expect("an IP literal is a valid rustls ServerName")
        .to_owned();
    assert!(
        matches!(name, ServerName::IpAddress(_)),
        "rustls should classify this as an IP, or the test proves nothing"
    );
    verifier()
        .verify_server_cert(
            &CertificateDer::from(leaf.as_slice()),
            &[],
            &name,
            &[],
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(NOW)),
        )
        .expect("the corpus's IPv4 leaf is valid for 192.0.2.5");
}

/// An error with no rustls variant keeps its reason instead of being
/// flattened, and an application can get the original back out.
///
/// The EKU case is the handy one: the corpus has a leaf whose extended
/// key usage is code signing, which the default TLS profile refuses.
#[test]
fn an_unmappable_error_survives_inside_other() {
    let err = verify(
        &verifier(),
        "host-exact-foo-codesigning-eku.der",
        "foo.example.com",
        NOW,
    )
    .expect_err("a code-signing EKU is not valid for TLS server auth");

    let RustlsError::InvalidCertificate(inner) = &err else {
        panic!("expected a certificate error, got {err:?}");
    };
    match inner {
        // Either rustls has a variant for it, in which case it must be
        // the purpose one...
        CertificateError::InvalidPurpose => {}
        // ...or it does not, and then the original must still be
        // reachable rather than flattened away.
        CertificateError::Other(other) => {
            let recovered = other
                .0
                .downcast_ref::<pkix_chain::Error>()
                .expect("the pkix error must survive inside Other, not be flattened");
            // Printing it is the thing an application does with it.
            assert!(!recovered.to_string().is_empty());
        }
        unexpected => panic!("expected InvalidPurpose or Other, got {unexpected:?}"),
    }
}

/// The schemes advertised to the peer must be exactly the ones this
/// crate can verify.
///
/// This used to echo the `CryptoProvider`'s list, which was right while
/// the handshake signatures were delegated to it. They are not any
/// more, so the provider's opinion is no longer the relevant one —
/// advertising a scheme the provider supports but this crate does not
/// would make a server choose it and then fail.
///
/// The lists genuinely differ: `ring` does not offer
/// `ECDSA_NISTP521_SHA512` and `pkix-path` does, so ours is not a
/// subset of the provider's and cannot be checked against it.
#[test]
fn advertised_schemes_are_the_ones_this_crate_verifies() {
    let advertised = PkixServerCertVerifier::new(Vec::new()).supported_verify_schemes();
    assert_eq!(advertised, pkix_rustls::handshake::SUPPORTED_SCHEMES);
    assert!(!advertised.is_empty());

    // The safety property: nothing advertised may be a scheme the
    // handshake code refuses. `pkix-rustls`'s own unit tests check the
    // converse — that nothing implemented is left unadvertised.
    for scheme in &advertised {
        assert!(
            !matches!(
                scheme,
                rustls::SignatureScheme::RSA_PKCS1_SHA1
                    | rustls::SignatureScheme::ECDSA_SHA1_Legacy
                    | rustls::SignatureScheme::ED448
            ),
            "{scheme:?} must not be advertised"
        );
    }
}
