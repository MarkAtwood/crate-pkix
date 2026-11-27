//! What `Error` and `IoFailure` say when something asks.
//!
//! Neither type's `Display` nor `Error::source` has a caller inside the
//! crate: loading returns an `Error` and rendering it is the consumer's
//! business. So none of these impls was exercised, and each fails
//! quietly in its own way -- a `Display` that writes nothing still
//! returns `Ok`, and a `source` that answers `None` still satisfies the
//! trait while breaking every chained report of the cause.
//!
//! The variants are built through the crate's public entry points
//! wherever one produces them, so the shapes here are the shapes a
//! caller actually receives.

use pkix_truststore::{from_der, from_pem, from_pem_file_with_cap, Error, IoFailure};
use std::error::Error as _;
use std::io;

/// One of every `Error` variant, with how it was obtained.
fn every_variant() -> Vec<(&'static str, Error)> {
    let io_err = from_pem_file_with_cap("tests/fixtures/does-not-exist.pem", 1024)
        .expect_err("a missing file is an i/o error");
    let pem_err =
        from_pem(b"-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n")
            .expect_err("undecodable PEM");
    let der_err = from_der(&[0x30, 0x01, 0xff]).expect_err("undecodable DER");
    let none = from_pem(b"no markers here").expect_err("no certificates");
    vec![
        ("Io", io_err),
        ("Pem", pem_err),
        ("Der", der_err),
        ("NoCertificates", none),
        (
            "MalformedAnchor",
            Error::MalformedAnchor {
                index: 2,
                source: match from_der(&[0x30, 0x01, 0xff]).expect_err("a DerError to borrow") {
                    Error::Der(e) => e,
                    other => panic!("expected Error::Der, got {other:?}"),
                },
            },
        ),
    ]
}

/// Every variant renders something, and no two render the same thing.
///
/// An `Error` whose message is empty, or shared with another variant,
/// tells a caller nothing about why a trust store failed to load --
/// which is the one thing a deployment reads when its anchors do not
/// appear.
#[test]
fn every_error_variant_renders_a_distinct_message() {
    let variants = every_variant();
    let rendered: Vec<String> = variants.iter().map(|(_, e)| format!("{e}")).collect();
    for ((name, _), text) in variants.iter().zip(&rendered) {
        assert!(!text.is_empty(), "Error::{name} renders nothing");
    }
    for (i, a) in rendered.iter().enumerate() {
        for (j, b) in rendered.iter().enumerate().skip(i + 1) {
            assert_ne!(
                a, b,
                "Error::{} and Error::{} render the same message",
                variants[i].0, variants[j].0
            );
        }
    }
}

/// Every variant but `NoCertificates` exposes the cause it wraps.
///
/// `NoCertificates` is the only one with nothing underneath it: there is
/// no inner failure, the input simply held no certificate. The rest
/// carry one, and a `source` answering `None` drops it from every
/// chained report -- the position in `MalformedAnchor` survives in the
/// message, but the DER failure that explains it lives only in the
/// wrapped value.
#[test]
fn every_variant_with_a_cause_exposes_it() {
    for (name, err) in &every_variant() {
        let expected = *name != "NoCertificates";
        assert_eq!(
            err.source().is_some(),
            expected,
            "Error::{name} source presence"
        );
    }
}

/// `IoFailure` renders its message, which is the whole of what it holds
/// besides the kind.
///
/// `Error::Io`'s own rendering interpolates it, so an `IoFailure` that
/// rendered nothing would leave "i/o error: " and no cause.
#[test]
fn an_io_failure_renders_its_message() {
    let failure = IoFailure::from_io(&io::Error::new(
        io::ErrorKind::PermissionDenied,
        "anchors.pem: permission denied",
    ));
    assert_eq!(format!("{failure}"), failure.message);
    assert!(
        failure.message.contains("permission denied"),
        "the message carries the cause; got {}",
        failure.message
    );

    let wrapped = Error::Io(failure.clone());
    assert!(
        format!("{wrapped}").contains(&failure.message),
        "Error::Io interpolates it rather than discarding it"
    );
}
