//! The README's call shapes, type-checked.
//!
//! Every example in `README.md` is an illustrative fragment: it refers to a
//! `chain`, `anchors` and `policy` it never builds, so the blocks cannot be
//! compiled where they stand. `#[doc = include_str!("../README.md")]` was
//! the obvious guard and does not work for that reason — it would force
//! setup boilerplate into a document whose job is to show the shape of a
//! call, and `#`-hidden doctest lines are not hidden on crates.io or
//! GitHub, where this README is mostly read.
//!
//! So the guard lives here instead. Each function below mirrors one
//! README example argument for argument, against the same unit structs the
//! README names. Nothing is executed and no assertion is made: the point is
//! that it compiles. Change a wrapper's parameter list without updating the
//! README and this file stops building.
//!
//! The drift this catches already happened once. Five wrappers gained
//! `verifier` and `aia` parameters, and the README kept passing a single
//! `&NoRevocation` — which then sat in the `verifier` position, so the
//! examples were both wrong in arity and misleading about which argument
//! was which.
//!
//! Keep the calls here byte-identical to the README's, including argument
//! order and the choice of `DefaultVerifier` / `NoRevocation` /
//! `NoAiaFetcher`, or the guard stops matching what it guards.

#![allow(dead_code, unused_variables)]

use pkix_chain::{
    verify_chain, verify_chain_default, verify_code_signer, verify_smime_signer,
    verify_time_stamper, verify_tls_client_dns, verify_tls_server, CrlChecker, DefaultVerifier,
    MailboxName, NoAiaFetcher, NoRevocation, OcspChecker, ServerName, TrustAnchor,
    ValidationPolicy,
};
use pkix_profiles::{
    BasicCodeSigningProfile, BasicSmimeProfile, BasicTimeStampingProfile, BasicTlsProfile,
    Rfc5280Profile,
};
use x509_cert::Certificate;

type Chain = Vec<Certificate>;
type Anchors = Vec<TrustAnchor>;

fn unix_now() -> u64 {
    0
}

/// README: "Quick start".
fn quick_start(chain: Chain, anchors: Anchors, policy: ValidationPolicy) -> pkix_chain::Result<()> {
    let result = verify_chain_default(&chain, &anchors, &policy, &NoRevocation)?;
    Ok(())
}

/// README: "With CRL revocation" — `CrlChecker::new` returns a `Result`, so
/// the `?` is load-bearing: `&Result<CrlChecker>` is not a
/// `RevocationChecker`.
fn with_crl(
    chain: Chain,
    anchors: Anchors,
    policy: ValidationPolicy,
    crl_der: Vec<u8>,
) -> pkix_chain::Result<()> {
    let checker = CrlChecker::new(crl_der, unix_now(), DefaultVerifier)?;
    let result = verify_chain_default(&chain, &anchors, &policy, &checker)?;
    Ok(())
}

/// README: "With delta CRL".
fn with_delta_crl(
    chain: Chain,
    anchors: Anchors,
    policy: ValidationPolicy,
    base_crl_der: Vec<u8>,
    delta_crl_der: Vec<u8>,
) -> pkix_chain::Result<()> {
    let checker = CrlChecker::with_delta(base_crl_der, delta_crl_der, unix_now(), DefaultVerifier)?;
    let result = verify_chain_default(&chain, &anchors, &policy, &checker)?;
    Ok(())
}

/// README: "With OCSP revocation" — same `Result` point as the CRL case.
fn with_ocsp(
    chain: Chain,
    anchors: Anchors,
    policy: ValidationPolicy,
    ocsp_response_der: Vec<u8>,
) -> pkix_chain::Result<()> {
    let checker = OcspChecker::new(ocsp_response_der, unix_now(), DefaultVerifier)?;
    let result = verify_chain_default(&chain, &anchors, &policy, &checker)?;
    Ok(())
}

/// README: "With a custom signature backend".
fn custom_backend(
    chain: Chain,
    anchors: Anchors,
    policy: ValidationPolicy,
) -> pkix_chain::Result<()> {
    let my_verifier = DefaultVerifier;
    let result = verify_chain(
        &chain,
        &anchors,
        &policy,
        &my_verifier,
        &NoRevocation,
        &NoAiaFetcher,
    )?;
    Ok(())
}

/// README: "TLS server identity".
fn tls_server(chain: Chain, anchors: Anchors) -> pkix_chain::Result<()> {
    let name = ServerName::dns_name("www.example.com")?;
    let result = verify_tls_server(
        &chain,
        &anchors,
        &name,
        &BasicTlsProfile,
        unix_now(),
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )?;
    Ok(())
}

/// README: "TLS client authentication identity".
fn tls_client(chain: Chain, anchors: Anchors) -> pkix_chain::Result<()> {
    let name = ServerName::dns_name("client.example.com")?;
    let result = verify_tls_client_dns(
        &chain,
        &anchors,
        Some(&name),
        &Rfc5280Profile,
        unix_now(),
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )?;
    Ok(())
}

/// README: "S/MIME signer identity".
fn smime_signer(chain: Chain, anchors: Anchors) -> pkix_chain::Result<()> {
    let mailbox = MailboxName::parse("alice@example.com")?;
    let result = verify_smime_signer(
        &chain,
        &anchors,
        &mailbox,
        &BasicSmimeProfile,
        unix_now(),
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )?;
    Ok(())
}

/// README: "Code signing".
fn code_signer(chain: Chain, anchors: Anchors) -> pkix_chain::Result<()> {
    let result = verify_code_signer(
        &chain,
        &anchors,
        &BasicCodeSigningProfile,
        unix_now(),
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )?;
    Ok(())
}

/// README: "Time stamping".
fn time_stamper(chain: Chain, anchors: Anchors) -> pkix_chain::Result<()> {
    let result = verify_time_stamper(
        &chain,
        &anchors,
        &BasicTimeStampingProfile,
        unix_now(),
        &DefaultVerifier,
        &NoRevocation,
        &NoAiaFetcher,
    )?;
    Ok(())
}

/// A test target so the file is run as well as compiled; compiling is the
/// actual assertion.
#[test]
fn the_readme_call_shapes_compile() {}

/// Every `verify_*` call in the README appears verbatim in this file.
///
/// Compiling only guards one direction: it catches a wrapper whose
/// parameters changed, because the calls above would stop building. It does
/// not catch the README drifting away from the calls above, which is the
/// direction that actually broke before — the source was fine and the
/// document was stale. Reading the README back and requiring each call to
/// appear here closes that, so the guard cannot silently stop describing
/// what it guards.
///
/// Comparison is on the argument sequence with whitespace collapsed, since
/// the README wraps for width and `rustfmt` wraps for its own reasons.
#[test]
fn every_readme_call_is_mirrored_here() {
    const README: &str = include_str!("../README.md");
    const MIRROR: &str = include_str!("readme_examples.rs");

    fn calls(src: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for (idx, _) in src.match_indices("verify_") {
            let tail = &src[idx..];
            let Some(open) = tail.find('(') else { continue };
            let name = &tail[..open];
            // A call, not a prose mention or an import list.
            if !name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            {
                continue;
            }
            // Balance parentheses to find the end of the argument list.
            let bytes = tail.as_bytes();
            let mut depth = 0usize;
            let mut end = None;
            for (i, b) in bytes.iter().enumerate().skip(open) {
                match b {
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(i);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let Some(end) = end else { continue };
            let args: String = tail[open + 1..end]
                .split_whitespace()
                .collect::<Vec<_>>()
                .join("")
                .trim_end_matches(',')
                .to_string();
            // Skip zero-argument mentions such as `unix_now()`.
            if args.is_empty() {
                continue;
            }
            out.push((name.to_string(), args));
        }
        out
    }

    let readme_calls = calls(README);
    assert!(
        readme_calls.len() >= 9,
        "expected the README to still show the wrapper calls; found {}",
        readme_calls.len()
    );

    let mirrored = calls(MIRROR);
    for (name, args) in &readme_calls {
        assert!(
            mirrored.iter().any(|(n, a)| n == name && a == args),
            "README calls {name}({args}) but tests/readme_examples.rs does not. \
             Either the README drifted or this guard was not updated with it; \
             fix whichever is wrong, do not delete the assertion."
        );
    }
}
