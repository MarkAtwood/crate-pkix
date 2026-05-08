//! PKITS §4.5 Verifying Paths with Self-Issued Certificates — `pkix-path` subset.
//!
//! All cert names and expected outcomes come from the NIST PKITS `vectors.json`,
//! cross-referenced with the PKITS specification §4.5 narrative.
//! Oracle: NIST PKITS (SP 800-89) §4.5.
//!
//! # Which §4.5 cases live here
//!
//! PKITS §4.5 contains 8 test cases. Five exercise structural path validation and
//! live in this file:
//!
//! - 4.5.1, 4.5.3, 4.5.4, 4.5.6 — PASS. Exercise self-issued-cert exemptions in
//!   RFC 5280 §6.1: §6.1.4(h) (counter-decrement skip on self-issued) and
//!   §6.1.4(m) (`pathLenConstraint` counts only non-self-issued certs).
//! - 4.5.8 — FAIL. The EE was signed by the self-issued CRL-signing cert
//!   (verified via X.509 `AuthorityKeyIdentifier`). That cert lacks
//!   `BasicConstraints`/`keyCertSign` and so cannot legitimately issue an EE;
//!   §6.1.4(k) rejects it with `Error::NotCA`.
//!
//! Three (4.5.2, 4.5.5, 4.5.7) fail because the EE is revoked on a CRL signed
//! by a self-issued cert. `pkix-path` is `no_std` and does not perform
//! revocation; those FAIL cases would *wrongly* pass here. They live in
//! `pkix-revocation/tests/pkits_4_5.rs` instead.
//!
//! # Regression role
//!
//! These tests are the regression-protective baseline for the planned `chain_walk`
//! decomposition. The intermediate-basic-constraints (pathLen) and policy-tree
//! (counter) helpers must continue to pass these tests after refactor.

#[path = "pkits_helper.rs"]
mod pkits_helper;

use pkits_helper::{pkits_validate, PKITS_NOW};

// ---------------------------------------------------------------------------
// §4.5 Verifying Paths with Self-Issued Certificates — PASS subset
// ---------------------------------------------------------------------------

/// §4.5.1 Valid Basic Self-Issued Old With New Test1.
///
/// Chain (leaf → root):
/// `Test1EE` → `BasicSelfIssuedNewKeyOldWithNewCACert` → `BasicSelfIssuedNewKeyCACert` → TrustAnchor.
///
/// Both `NewKeyCACert` and `OldWithNewCACert` carry the same subject DN
/// ("Basic Self-Issued New Key CA"). `OldWithNewCACert` is self-issued
/// (subject == issuer) and binds the OLD CA key (its SPKI) under a signature
/// from the NEW CA key. The EE is signed by the OLD key, so the validator
/// must walk: anchor → NEW key (from `NewKeyCACert.SPKI`) → OLD key
/// (from `OldWithNewCACert.SPKI`) → EE signature.
///
/// Exercises RFC 5280 §6.1.4(m): `pathLenConstraint` counts only non-self-issued
/// certs. Without the §6.1.4(m) exemption a path-length-constrained NewKeyCACert
/// would reject the chain.
///
/// Oracle: PKITS §4.5.1 MUST validate.
#[test]
fn pkits_4_5_1_valid_basic_self_issued_old_with_new() {
    let result = pkits_validate(
        &[
            "ValidBasicSelfIssuedOldWithNewTest1EE",
            "BasicSelfIssuedNewKeyOldWithNewCACert",
            "BasicSelfIssuedNewKeyCACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.5.1 must validate");
}

/// §4.5.3 Valid Basic Self-Issued New With Old Test3.
///
/// Chain (leaf → root):
/// `Test3EE` → `BasicSelfIssuedOldKeyNewWithOldCACert` → `BasicSelfIssuedOldKeyCACert` → TrustAnchor.
///
/// Mirror of §4.5.1 with the key-rollover orientation reversed.
/// `NewWithOldCACert` is self-issued and binds the NEW CA key under a signature
/// from the OLD CA key. The EE is signed by the NEW key. Validator walk:
/// anchor → OLD key (from `OldKeyCACert.SPKI`) → NEW key
/// (from `NewWithOldCACert.SPKI`) → EE signature.
///
/// Same §6.1.4(m) self-issued path-length exemption applies.
///
/// Oracle: PKITS §4.5.3 MUST validate.
#[test]
fn pkits_4_5_3_valid_basic_self_issued_new_with_old_test3() {
    let result = pkits_validate(
        &[
            "ValidBasicSelfIssuedNewWithOldTest3EE",
            "BasicSelfIssuedOldKeyNewWithOldCACert",
            "BasicSelfIssuedOldKeyCACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.5.3 must validate");
}

/// §4.5.4 Valid Basic Self-Issued New With Old Test4.
///
/// Chain (leaf → root): `Test4EE` → `BasicSelfIssuedOldKeyCACert` → TrustAnchor.
///
/// Test4EE's `AuthorityKeyIdentifier` matches `OldKeyCACert.SKI`, not
/// `NewWithOldCACert.SKI`: Test4EE is signed by the OLD CA key directly,
/// bypassing the self-issued rollover bridge that §4.5.3's Test3EE goes
/// through. The PKITS bundle (`vectors.json` `CertPath`) lists both
/// `OldKeyCACert` and `NewWithOldCACert` because a path builder must select
/// the correct issuer when multiple bundle certs share the same subject DN
/// ("Basic Self-Issued Old Key CA"). pkix-path is positional; the caller
/// pre-orders the chain to the issuer that actually signed the EE.
///
/// Including the self-issued bridge in the chain would fail with
/// `SignatureInvalid { index: 0 }` because the EE signature would be checked
/// against the NEW key (the bridge's SPKI), not the OLD key that actually
/// signed it.
///
/// Oracle: PKITS §4.5.4 MUST validate.
#[test]
fn pkits_4_5_4_valid_basic_self_issued_new_with_old_test4() {
    let result = pkits_validate(
        &[
            "ValidBasicSelfIssuedNewWithOldTest4EE",
            "BasicSelfIssuedOldKeyCACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.5.4 must validate");
}

/// §4.5.6 Valid Basic Self-Issued CRL Signing Key Test6.
///
/// Chain (leaf → root): `Test6EE` → `BasicSelfIssuedCRLSigningKeyCACert` → TrustAnchor.
///
/// PKITS §4.5.6 splits the CA's `keyCertSign` and `cRLSign` roles across two
/// certificates with identical subject DNs ("Basic Self-Issued CRL Signing Key
/// CA"): the canonical CA cert holds `keyCertSign` and signs the EE; a separate
/// self-issued cert (`BasicSelfIssuedCRLSigningKeyCRLCert`) holds only
/// `cRLSign` and exists solely to sign CRLs. The PKITS bundle for this case
/// includes the CRL-signing cert in `CertPath`, which is meaningful for path
/// building (RFC 4158) and revocation but irrelevant to RFC 5280 §6.1 path
/// validation: including the `cRLSign`-only cert in the chain would fail
/// §6.1.4(n) (`keyCertSign` required for any cert that issues another cert).
///
/// `pkix-path` is positional and does not perform RFC 4158 path building (see
/// AGENTS.md and `pkix-path/README.md`); the caller pre-orders the chain to
/// include only certificates required for §6.1 validation. The full bundle —
/// including the self-issued CRL-signing cert — is exercised in the
/// `pkix-revocation` companion test (`pkix-revocation/tests/pkits_4_5.rs`),
/// where the CRL-signing cert is required to verify the CRL signature.
///
/// Oracle: PKITS §4.5.6 MUST validate.
#[test]
fn pkits_4_5_6_valid_basic_self_issued_crl_signing_key_test6() {
    let result = pkits_validate(
        &[
            "ValidBasicSelfIssuedCRLSigningKeyTest6EE",
            "BasicSelfIssuedCRLSigningKeyCACert",
        ],
        PKITS_NOW,
    );
    result.expect("§4.5.6 must validate");
}

/// §4.5.8 Invalid Basic Self-Issued CRL Signing Key Test8.
///
/// Chain (leaf → root): `Test8EE` → `BasicSelfIssuedCRLSigningKeyCRLCert` →
/// `BasicSelfIssuedCRLSigningKeyCACert` → TrustAnchor.
///
/// PKITS §4.5.8 narrative: "The end entity's certificate was signed using the CRL
/// signing key." Test8EE's `AuthorityKeyIdentifier` matches `CRLCert.SKI` (the
/// self-issued cRL-signing cert), confirming the CA used the CRL-signing key —
/// not the certificate-signing key — to sign the EE.
///
/// `CRLCert` has no `BasicConstraints` extension (it's only meant to sign CRLs,
/// not certificates). When chain validation reaches `CRLCert` as an intermediate,
/// RFC 5280 §6.1.4(k) rejects it: a non-self-signed cert acting as an issuer
/// must have `BasicConstraints` with `cA=TRUE`. The validator returns
/// `Error::NotCA`. (`KeyUsageMissing` for keyCertSign would also be a valid
/// outcome under §6.1.4(n); pkix-path checks BC first.)
///
/// Oracle: PKITS §4.5.8 MUST NOT validate (the EE's issuer is not a valid CA).
#[test]
fn pkits_4_5_8_invalid_basic_self_issued_crl_signing_key_test8() {
    let result = pkits_validate(
        &[
            "InvalidBasicSelfIssuedCRLSigningKeyTest8EE",
            "BasicSelfIssuedCRLSigningKeyCRLCert",
            "BasicSelfIssuedCRLSigningKeyCACert",
        ],
        PKITS_NOW,
    );
    assert!(
        matches!(
            result,
            Err(pkix_path::Error::NotCA { .. } | pkix_path::Error::KeyUsageMissing { .. })
        ),
        "§4.5.8 must fail with NotCA or KeyUsageMissing, got: {result:?}"
    );
}
