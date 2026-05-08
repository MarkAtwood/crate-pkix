//! PKITS §4.5 Verifying Paths with Self-Issued Certificates — `pkix-path` PASS subset.
//!
//! All cert names and expected outcomes come from the NIST PKITS `vectors.json`.
//! Oracle: NIST PKITS (SP 800-89) §4.5.
//!
//! # Why only the PASS cases live here
//!
//! PKITS §4.5 contains 8 test cases. The 4 PASS cases (4.5.1, 4.5.3, 4.5.4, 4.5.6)
//! exercise self-issued-cert exemptions in RFC 5280 §6.1 path validation:
//!
//! - §6.1.4(h) — `explicit_policy` / `policy_mapping` / `inhibit_any_policy` counter
//!   decrements skip self-issued certs.
//! - §6.1.4(m) — `pathLenConstraint` counts only non-self-issued certs.
//!
//! The 4 FAIL cases (4.5.2, 4.5.5, 4.5.7, 4.5.8) all fail because the EE is revoked
//! on a self-issued-signed CRL. `pkix-path` is `no_std` and does not perform
//! revocation; the FAIL cases would *wrongly* pass here. They live in
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
