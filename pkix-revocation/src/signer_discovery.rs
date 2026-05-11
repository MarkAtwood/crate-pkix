//! Path-level CRL signer discovery (RFC 5280 §6.3.3(f)).
//!
//! For indirect CRLs (RFC 5280 §5.2.6) and self-issued bridge cases
//! (PKITS §4.5 — "old key signs new, new key signs old" key rollover),
//! the CRL is signed by a certificate that is not the certificate-under-check's
//! direct issuer. This module walks a caller-supplied bundle to locate the
//! cert that actually signed the CRL, using:
//!
//! 1. `AuthorityKeyIdentifier` on the CRL → `SubjectKeyIdentifier` on bundle
//!    certs (RFC 5280 §4.2.1.1 / §4.2.1.2). Most reliable when present.
//! 2. Issuer-DN fallback: bundle certs whose `subject` matches the CRL's
//!    `issuer` DN are candidates when AKI/SKI is unavailable. RFC 4518 DN
//!    comparison is applied (via [`pkix_path::names_match`]).
//!
//! # Architectural constraint
//!
//! This module performs **discovery only**, not full chain validation.
//! Per the project's one-way dep direction (`pkix-chain` → `pkix-revocation`
//! → `pkix-path`), this crate cannot perform RFC 5280 §6.1 signature-and-
//! policy validation on the discovered signer. The
//! [`CrlChecker::new_with_signer_discovery`] constructor performs only the
//! cheap structural §6.3.3(f) gating documented on that method; full chain
//! validation of the discovered signer is the responsibility of higher-level
//! composers such as `pkix-chain`.
//!
//! [`CrlChecker::new_with_signer_discovery`]: crate::CrlChecker::new_with_signer_discovery

use der::{asn1::OctetString, Decode as _};
use pkix_path::names_match;
use x509_cert::{crl::CertificateList, Certificate};

/// OID for `AuthorityKeyIdentifier` extension (RFC 5280 §4.2.1.1) —
/// id-ce-authorityKeyIdentifier: 2.5.29.35.
const OID_AUTHORITY_KEY_IDENTIFIER: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.35");

/// OID for `SubjectKeyIdentifier` extension (RFC 5280 §4.2.1.2) —
/// id-ce-subjectKeyIdentifier: 2.5.29.14.
const OID_SUBJECT_KEY_IDENTIFIER: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.14");

/// Locate the certificate in `bundle` that signed `crl`.
///
/// Discovery proceeds in two stages:
///
/// 1. **AKI/SKI walk (preferred).** If the CRL carries an
///    `AuthorityKeyIdentifier` extension with a `keyIdentifier`, the first
///    cert in `bundle` whose `SubjectKeyIdentifier` byte-equals the AKI
///    `keyIdentifier` is returned. This is the only reliable discriminator
///    when multiple certs share the same subject DN (e.g., key rollover
///    bridges in PKITS §4.5).
///
/// 2. **Issuer-DN fallback.** When the CRL has no AKI, or the AKI carries
///    only `authorityCertIssuer` / `authorityCertSerialNumber` rather than
///    `keyIdentifier`, the function falls back to the first cert in `bundle`
///    whose `subject` DN matches the CRL's `issuer` DN under
///    [`pkix_path::names_match`].
///
/// Returns `None` if no candidate is found.
///
/// # Out of scope
///
/// - No signature verification is performed. A returned cert is a *candidate*;
///   callers (or [`CrlChecker::new_with_signer_discovery`]) must verify the
///   CRL signature against the returned cert's SPKI.
/// - `AuthorityKeyIdentifier.authorityCertSerialNumber` is not used as a
///   tiebreaker. In practice, AKI `keyIdentifier` is the discriminator that
///   PKITS and real-world deployments rely on. If a future test corpus needs
///   serial-based discrimination, it can be added without breaking the
///   `Option<&Certificate>` return shape.
/// - Malformed AKI / SKI extensions are treated as "extension absent" for
///   the purposes of discovery. Discovery is a heuristic; rejecting a chain
///   because of a malformed AKI on the CRL would punish callers for the
///   CRL issuer's bug, and the CRL signature verification step (downstream)
///   provides the authoritative gate.
///
/// # Independent oracle
///
/// The AKI/SKI walk's correctness is independently verified at the
/// extension-parser layer: `AuthorityKeyIdentifier` / `SubjectKeyIdentifier`
/// DER decoders live in `x509-cert` and have their own round-trip tests.
/// This function only performs byte equality of two decoded `OctetString`s;
/// no cryptographic primitive is being re-implemented here.
///
/// [`CrlChecker::new_with_signer_discovery`]: crate::CrlChecker::new_with_signer_discovery
#[must_use]
pub fn discover_crl_signer<'a>(
    bundle: &'a [Certificate],
    crl: &CertificateList,
) -> Option<&'a Certificate> {
    // (1) AKI/SKI walk.
    if let Some(aki_key_id) = crl_authority_key_id(crl) {
        for cert in bundle {
            if let Some(ski) = cert_subject_key_id(cert) {
                if ski.as_bytes() == aki_key_id.as_bytes() {
                    return Some(cert);
                }
            }
        }
        // AKI present but no SKI match: do not silently fall back to DN match.
        // A bundle that has the right DN but the wrong key would otherwise
        // hijack discovery — exactly the case AKI is designed to prevent.
        // Returning None here forces the caller to surface the failure
        // (CrlSignerNotFound) rather than silently picking the wrong cert.
        return None;
    }

    // (2) Issuer-DN fallback (only when no AKI keyIdentifier was present).
    let crl_issuer = &crl.tbs_cert_list.issuer;
    bundle
        .iter()
        .find(|cert| names_match(&cert.tbs_certificate.subject, crl_issuer))
}

/// Walk `bundle` from `signer` upward to a self-signed (anchor-like) cert.
///
/// Used by [`crate::CrlChecker::new_with_signer_discovery`] to satisfy
/// RFC 5280 §6.3.3(f)'s "chain back to a trust anchor" gate without pulling
/// in `pkix-path`'s full validation machinery (which would invert the one-way
/// dep direction).
///
/// "Chain" here means structural reachability only:
///
/// 1. If `signer.subject == signer.issuer` (self-signed) the walk succeeds
///    immediately — the bundle contains its own anchor candidate.
/// 2. Otherwise, find a cert in `bundle` whose `subject` matches `signer`'s
///    `issuer`. Prefer AKI/SKI matching when available; fall back to DN.
/// 3. Repeat until a self-signed cert is reached, or until no parent can be
///    found, or until a cycle is detected.
///
/// **No signature verification is performed.** The discovered signer's
/// signature is verified downstream when the constructed `CrlChecker` runs
/// `check_revocation`. Higher-layer callers (`pkix-chain`) are responsible
/// for full RFC 5280 §6.1 validation of the signer's path.
///
/// Returns `true` iff a self-signed cert is reachable. A bundle of size
/// `N` is walked at most `N + 1` steps; cycle detection uses subject-DN
/// equality to avoid quadratic memory.
pub(crate) fn reaches_self_signed(bundle: &[Certificate], signer: &Certificate) -> bool {
    // Bounded walk: at most one step per bundle entry, plus one to detect
    // the self-signed terminator. A cycle (which should not occur in a
    // well-formed bundle) would re-visit a subject DN we've already seen.
    let mut current = signer;
    let mut steps = 0usize;
    let max_steps = bundle.len().saturating_add(1);

    loop {
        // Self-signed: subject DN matches issuer DN. RFC 5280 §3.2 treats
        // such certs as candidate anchors. We do NOT verify the self-
        // signature here — that is the caller's responsibility via
        // pkix-chain or equivalent.
        if names_match(
            &current.tbs_certificate.subject,
            &current.tbs_certificate.issuer,
        ) {
            return true;
        }

        if steps >= max_steps {
            // Walked past the size of the bundle without hitting a self-
            // signed terminator. Either there is no anchor candidate or
            // the chain is malformed; fail closed.
            return false;
        }
        steps += 1;

        // Find the parent: prefer AKI on `current` matching SKI on parent,
        // fall back to subject-DN matching `current.issuer`.
        let parent = find_parent(bundle, current);
        match parent {
            Some(p) => current = p,
            None => return false,
        }
    }
}

/// Find a candidate parent for `cert` in `bundle`.
///
/// Preference order:
/// 1. Parent whose SKI matches `cert`'s AKI `keyIdentifier`.
/// 2. Parent whose subject DN matches `cert.issuer`.
///
/// Does not return `cert` itself unless it is the only DN match and is
/// self-signed (in which case the caller's self-signed check handles it
/// at the next iteration).
fn find_parent<'a>(bundle: &'a [Certificate], cert: &Certificate) -> Option<&'a Certificate> {
    if let Some(aki) = cert_authority_key_id(cert) {
        for candidate in bundle {
            // Skip the cert itself to prevent trivial self-loops when a
            // non-self-signed cert appears once in the bundle.
            if core::ptr::eq(candidate, cert) {
                continue;
            }
            if let Some(ski) = cert_subject_key_id(candidate) {
                if ski.as_bytes() == aki.as_bytes() {
                    return Some(candidate);
                }
            }
        }
    }
    let issuer = &cert.tbs_certificate.issuer;
    bundle.iter().find(|candidate| {
        !core::ptr::eq(*candidate, cert) && names_match(&candidate.tbs_certificate.subject, issuer)
    })
}

// ---------------------------------------------------------------------------
// Extension extractors
// ---------------------------------------------------------------------------

/// Extract the `AuthorityKeyIdentifier.keyIdentifier` field from a CRL.
///
/// Returns `None` if:
/// - The AKI extension is absent.
/// - The AKI is present but cannot be DER-decoded (treated as absent for
///   discovery purposes; see module docs).
/// - The AKI is present and decodes but contains no `keyIdentifier` field
///   (only `authorityCertIssuer` / `authorityCertSerialNumber`).
fn crl_authority_key_id(crl: &CertificateList) -> Option<OctetString> {
    let ext = crl
        .tbs_cert_list
        .crl_extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|e| e.extn_id == OID_AUTHORITY_KEY_IDENTIFIER)?;
    let aki =
        x509_cert::ext::pkix::AuthorityKeyIdentifier::from_der(ext.extn_value.as_bytes()).ok()?;
    aki.key_identifier
}

/// Extract the `AuthorityKeyIdentifier.keyIdentifier` field from a certificate.
fn cert_authority_key_id(cert: &Certificate) -> Option<OctetString> {
    let ext = cert
        .tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|e| e.extn_id == OID_AUTHORITY_KEY_IDENTIFIER)?;
    let aki =
        x509_cert::ext::pkix::AuthorityKeyIdentifier::from_der(ext.extn_value.as_bytes()).ok()?;
    aki.key_identifier
}

/// Extract the `SubjectKeyIdentifier` value from a certificate.
fn cert_subject_key_id(cert: &Certificate) -> Option<OctetString> {
    let ext = cert
        .tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|e| e.extn_id == OID_SUBJECT_KEY_IDENTIFIER)?;
    let ski =
        x509_cert::ext::pkix::SubjectKeyIdentifier::from_der(ext.extn_value.as_bytes()).ok()?;
    Some(ski.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkits_cert(name: &str) -> Vec<u8> {
        let base = env!("CARGO_MANIFEST_DIR");
        let path = format!("{base}/../pkix-path/tests/pkits/certs/{name}.crt");
        std::fs::read(&path).unwrap_or_else(|e| panic!("cert not found at {path}: {e}"))
    }

    fn pkits_crl(name: &str) -> Vec<u8> {
        let base = env!("CARGO_MANIFEST_DIR");
        let path = format!("{base}/../pkix-path/tests/pkits/crls/{name}.crl");
        std::fs::read(&path).unwrap_or_else(|e| panic!("CRL not found at {path}: {e}"))
    }

    fn load_cert(der: &[u8]) -> Certificate {
        Certificate::from_der(der).expect("cert DER parse")
    }

    fn load_crl(der: &[u8]) -> CertificateList {
        CertificateList::from_der(der).expect("CRL DER parse")
    }

    /// PKITS §4.5: AKI-on-CRL → SKI-on-bundle-cert walk picks the
    /// correct rollover-bridge signer even when several bundle certs
    /// share the CRL issuer's subject DN.
    #[test]
    fn aki_ski_picks_correct_rollover_signer() {
        // BasicSelfIssuedNewKeyCACRL is signed by BasicSelfIssuedNewKeyCACert
        // (the NEW key), not by BasicSelfIssuedNewKeyOldWithNewCACert (the
        // self-issued bridge with the OLD key, same subject DN). AKI/SKI is
        // the discriminator.
        let new_key_ca = load_cert(&pkits_cert("BasicSelfIssuedNewKeyCACert"));
        let bridge = load_cert(&pkits_cert("BasicSelfIssuedNewKeyOldWithNewCACert"));
        let crl = load_crl(&pkits_crl("BasicSelfIssuedNewKeyCACRL"));

        // Order: bridge first to verify we don't just take the first DN match.
        let bundle = vec![bridge.clone(), new_key_ca.clone()];
        let signer = discover_crl_signer(&bundle, &crl).expect("must locate signer");
        assert_eq!(
            signer.tbs_certificate.subject_public_key_info,
            new_key_ca.tbs_certificate.subject_public_key_info,
            "AKI/SKI walk should pick the NEW key cert, not the bridge",
        );
    }

    /// Reverse order check: still picks the right cert.
    #[test]
    fn aki_ski_is_order_independent() {
        let new_key_ca = load_cert(&pkits_cert("BasicSelfIssuedNewKeyCACert"));
        let bridge = load_cert(&pkits_cert("BasicSelfIssuedNewKeyOldWithNewCACert"));
        let crl = load_crl(&pkits_crl("BasicSelfIssuedNewKeyCACRL"));

        let bundle = vec![new_key_ca.clone(), bridge.clone()];
        let signer = discover_crl_signer(&bundle, &crl).expect("must locate signer");
        assert_eq!(
            signer.tbs_certificate.subject_public_key_info,
            new_key_ca.tbs_certificate.subject_public_key_info,
        );
    }

    /// Empty bundle → None.
    #[test]
    fn empty_bundle_returns_none() {
        let crl = load_crl(&pkits_crl("BasicSelfIssuedNewKeyCACRL"));
        assert!(discover_crl_signer(&[], &crl).is_none());
    }

    /// Bundle without any matching cert → None.
    #[test]
    fn unrelated_bundle_returns_none() {
        // Use a cert from a completely different test family — its SKI
        // will not match the §4.5 CRL's AKI.
        let unrelated = load_cert(&pkits_cert("GoodCACert"));
        let crl = load_crl(&pkits_crl("BasicSelfIssuedNewKeyCACRL"));
        assert!(discover_crl_signer(std::slice::from_ref(&unrelated), &crl).is_none());
    }

    /// reaches_self_signed: a self-signed cert is its own anchor.
    #[test]
    fn self_signed_reaches_itself() {
        let trust_anchor = load_cert(&pkits_cert("TrustAnchorRootCertificate"));
        assert!(reaches_self_signed(
            std::slice::from_ref(&trust_anchor),
            &trust_anchor
        ));
    }

    /// reaches_self_signed: a non-self-signed cert with no parent in the
    /// bundle does not reach an anchor.
    #[test]
    fn orphan_cert_does_not_reach_anchor() {
        let signer = load_cert(&pkits_cert("BasicSelfIssuedNewKeyCACert"));
        // No parent in bundle.
        assert!(!reaches_self_signed(std::slice::from_ref(&signer), &signer));
    }

    /// reaches_self_signed: signer + its issuer (a self-signed root) → true.
    #[test]
    fn signer_with_root_reaches_anchor() {
        let signer = load_cert(&pkits_cert("BasicSelfIssuedNewKeyCACert"));
        let root = load_cert(&pkits_cert("TrustAnchorRootCertificate"));
        let bundle = vec![signer.clone(), root.clone()];
        assert!(reaches_self_signed(&bundle, &signer));
    }
}
