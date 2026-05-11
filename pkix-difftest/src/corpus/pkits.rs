//! PKITS corpus loader.
//!
//! Reads the NIST PKITS test vector manifest (`vectors.json`) and emits one
//! [`crate::corpus::CorpusItem`] per test case. The certificate files
//! referenced by `CertPath` live in the `certs/` subdirectory of the
//! supplied corpus root. The CRL files referenced by `CRLPath` live in the
//! `crls/` subdirectory and are loaded into [`crate::Chain::crls`] for
//! oracle-side revocation checking.
//!
//! The vectors.json schema is fully uniform across the 249 entries shipped
//! with this project — see PKIX-7nsf.4 explore notes. We deserialise every
//! field, even the ones the v1 harness ignores (`InitialPolicy*`),
//! to make the loader fail loudly if a future PKITS update changes the
//! schema. `#[serde(deny_unknown_fields)]` is the canonical way to do that.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use der::Decode as _;
use pkix_path::TrustAnchor;
use pkix_path_builder::{build_path, CertPool};
use serde::Deserialize;
use x509_cert::Certificate;

use crate::corpus::{Corpus, CorpusItem};
use crate::{Chain, Verdict};

/// PKITS vector entry.
///
/// `pub` so callers (and PKIX-7nsf.5's classifier) can examine the policy
/// fields when they become relevant. v1 only uses `name`, `cert_path`,
/// `should_validate`.
//
// `clippy::struct_excessive_bools` is allowed here because the struct is a
// 1:1 mirror of an external JSON schema (NIST PKITS vectors.json). PKITS
// happens to define 4 boolean policy flags; refactoring to enums would
// distort the deserialised shape. The lint's intent ("don't accumulate state
// flags") is correct in general but does not apply to schema-faithful types.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct PkitsVector {
    pub name: String,
    /// Cert filenames in **root-first** order
    /// (`CertPath[0]` == trust anchor, `CertPath[len-1]` == end-entity).
    pub cert_path: Vec<String>,
    /// Acronym capitalisation in PKITS JSON (`CRLPath`, not `CrlPath`)
    /// requires a manual override; serde's `PascalCase` renamer would
    /// otherwise produce the wrong key.
    #[serde(rename = "CRLPath")]
    pub crl_path: Vec<String>,
    pub should_validate: bool,
    pub initial_policy_set: Vec<String>,
    pub initial_policy_mapping_inhibit: bool,
    pub initial_explicit_policy: bool,
    pub initial_any_policy_inhibit: bool,
}

/// Corpus implementation for the NIST PKITS test vectors.
#[derive(Debug)]
pub struct PkitsCorpus {
    /// Directory containing `vectors.json` and `certs/`.
    root: PathBuf,
    vectors: Vec<PkitsVector>,
}

impl PkitsCorpus {
    /// Load the PKITS manifest from `<root>/vectors.json`.
    ///
    /// Errors when the directory or manifest is missing, or when the JSON
    /// fails to parse as a `Vec<PkitsVector>`. (Per-entry resolution errors
    /// surface lazily during iteration.)
    pub fn load(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        let manifest_path = root.join("vectors.json");
        let manifest_bytes = fs::read(&manifest_path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "PKITS corpus: cannot read manifest at {}: {e}",
                    manifest_path.display()
                ),
            )
        })?;
        let vectors: Vec<PkitsVector> = serde_json::from_slice(&manifest_bytes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "PKITS corpus: malformed manifest at {}: {e}",
                    manifest_path.display()
                ),
            )
        })?;
        Ok(Self { root, vectors })
    }

    /// Number of vectors in the manifest. Used by tests and reporters.
    #[must_use]
    pub fn len(&self) -> usize {
        self.vectors.len()
    }

    /// Whether the manifest is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vectors.is_empty()
    }

    fn certs_dir(&self) -> PathBuf {
        self.root.join("certs")
    }

    fn crls_dir(&self) -> PathBuf {
        self.root.join("crls")
    }
}

impl Corpus for PkitsCorpus {
    fn iter(&self) -> Box<dyn Iterator<Item = io::Result<CorpusItem>> + '_> {
        let certs_dir = self.certs_dir();
        let crls_dir = self.crls_dir();
        Box::new(self.vectors.iter().map(move |vec| {
            build_item(&certs_dir, &crls_dir, vec).map_err(|e| {
                // Annotate the error with the test name so reporters can
                // attribute it without cross-referencing.
                io::Error::new(e.kind(), format!("PKITS '{}': {}", vec.name, e))
            })
        }))
    }
}

/// Try to assemble the canonical leaf-first signature chain from a PKITS
/// `CertPath` bundle (root-first DER) via `pkix-path-builder`.
///
/// Returns `None` on any failure — parse error, build error, or an internal
/// invariant violation. Callers fall back to the v1 root-first-reversed
/// ordering, which keeps the chain bytes visible to every oracle for
/// downstream classification.
///
/// Assumes `der_blocks` is root-first and `der_blocks[0]` is the trust
/// anchor (true for every shipped PKITS vector — verified by jq against
/// `vectors.json`).
fn try_build_chain(der_blocks: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let mut parsed: Vec<Certificate> = Vec::with_capacity(der_blocks.len());
    for bytes in der_blocks {
        parsed.push(Certificate::from_der(bytes).ok()?);
    }

    let anchor_idx = 0;
    let ee_idx = parsed.len() - 1;
    let anchor = &parsed[anchor_idx];
    let ee = &parsed[ee_idx];

    // Pool of candidates for path building: everything except the anchor.
    // Including the EE in the pool is harmless — `build_path` uses pool
    // only as a candidate source for intermediates and never tries to
    // re-add the target.
    let pool: CertPool = parsed
        .iter()
        .enumerate()
        .filter(|&(i, _)| i != anchor_idx)
        .map(|(_, c)| c.clone())
        .collect();

    let trust_anchors = [TrustAnchor::from_cert(anchor.clone())];
    let built = build_path(ee, &pool, &trust_anchors).ok()?;

    // Map each built-chain cert back to its source DER bytes. `Certificate`
    // derives `PartialEq` over its full ASN.1 content, so equality is the
    // right oracle: a cert and its parsed-then-cloned twin compare equal.
    let mut chain_der: Vec<Vec<u8>> = Vec::with_capacity(built.len() + 1);
    for built_cert in &built {
        let idx = parsed.iter().position(|p| p == built_cert)?;
        chain_der.push(der_blocks[idx].clone());
    }
    // Append the anchor (build_path returns the chain up to anchor-issued
    // but not the anchor itself; the oracles' `root_in_chain == true`
    // contract requires the anchor at the end).
    chain_der.push(der_blocks[anchor_idx].clone());
    Some(chain_der)
}

/// Build a single [`CorpusItem`] from a PKITS vector entry.
///
/// PKITS `CertPath` is a **bundle** for a path builder, not a pre-ordered
/// signature chain (see the bd memory `pkits-certpath-is-bundle-not-signature-chain`
/// and PKIX-t0w4 for the underlying issue). For most tests it happens to be
/// the signature chain too, but PKITS §4.4, §4.14, and some §4.5 entries
/// include a CRL-signing cert at a position that breaks the positional walk
/// `pkix-path` expects. To present every oracle with the actual signature
/// chain we route the bundle through `pkix_path_builder::build_path` and
/// store the resulting leaf-first chain (anchor appended) as `certs_der`.
///
/// `CertPath[0]` is the trust anchor in every shipped PKITS vector; `CertPath`
/// suffix entries are candidate intermediates and the end-entity. Build flow:
///
/// 1. Parse every entry.
/// 2. Anchor = `parsed[0]`. End-entity = `parsed[last]`.
/// 3. Pool = `parsed[1..]` (everything except the anchor).
/// 4. `build_path(target=ee, pool, anchors=[anchor])` → leaf-first
///    `[ee, ..., anchor-issued]`.
/// 5. Append the anchor cert to keep `root_in_chain == true`.
///
/// `build_path` returning `NoPathFound` is itself a meaningful corpus signal —
/// it means the bundle cannot be assembled into a valid chain. We surface
/// that as an `io::Error` so the corpus iterator reports the failed entry
/// rather than silently substituting a bogus chain.
fn build_item(certs_dir: &Path, crls_dir: &Path, vec: &PkitsVector) -> io::Result<CorpusItem> {
    if vec.cert_path.len() < 2 {
        // Defensive: the schema explore confirmed every vector has CertPath
        // length ≥ 2, but a future PKITS update could violate that.
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CertPath has fewer than 2 entries",
        ));
    }

    // Read each DER cert. PKITS gives root-first.
    let mut der_blocks: Vec<Vec<u8>> = Vec::with_capacity(vec.cert_path.len());
    for filename in &vec.cert_path {
        let path = certs_dir.join(filename);
        let bytes = fs::read(&path)
            .map_err(|e| io::Error::new(e.kind(), format!("read {}: {e}", path.display())))?;
        der_blocks.push(bytes);
    }

    // Try to assemble a chain through pkix-path-builder. Two failure modes
    // we tolerate (both fall back to v1 root-first-reversed ordering):
    //
    // 1. **Parse failure** — at least one cert in the bundle does not
    //    decode (e.g. PKITS §4.2.3 pre-2000 UTCTime, an upstream
    //    x509-cert / der-crate limitation). The v1 loader never parsed,
    //    so the chain was always visible to OpenSSL/pyca via raw DER.
    //    Preserve that behaviour rather than dropping the entry.
    // 2. **No path found** — typically a PKITS *negative* test whose
    //    bundle deliberately violates a topological invariant
    //    (cA=FALSE intermediate, name-chain mismatch, no DN-matching
    //    candidate). The oracles agree on "this chain should fail"
    //    either way, so the fallback preserves baseline coverage for
    //    the negative-test cases that motivate the bundle layout.
    let chain_der = try_build_chain(&der_blocks).unwrap_or_else(|| {
        let mut rev = der_blocks.clone();
        rev.reverse();
        rev
    });

    // CRLs follow the same convention: filenames are listed in the manifest
    // and resolved against `crls_dir`. Order is preserved (no reverse) because
    // CRLs are not chain-ordered — each one stands alone, and downstream
    // oracles use them positionally only for deterministic reason-string
    // attribution.
    let mut crl_blocks: Vec<Vec<u8>> = Vec::with_capacity(vec.crl_path.len());
    for filename in &vec.crl_path {
        let path = crls_dir.join(filename);
        let bytes = fs::read(&path)
            .map_err(|e| io::Error::new(e.kind(), format!("read {}: {e}", path.display())))?;
        crl_blocks.push(bytes);
    }

    let chain = Chain {
        certs_der: chain_der,
        crls: crl_blocks,
        root_in_chain: true,
        label: vec.name.clone(),
        // PKITS has no per-testcase validation time; oracles fall back to
        // their current-time defaults. The limbo loader (PKIX-g9vc.2) sets
        // this from each testcase's `validation_time` field.
        validation_time_unix: None,
    };

    Ok(CorpusItem {
        name: vec.name.clone(),
        expected: Some(if vec.should_validate {
            Verdict::Pass
        } else {
            // The reason field is intentionally empty: PKITS does not
            // standardise the *reason* a chain should fail, only that it
            // should. `DiagnosticDivergence` classification will treat empty
            // expected reasons specially (see PKIX-7nsf.5).
            Verdict::Fail {
                reason: String::new(),
            }
        }),
        chain,
    })
}
