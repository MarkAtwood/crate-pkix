//! PKITS corpus loader.
//!
//! Reads the NIST PKITS test vector manifest (`vectors.json`) and emits one
//! [`crate::corpus::CorpusItem`] per test case. The certificate files
//! referenced by `CertPath` live in the `certs/` subdirectory of the
//! supplied corpus root.
//!
//! The vectors.json schema is fully uniform across the 249 entries shipped
//! with this project — see PKIX-7nsf.4 explore notes. We deserialise every
//! field, even the ones the v1 harness ignores (`CRLPath`, `InitialPolicy*`),
//! to make the loader fail loudly if a future PKITS update changes the
//! schema. `#[serde(deny_unknown_fields)]` is the canonical way to do that.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;

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
}

impl Corpus for PkitsCorpus {
    fn iter(&self) -> Box<dyn Iterator<Item = io::Result<CorpusItem>> + '_> {
        let certs_dir = self.certs_dir();
        Box::new(self.vectors.iter().map(move |vec| {
            build_item(&certs_dir, vec).map_err(|e| {
                // Annotate the error with the test name so reporters can
                // attribute it without cross-referencing.
                io::Error::new(e.kind(), format!("PKITS '{}': {}", vec.name, e))
            })
        }))
    }
}

/// Build a single [`CorpusItem`] from a PKITS vector entry.
///
/// Reads each `.crt` file as DER, builds a `Chain` directly (skipping the
/// PEM round-trip in `Chain::from_pem_bytes`), and reverses to leaf-first.
fn build_item(certs_dir: &Path, vec: &PkitsVector) -> io::Result<CorpusItem> {
    if vec.cert_path.len() < 2 {
        // Defensive: the schema explore confirmed every vector has CertPath
        // length ≥ 2, but a future PKITS update could violate that.
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CertPath has fewer than 2 entries",
        ));
    }

    // Read each DER cert. PKITS gives root-first; we reverse below to canonical
    // leaf-first.
    let mut der_blocks: Vec<Vec<u8>> = Vec::with_capacity(vec.cert_path.len());
    for filename in &vec.cert_path {
        let path = certs_dir.join(filename);
        let bytes = fs::read(&path)
            .map_err(|e| io::Error::new(e.kind(), format!("read {}: {e}", path.display())))?;
        der_blocks.push(bytes);
    }
    der_blocks.reverse(); // root-first → leaf-first

    let chain = Chain {
        certs_der: der_blocks,
        crls: Vec::new(),
        root_in_chain: true,
        label: vec.name.clone(),
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
