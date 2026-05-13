//! Recursive PEM-tree corpus loader.
//!
//! Walks a directory tree and yields a [`crate::corpus::CorpusItem`] for every
//! file matching the configured filename (default `chain.pem`). No
//! ground-truth verdict — this corpus shape is for in-the-wild bundles
//! where we want to know what the oracles say but have no reference answer.
//!
//! ## Filename match policy
//!
//! Default: case-sensitive exact match on `chain.pem`. Use
//! [`PemTreeCorpus::load_with_filename`] if your corpus uses a different
//! convention. We deliberately do not pull in a glob crate — filename
//! filtering is enough for both PKITS and pyca conventions.
//!
//! ## CRL convention
//!
//! When a chain directory contains a sibling `crls/` subdirectory, every
//! regular file in `crls/` is treated as a CRL: PEM-encoded `X509 CRL`
//! blocks (one per file) are decoded to DER, and bare DER files are accepted
//! as-is. Files are read in lexicographic order for deterministic test
//! reports. The resulting DER bytes are attached to the chain via
//! [`crate::Chain::with_crls`].
//!
//! An absent `crls/` directory leaves the chain's `crls` empty (no
//! revocation). A `crls/` directory that exists but contains no regular
//! files is also treated as empty and is not an error — this is the same
//! shape `limbo-to-pem-tree.py` produces for testcases with the `has-crl`
//! feature.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::corpus::{filter_non_certificate_blocks, Corpus, CorpusItem};
use crate::Chain;

/// Corpus implementation that walks a directory for chain.pem-style bundles.
#[derive(Debug)]
pub struct PemTreeCorpus {
    chain_paths: Vec<PathBuf>,
    /// Root prefix used to derive chain `name` values (relative-path style).
    root: PathBuf,
}

impl PemTreeCorpus {
    /// Walk `root` recursively and collect every file matching `chain.pem`.
    ///
    /// The directory is walked at construction time — that is, finding the
    /// chain files is eager but reading them is lazy (during iteration).
    /// This split lets the caller fail-fast on a missing root directory while
    /// still keeping memory pressure low for large corpora (millions of
    /// chains in a CT-log dump).
    pub fn load(root: impl AsRef<Path>) -> io::Result<Self> {
        Self::load_with_filename(root, "chain.pem")
    }

    /// Walk `root` recursively and collect every file with the given
    /// basename.
    pub fn load_with_filename(root: impl AsRef<Path>, filename: &str) -> io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        if !root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("PEM-tree corpus: not a directory: {}", root.display()),
            ));
        }
        let mut chain_paths = Vec::new();
        walk(&root, filename, &mut chain_paths)?;
        chain_paths.sort(); // deterministic iteration order for diff-friendly reports
        Ok(Self { chain_paths, root })
    }

    /// Number of chain files discovered. Used by tests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.chain_paths.len()
    }

    /// Whether the corpus is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chain_paths.is_empty()
    }
}

impl Corpus for PemTreeCorpus {
    fn iter(&self) -> Box<dyn Iterator<Item = io::Result<CorpusItem>> + '_> {
        let root = self.root.clone();
        Box::new(self.chain_paths.iter().map(move |path| {
            load_one(&root, path).map_err(|e| {
                io::Error::new(e.kind(), format!("PEM-tree '{}': {}", path.display(), e))
            })
        }))
    }
}

fn load_one(root: &Path, path: &Path) -> io::Result<CorpusItem> {
    let bytes = fs::read(path)?;
    // Drop non-CERTIFICATE blocks so private keys and the like don't break
    // the chain loader. The caller (PEM-tree) explicitly chose this lax
    // policy; the strict `Chain::from_pem_bytes` path is unaffected.
    let cert_only = filter_non_certificate_blocks(&bytes);
    let name = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned();
    let mut chain = Chain::from_pem_bytes(&cert_only, name.clone())?;

    // Optional `crls/` sibling directory next to chain.pem. Absence is the
    // common case (no revocation); presence opts the chain into RFC 5280
    // §6.3 revocation against the bundled CRLs at oracle time.
    if let Some(parent) = path.parent() {
        let crls_dir = parent.join("crls");
        if crls_dir.is_dir() {
            let crls = load_crls_in_dir(&crls_dir).map_err(|e| {
                io::Error::new(e.kind(), format!("crls/ for {}: {}", path.display(), e))
            })?;
            if !crls.is_empty() {
                chain = chain.with_crls(crls);
            }
        }
    }

    Ok(CorpusItem {
        name,
        expected: None,
        chain,
    })
}

/// Load every regular file in `dir` as a CRL and return the DER bytes.
///
/// Each file is decoded once: a PEM-encoded `X509 CRL` block is recognised
/// and converted to DER; anything else is passed through as-is on the
/// assumption it is already DER. Files are visited in lexicographic order so
/// the resulting `Vec<Vec<u8>>` order is reproducible across runs (the diff
/// harness's reports compare verdict-by-verdict, so deterministic CRL
/// ordering keeps reason strings stable when oracles differ on which CRL
/// rejected a chain first).
///
/// Subdirectories and non-regular entries are skipped silently. A PEM block
/// labelled anything other than `X509 CRL` is rejected as a configuration
/// error.
fn load_crls_in_dir(dir: &Path) -> io::Result<Vec<Vec<u8>>> {
    let mut entries: Vec<_> = fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::path);

    let mut crls = Vec::new();
    for entry in entries {
        let ft = entry.file_type()?;
        if !ft.is_file() {
            continue;
        }
        let path = entry.path();
        let bytes = fs::read(&path)?;
        match pem_rfc7468::decode_vec(&bytes) {
            Ok((label, der)) => {
                if label != "X509 CRL" {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "{}: expected PEM block 'X509 CRL', got '{}'",
                            path.display(),
                            label
                        ),
                    ));
                }
                crls.push(der);
            }
            // Not a PEM block at all — assume the file is bare DER.
            Err(_) => crls.push(bytes),
        }
    }
    Ok(crls)
}

/// Naive recursive directory walker. Avoids the `walkdir` dep — the
/// corpora we walk are small (PKITS, pyca tests). If/when CT-log-scale
/// walking lands (PKIX-5bab), reconsider.
fn walk(dir: &Path, filename: &str, out: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        // Use file_type rather than is_dir/is_file to avoid following
        // symlinks blindly into a cycle. We stay on the current filesystem
        // and treat symlinks to dirs as opaque (don't recurse).
        let ft = entry.file_type()?;
        if ft.is_dir() {
            walk(&path, filename, out)?;
        } else if ft.is_file()
            && path
                .file_name()
                .is_some_and(|n| n.to_string_lossy() == filename)
        {
            out.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Two contrived bytes-as-CRLs written into `dir/crls/{a,b}.pem`. The
    /// content does not need to be a real CRL — `load_crls_in_dir` only
    /// decodes PEM, it does not validate CRL structure. That keeps this
    /// test independent of an upstream CRL fixture.
    fn write_pem_crls(dir: &Path, payloads: &[&[u8]]) -> io::Result<()> {
        let crls_dir = dir.join("crls");
        std::fs::create_dir_all(&crls_dir)?;
        for (i, payload) in payloads.iter().enumerate() {
            let pem = pem_rfc7468::encode_string("X509 CRL", pem_rfc7468::LineEnding::LF, payload)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            std::fs::write(crls_dir.join(format!("{i}.pem")), pem)?;
        }
        Ok(())
    }

    #[test]
    fn load_crls_in_dir_decodes_pem_x509_crl_blocks_in_lex_order() {
        // Oracle: PEM payloads in lex-named files are decoded back to the
        // original DER, in lexicographic order.
        let dir = TempDir::new().expect("tempdir");
        let payloads: [&[u8]; 3] = [b"first", b"second", b"third"];
        write_pem_crls(dir.path(), &payloads).expect("write");
        let out = load_crls_in_dir(&dir.path().join("crls")).expect("load");
        assert_eq!(out.len(), 3);
        assert_eq!(out[0], b"first");
        assert_eq!(out[1], b"second");
        assert_eq!(out[2], b"third");
    }

    #[test]
    fn load_crls_in_dir_accepts_bare_der_files() {
        // Oracle: a file that is not a PEM block is passed through as DER.
        // This keeps the loader liberal in what it accepts — testcases that
        // ship CRLs as raw .crl files don't need an extra conversion step.
        let dir = TempDir::new().expect("tempdir");
        let crls_dir = dir.path().join("crls");
        std::fs::create_dir_all(&crls_dir).expect("mkdir");
        std::fs::write(crls_dir.join("0.crl"), b"\x30\x82\x00\x01raw der bytes").expect("write");
        let out = load_crls_in_dir(&crls_dir).expect("load");
        assert_eq!(out.len(), 1);
        assert!(out[0].starts_with(b"\x30\x82"));
    }

    #[test]
    fn load_crls_in_dir_rejects_wrong_pem_label() {
        // Oracle: a CERTIFICATE block in the crls/ directory is a
        // configuration error and must surface as an error, not be
        // silently swallowed.
        let dir = TempDir::new().expect("tempdir");
        let crls_dir = dir.path().join("crls");
        std::fs::create_dir_all(&crls_dir).expect("mkdir");
        let cert_pem = pem_rfc7468::encode_string(
            "CERTIFICATE",
            pem_rfc7468::LineEnding::LF,
            b"not actually a cert",
        )
        .expect("encode");
        std::fs::write(crls_dir.join("0.pem"), cert_pem).expect("write");
        let err = load_crls_in_dir(&crls_dir).expect_err("must error on wrong label");
        assert!(
            err.to_string().contains("X509 CRL"),
            "error must mention expected label, got: {err}"
        );
    }

    #[test]
    fn load_crls_in_dir_skips_subdirectories() {
        // Oracle: a subdirectory inside crls/ is silently skipped (the
        // intent is to allow future grouping conventions without breaking
        // existing layouts). Only regular files are loaded.
        let dir = TempDir::new().expect("tempdir");
        let crls_dir = dir.path().join("crls");
        std::fs::create_dir_all(crls_dir.join("subdir")).expect("mkdir");
        let pem = pem_rfc7468::encode_string("X509 CRL", pem_rfc7468::LineEnding::LF, b"present")
            .expect("encode");
        std::fs::write(crls_dir.join("0.pem"), pem).expect("write");
        let out = load_crls_in_dir(&crls_dir).expect("load");
        assert_eq!(
            out.len(),
            1,
            "subdir must be skipped, only the regular file loaded"
        );
    }

    #[test]
    fn load_one_attaches_crls_from_sibling_crls_directory() {
        // Oracle: end-to-end. Write a real chain.pem next to a crls/ dir
        // and confirm the loader emits a CorpusItem whose chain has crls
        // populated. Uses an existing PKITS cert as the chain so we know
        // it parses; the CRL payload itself does not need to be parsed by
        // the harness (only by oracles).
        let chain_pem_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("pkix-path")
            .join("tests")
            .join("pkits")
            .join("certs")
            .join("TrustAnchorRootCertificate.crt");
        let chain_der = std::fs::read(&chain_pem_path).expect("read PKITS root cert DER");

        let dir = TempDir::new().expect("tempdir");
        // Self-signed root used as both leaf and root for ordering
        // detection: leaf cert + (different cert as) anchor would be
        // ideal, but we already test ordering elsewhere. Two-cert chain
        // with the same self-signed cert appears at both positions; the
        // is_self_issued heuristic will then flag both ends self-issued,
        // failing detection. So use the cert twice in a way that breaks
        // the heuristic — wait, that errors. Use the cert once: a
        // single-element chain (heuristic returns Ok(true) early). The
        // CorpusItem still loads and the only failure surface is the
        // chain-too-short error which load_one does not check.
        //
        // Actually, simpler: a single-cert "chain" is what we test
        // ordering for in lib.rs's tests; load_one accepts it. That's
        // enough for this test, which only cares about the crls/
        // sibling-dir wiring.
        let cert_pem =
            pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &chain_der)
                .expect("PEM encode cert");
        std::fs::write(dir.path().join("chain.pem"), cert_pem).expect("write chain.pem");

        let crl_pem = pem_rfc7468::encode_string(
            "X509 CRL",
            pem_rfc7468::LineEnding::LF,
            b"opaque CRL bytes for harness wiring test",
        )
        .expect("PEM encode CRL");
        std::fs::create_dir(dir.path().join("crls")).expect("mkdir crls");
        std::fs::write(dir.path().join("crls").join("0.pem"), crl_pem).expect("write crl");

        let item =
            load_one(dir.path(), &dir.path().join("chain.pem")).expect("load_one must succeed");
        assert_eq!(
            item.chain.crls.len(),
            1,
            "load_one must pick up the sibling crls/ directory"
        );
        assert_eq!(
            item.chain.crls[0],
            b"opaque CRL bytes for harness wiring test"
        );
    }

    #[test]
    fn load_one_leaves_crls_empty_when_sibling_directory_absent() {
        // Oracle: no crls/ sibling → chain.crls.is_empty(). This is the
        // common case for testcases without revocation data.
        let chain_pem_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("pkix-path")
            .join("tests")
            .join("pkits")
            .join("certs")
            .join("TrustAnchorRootCertificate.crt");
        let chain_der = std::fs::read(&chain_pem_path).expect("read root cert DER");

        let dir = TempDir::new().expect("tempdir");
        let cert_pem =
            pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &chain_der)
                .expect("PEM encode cert");
        std::fs::write(dir.path().join("chain.pem"), cert_pem).expect("write");

        let item =
            load_one(dir.path(), &dir.path().join("chain.pem")).expect("load_one must succeed");
        assert!(
            item.chain.crls.is_empty(),
            "absent crls/ must leave chain.crls empty"
        );
    }
}
