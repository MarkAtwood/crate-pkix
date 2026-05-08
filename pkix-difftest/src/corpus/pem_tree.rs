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
    let chain = Chain::from_pem_bytes(&cert_only, name.clone())?;
    Ok(CorpusItem {
        name,
        expected: None,
        chain,
    })
}

/// Naive recursive directory walker. Avoids the `walkdir` dep — for v0.1
/// the corpora we walk are small (PKITS, pyca tests). If/when CT-log-scale
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
