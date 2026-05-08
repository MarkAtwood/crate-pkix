//! Single-chain corpus assembled from explicit file paths.
//!
//! Used for ad-hoc debugging: `pkix-difftest pem-multi leaf.pem int.pem
//! root.pem` runs one chain through the harness without needing to pre-build
//! a concatenated `chain.pem`. The yielded chain is auto-ordered by the same
//! self-issued-cert heuristic as [`crate::Chain::from_pem_bytes`].
//!
//! Each input file may be any DER- or PEM-encoded certificate. The loader
//! detects DER (file does not start with `-----BEGIN`) versus PEM and
//! decodes accordingly.

use std::fs;
use std::io;
use std::path::PathBuf;

use crate::corpus::{Corpus, CorpusItem};
use crate::Chain;

/// Single-chain corpus from a fixed list of file paths.
#[derive(Debug)]
pub struct PemMultiCorpus {
    paths: Vec<PathBuf>,
    label: String,
}

impl PemMultiCorpus {
    /// Construct from a list of cert files. Order in `paths` is irrelevant —
    /// the loader auto-detects leaf-first vs root-first.
    pub fn new(paths: Vec<PathBuf>, label: impl Into<String>) -> Self {
        Self {
            paths,
            label: label.into(),
        }
    }
}

impl Corpus for PemMultiCorpus {
    fn iter(&self) -> Box<dyn Iterator<Item = io::Result<CorpusItem>> + '_> {
        let label = self.label.clone();
        let paths = self.paths.clone();
        Box::new(std::iter::once_with(move || {
            build_chain(&paths, &label).map(|chain| CorpusItem {
                name: label.clone(),
                expected: None,
                chain,
            })
        }))
    }
}

fn build_chain(paths: &[PathBuf], label: &str) -> io::Result<Chain> {
    if paths.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pem-multi corpus: no cert files provided",
        ));
    }
    // Collect each file as one PEM block so we can hand the lot to
    // `Chain::from_pem_bytes` and reuse the existing ordering-detect path.
    let mut concat: Vec<u8> = Vec::new();
    for path in paths {
        let bytes = fs::read(path)
            .map_err(|e| io::Error::new(e.kind(), format!("read {}: {e}", path.display())))?;
        let pem = if looks_like_pem(&bytes) {
            // Pass through verbatim — may be one or multiple blocks.
            String::from_utf8(bytes).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: invalid UTF-8 in PEM: {e}", path.display()),
                )
            })?
        } else {
            // Treat as DER — wrap in PEM.
            pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &bytes).map_err(
                |e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{}: DER → PEM encode failed: {e}", path.display()),
                    )
                },
            )?
        };
        concat.extend_from_slice(pem.as_bytes());
        // Ensure we always end with a newline so the next block's BEGIN is on
        // its own line, regardless of whether the source PEM had a trailing
        // newline.
        if !concat.ends_with(b"\n") {
            concat.push(b'\n');
        }
    }
    Chain::from_pem_bytes(&concat, label.to_string())
}

fn looks_like_pem(bytes: &[u8]) -> bool {
    // Skip leading ASCII whitespace then check for the BEGIN preamble. PEM
    // files commonly have a UTF-8 BOM or leading blank lines that we don't
    // want to misclassify as DER.
    let trimmed = bytes
        .iter()
        .position(|&b| !b.is_ascii_whitespace() && b != 0xEF && b != 0xBB && b != 0xBF);
    let Some(start) = trimmed else { return false };
    bytes[start..].starts_with(b"-----BEGIN ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_like_pem_recognises_basic_pem() {
        assert!(looks_like_pem(b"-----BEGIN CERTIFICATE-----\n"));
        assert!(looks_like_pem(b"\n   -----BEGIN CERTIFICATE-----\n"));
    }

    #[test]
    fn looks_like_pem_rejects_der_bytes() {
        // DER cert always starts with 0x30 (SEQUENCE).
        assert!(!looks_like_pem(&[0x30, 0x82, 0x01, 0x00]));
    }

    #[test]
    fn looks_like_pem_handles_empty() {
        assert!(!looks_like_pem(b""));
        assert!(!looks_like_pem(b"   \n  "));
    }
}
