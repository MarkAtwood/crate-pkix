//! Corpus loaders.
//!
//! A corpus is anything that yields `(name, expected_verdict_opt, chain)`
//! triples. The harness runs each chain through every configured oracle and
//! classifies the resulting verdict tuple (PKIX-7nsf.5).
//!
//! Three loaders are provided:
//! * [`pkits::PkitsCorpus`] — reads `tests/pkits/vectors.json` shipped with
//!   the NIST PKITS test vector pack. Provides ground truth via
//!   `ShouldValidate`.
//! * [`pem_tree::PemTreeCorpus`] — recursively walks a directory tree and
//!   yields every file matching a configurable filename (default
//!   `chain.pem`). No ground truth.
//! * [`pem_multi::PemMultiCorpus`] — single chain assembled from explicit
//!   file paths supplied on the command line. Useful for ad-hoc debugging.
//!
//! The trait surface is `Box<dyn Iterator<...>> + '_` rather than `impl
//! Iterator + '_` because workspace MSRV is 1.73 and `impl Trait in trait
//! return position` (RPITIT) only stabilised in 1.75.

pub mod pem_multi;
pub mod pem_tree;
pub mod pkits;

use std::io;

use crate::{Chain, Verdict};

/// One element yielded by a [`Corpus`] iterator.
///
/// Each item is independently fallible — a malformed chain inside a corpus
/// must NOT abort iteration over sibling chains. The iterator yields a
/// per-chain `io::Result` so the caller (and the eventual reporter) can flag
/// the broken entries while still scoring the rest.
pub struct CorpusItem {
    /// Human-readable identifier — typically the PKITS test name or the
    /// chain.pem path relative to the corpus root.
    pub name: String,
    /// Ground-truth expected verdict, if the corpus carries one.
    /// `None` means the corpus has no opinion (e.g., real-wild PEM bundles).
    pub expected: Option<Verdict>,
    /// The chain itself, normalised to leaf-first.
    pub chain: Chain,
}

/// A source of cert chains to feed through the harness.
pub trait Corpus {
    /// Iterate over every chain in the corpus.
    ///
    /// Each item is an `io::Result<CorpusItem>`. The iterator must keep
    /// yielding even after one or more items fail — the harness reports
    /// per-chain errors as a separate category, distinct from per-chain
    /// verdicts. Implementations MUST NOT silently skip entries.
    fn iter(&self) -> Box<dyn Iterator<Item = io::Result<CorpusItem>> + '_>;
}

/// Strip every PEM block whose label is not `CERTIFICATE` and return the
/// concatenated cert-only PEM bytes.
///
/// Real-world chain.pem bundles in the wild often include a private key block
/// alongside the certs (e.g. `cat key.pem chain.pem > bundle.pem`). The
/// strict [`Chain::from_pem_bytes`] loader rejects those bundles by design
/// (single-chain CLI use treats mixed content as a config bug). Corpus
/// walkers, by contrast, should keep going — this helper centralises the
/// "drop everything except CERTIFICATE blocks" policy so individual corpus
/// implementations do not duplicate it.
///
/// If the input contains no CERTIFICATE blocks, returns an empty `Vec` and
/// the caller's `Chain::from_pem_bytes` will surface a "no PEM CERTIFICATE
/// blocks found" error — which is the correct outcome for a malformed entry.
pub(crate) fn filter_non_certificate_blocks(bytes: &[u8]) -> Vec<u8> {
    const BEGIN: &[u8] = b"-----BEGIN ";
    const CERT_LABEL: &[u8] = b"CERTIFICATE-----";
    const END: &[u8] = b"-----END ";
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let Some(rel_begin) = subseq(&bytes[cursor..], BEGIN) else {
            break;
        };
        let begin_start = cursor + rel_begin;
        let Some(rel_eol) = pos(&bytes[begin_start..], b'\n') else {
            break;
        };
        let after_begin = begin_start + rel_eol + 1;
        let Some(rel_end) = subseq(&bytes[after_begin..], END) else {
            break;
        };
        let end_line_start = after_begin + rel_end;
        let block_end = match pos(&bytes[end_line_start..], b'\n') {
            Some(n) => end_line_start + n + 1,
            None => bytes.len(),
        };
        // Only keep CERTIFICATE blocks. Compare the label that immediately
        // follows "-----BEGIN ".
        let label_start = begin_start + BEGIN.len();
        let label_end = label_start + CERT_LABEL.len();
        if label_end <= bytes.len() && &bytes[label_start..label_end] == CERT_LABEL {
            out.extend_from_slice(&bytes[begin_start..block_end]);
        }
        cursor = block_end;
    }
    out
}

fn subseq(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn pos(haystack: &[u8], byte: u8) -> Option<usize> {
    haystack.iter().position(|&b| b == byte)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_drops_non_cert_blocks() {
        let input = b"\
-----BEGIN CERTIFICATE-----
AAAA
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
SECRET
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
BBBB
-----END CERTIFICATE-----
";
        let filtered = filter_non_certificate_blocks(input);
        let s = std::str::from_utf8(&filtered).unwrap();
        assert_eq!(s.matches("BEGIN CERTIFICATE").count(), 2);
        assert_eq!(s.matches("RSA PRIVATE KEY").count(), 0);
        assert_eq!(s.matches("SECRET").count(), 0);
    }

    #[test]
    fn filter_preserves_certs_only() {
        let input = b"\
-----BEGIN CERTIFICATE-----
AAAA
-----END CERTIFICATE-----
";
        let filtered = filter_non_certificate_blocks(input);
        assert_eq!(filtered, input);
    }

    #[test]
    fn filter_handles_empty_input() {
        assert!(filter_non_certificate_blocks(b"").is_empty());
    }

    #[test]
    fn filter_handles_only_non_cert_blocks() {
        let input = b"\
-----BEGIN RSA PRIVATE KEY-----
xxxx
-----END RSA PRIVATE KEY-----
";
        assert!(filter_non_certificate_blocks(input).is_empty());
    }
}
