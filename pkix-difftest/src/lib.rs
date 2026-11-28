//! Shared types and helpers for the `pkix-difftest` differential harness.
//!
//! `pkix-difftest` runs a single cert chain through multiple validators
//! (`pkix-path`, `openssl verify`, `cryptography.x509.verification`) and
//! reports where they agree and disagree. This crate is dev tooling only
//! (`publish = false`); it is `std`-ful and pulls in subprocess + Python
//! bridge machinery that has no place in a library consumer's dependency
//! graph.
//!
//! See the parent bead `PKIX-7nsf` and the in-scope decomposition
//! `PKIX-7nsf.1`–`PKIX-7nsf.8` for full context.
//!
//! That decomposition has landed: the `Chain` loader, all three oracles
//! ([`oracles::pkix_path`], [`oracles::openssl`], [`oracles::pyca`]), the
//! PKITS, PEM-tree and x509-limbo corpus loaders, and the verdict
//! classifier and reporter all ship here.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)] // io::Error sources are obvious from context
#![allow(clippy::module_name_repetitions)]

use std::fmt;
use std::io;
use std::path::Path;

use der::{Decode, Encode};
use x509_cert::Certificate;

pub mod classify;
pub mod corpus;
pub mod oracles;
pub mod report;

/// Lint-domain differential oracles (PKIX-hbzo.1).
///
/// Distinct from [`oracles`], which is the path-validation oracle layer
/// (each oracle answers `(chain) -> Verdict`). The lint-oracle layer answers
/// `(cert_der) -> Vec<NormalizedFinding>` instead — different shape, different
/// vocabulary, different external tools. Feature-gated behind `lint-oracles`
/// because activating it pulls in `pkix-zlint-bridge` (subprocess plumbing)
/// and `pkix-lint-cabf` (in-process reference CA/B Forum lints), neither of
/// which the baseline path-validation CI needs to pay for.
#[cfg(feature = "lint-oracles")]
pub mod lint_oracles;

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

/// What one validator decided about one chain.
///
/// `Fail::reason` is intentionally a free-form `String` because every oracle
/// has its own dialect (OpenSSL stderr lines, pyca exception messages,
/// `pkix_path::Error` `Display` output). The classifier (PKIX-7nsf.5) treats
/// reasons opaquely except when bucketing `DiagnosticDivergence` cases where
/// every validator agreed on Pass/Fail but disagreed on why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail { reason: String },
}

impl Verdict {
    #[must_use]
    pub fn is_pass(&self) -> bool {
        matches!(self, Verdict::Pass)
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Verdict::Pass => f.write_str("Pass"),
            Verdict::Fail { reason } => write!(f, "Fail({reason})"),
        }
    }
}

// ---------------------------------------------------------------------------
// OracleName
// ---------------------------------------------------------------------------

/// Identifier for a validator in the diff harness.
///
/// `OracleName` is deliberately not `#[non_exhaustive]` — adding a new oracle
/// is a real architectural event (new subprocess, new dependency, possibly new
/// CI requirement) that should force every match site to be revisited. We
/// would rather take a compile error than a silent skip.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OracleName {
    /// `pkix_path::validate_path` — the system under test.
    PkixPath,
    /// `openssl verify` subprocess — primary external oracle.
    OpenSsl,
    /// pyca/cryptography `x509.verification.PolicyBuilder` Python sidecar.
    Pyca,
}

impl OracleName {
    /// Whether this oracle can be given the RFC 5280 §6.1.1 initial
    /// inputs a corpus testcase specifies.
    ///
    /// `pkix-path` exposes all four as `ValidationPolicy` fields. The
    /// other two do not, so the harness keeps them out of the comparison
    /// for any chain whose inputs are not the defaults:
    ///
    /// - `openssl verify` has `-policy`, `-explicit_policy`,
    ///   `-policy_check`, `-inhibit_map` and `-inhibit_any`, so it could
    ///   probably comply; nothing wires them up yet.
    /// - pyca's `PolicyBuilder` has no way to express a
    ///   user-initial-policy-set at all.
    #[must_use]
    pub fn honours_policy_inputs(self) -> bool {
        match self {
            Self::PkixPath => true,
            Self::OpenSsl | Self::Pyca => false,
        }
    }

    /// Whether this oracle checks the peer identity a corpus testcase
    /// states, rather than only validating the path.
    ///
    /// An oracle that does not must abstain on a chain that states one,
    /// for the same reason as [`honours_policy_inputs`]: it would answer
    /// "is this path valid" while the corpus asked "is this path valid
    /// for this name", pass a chain built for the wrong name, and show up
    /// as disagreeing with an oracle that got the question right.
    ///
    /// Only the pkix-path oracle checks it today. Both others could:
    /// `openssl verify` has `-verify_hostname` and `-verify_ip`, and
    /// pyca's `PolicyBuilder` takes the subject directly -- so unlike
    /// §6.1.1 policy inputs, this one is wirable for all three rather
    /// than blocked on pyca. Tracked in PKIX-rnsv.
    ///
    /// [`honours_policy_inputs`]: Self::honours_policy_inputs
    #[must_use]
    pub fn honours_peer_identity(self) -> bool {
        match self {
            Self::PkixPath => true,
            Self::OpenSsl | Self::Pyca => false,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            OracleName::PkixPath => "pkix-path",
            OracleName::OpenSsl => "openssl",
            OracleName::Pyca => "pyca",
        }
    }
}

impl fmt::Display for OracleName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Chain
// ---------------------------------------------------------------------------

/// A normalised certificate chain in canonical leaf-first order.
///
/// `certs_der[0]` is the end-entity. `certs_der[len-1]` is the trust anchor
/// (when `root_in_chain` is true) or the topmost issuer present (when false).
///
/// The harness internally always stores chains leaf-first because that is
/// what `pkix_path::validate_path` accepts directly. PKITS gives chains
/// root-first; concatenated PEM bundles in the wild are typically leaf-first
/// (matches `openssl verify`'s argument order). The loader detects the
/// input ordering using a self-issued-cert heuristic and reverses if needed.
///
/// # Revocation
///
/// `crls` carries DER-encoded `CertificateList` blobs (RFC 5280 §5.1) that
/// oracle adapters use for revocation checking. An empty `crls` vector
/// disables revocation in every oracle — the chain is then validated for
/// path correctness only. A non-empty `crls` opts every oracle into RFC 5280
/// §6.3 revocation against the supplied CRLs. Pyca's `PolicyBuilder` has no
/// integrated CRL verifier (verified against cryptography 48.0.0); see
/// `PKIX-emf1.4` for the pyca-side strategy.
///
/// **Limitation**: the harness requires the trust anchor to be
/// present in the chain (it is split off as the anchor when calling
/// `pkix-path`, and used as `-CAfile` for OpenSSL). Real-world TLS chains
/// often omit the root. Lifting this restriction is tracked under PKIX-7nsf.4
/// (corpus loader) — once corpus shapes that omit the root are introduced,
/// the loader will need an out-of-band trust source.
/// The RFC 5280 §6.1.1 initial inputs to path validation, as a corpus
/// testcase specifies them.
///
/// §6.1.1 lists these alongside the certificates as inputs to the
/// algorithm, and a testcase's expected verdict is the answer *under its
/// inputs*. PKITS §4.8, §4.10 and §4.12 drive one certificate bundle
/// repeatedly under different inputs — the "(Subpart N)" suffixes are
/// exactly those repeats — so a verdict produced under the defaults
/// cannot be scored against the expected result of a vector that asked
/// for something else.
///
/// [`Default`] is the RFC 5280 default: `anyPolicy` as the
/// user-initial-policy-set and all three inhibit flags clear. A corpus
/// that has no opinion leaves it at that, so an oracle can honour this
/// unconditionally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialPolicyInputs {
    /// `user-initial-policy-set`. The anyPolicy OID alone means "no
    /// restriction", which is the default.
    pub policy_set: Vec<der::asn1::ObjectIdentifier>,
    /// `initial-policy-mapping-inhibit`.
    pub policy_mapping_inhibit: bool,
    /// `initial-explicit-policy`.
    pub explicit_policy: bool,
    /// `initial-any-policy-inhibit`.
    pub any_policy_inhibit: bool,
}

/// `anyPolicy` (RFC 5280 §4.2.1.4).
pub const ANY_POLICY: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.32.0");

impl Default for InitialPolicyInputs {
    fn default() -> Self {
        Self {
            policy_set: vec![ANY_POLICY],
            policy_mapping_inhibit: false,
            explicit_policy: false,
            any_policy_inhibit: false,
        }
    }
}

impl InitialPolicyInputs {
    /// Whether these are the RFC 5280 defaults.
    ///
    /// An oracle that cannot express §6.1.1 inputs can still be given a
    /// chain whose inputs are the defaults, because that is what it
    /// implicitly applies. The harness uses this to decide whether such
    /// an oracle may vote on a chain at all.
    #[must_use]
    pub fn is_rfc5280_default(&self) -> bool {
        self.policy_set.as_slice() == [ANY_POLICY]
            && !self.policy_mapping_inhibit
            && !self.explicit_policy
            && !self.any_policy_inhibit
    }
}

#[derive(Clone, Debug)]
pub struct Chain {
    /// Leaf-first DER-encoded certificates.
    pub certs_der: Vec<Vec<u8>>,
    /// DER-encoded `CertificateList` blobs (RFC 5280 §5.1) that oracle
    /// adapters apply for revocation checking. Empty disables revocation.
    /// Populated by corpus loaders (PKITS, limbo, pem-tree) when the source
    /// testcase ships CRLs.
    pub crls: Vec<Vec<u8>>,

    /// Certificates in the source bundle that are **not** links in
    /// [`certs_der`](Self::certs_der)'s signature chain.
    ///
    /// Path building reduces a bundle to one chain and drops everything that
    /// is not a link in it. Several PKITS §4.4 and §4.5 vectors ship a CA's
    /// dedicated *CRL-signing* certificate exactly that way — a sibling of
    /// the chain, and the only certificate that verifies the CRL's signature.
    ///
    /// Dropping it makes CRL signer discovery impossible for those vectors, so
    /// a certificate whose CRL was signed by another of the CA's keys reports
    /// `CrlSignatureInvalid` and its revocation status reads as undetermined.
    ///
    /// Empty for corpora that do not reduce a bundle, and empty when path
    /// building falls back to plain reversal.
    pub aux_certs_der: Vec<Vec<u8>>,
    /// True when the last cert is intended as the trust anchor.
    /// Always true currently — see the type-level docs.
    pub root_in_chain: bool,
    /// Human-readable label, e.g. the source filename or PKITS test name.
    /// Used only for reporting.
    pub label: String,
    /// Per-chain validation time as Unix seconds. When `Some(secs)`, every
    /// oracle pins its clock to that instant so a chain with a fixed validity
    /// window verifies the same way at every wall-clock moment. When `None`,
    /// each oracle uses its own current-time default (system clock for
    /// pkix-path, OpenSSL's internal clock for openssl, `datetime.now(utc)`
    /// for the pyca sidecar). PKITS and pem-tree loaders set `None`; the
    /// limbo loader (PKIX-g9vc.2) sets `Some` from each testcase's
    /// `validation_time` field.
    pub validation_time_unix: Option<u64>,

    /// The RFC 5280 §6.1.1 initial inputs this chain is to be validated
    /// under. [`InitialPolicyInputs::default()`] for corpora that do not
    /// vary them; the PKITS loader sets it from each vector's four
    /// `Initial*` fields.
    pub initial_policy_inputs: InitialPolicyInputs,

    /// The identities the peer certificate is required to present, as
    /// RFC 6125 §6 reference identifiers.
    ///
    /// A chain is only half a question: "is this path valid" and "does
    /// the leaf speak for the name I asked for" are separate checks, and
    /// a corpus that states an expected peer name is asking the second
    /// one too. x509-limbo states it per testcase
    /// (`expected_peer_name`), and whole suites inside it -- `BetterTLS`'s
    /// `nameconstraints` in particular -- turn on nothing else: the
    /// chain is structurally valid and the expected failure is the
    /// requested name falling outside the CA's permitted subtrees.
    ///
    /// Empty means the corpus states no identity and the oracle checks
    /// the path alone. Every entry must match for the chain to pass:
    /// limbo's plural `expected_peer_names` lists identities a verifier
    /// is required to accept, so one that fails is a failure of the
    /// testcase.
    pub expected_peer_names: Vec<String>,
}

impl Chain {
    /// Load a chain from a concatenated-PEM file.
    pub fn from_pem_file(path: &Path) -> io::Result<Self> {
        let bytes = std::fs::read(path)?;
        Self::from_pem_bytes(&bytes, path.display().to_string())
    }

    /// Load a chain from in-memory concatenated PEM bytes.
    pub fn from_pem_bytes(bytes: &[u8], label: String) -> io::Result<Self> {
        let blocks = split_pem_blocks(bytes)?;
        if blocks.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "no PEM CERTIFICATE blocks found",
            ));
        }

        // Decode each block's DER and parse as Certificate so we can later
        // examine subject/issuer for the ordering heuristic. We keep both the
        // raw DER (what oracles need) and the parsed cert (what the heuristic
        // needs) side by side.
        let mut der_blocks: Vec<Vec<u8>> = Vec::with_capacity(blocks.len());
        let mut parsed: Vec<Certificate> = Vec::with_capacity(blocks.len());
        for block in &blocks {
            let (block_label, der) = pem_rfc7468::decode_vec(block).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("PEM decode failed: {e}"),
                )
            })?;
            // Reject non-cert blocks loudly. A chain.pem with a private key
            // mixed in is a configuration bug we should surface early, not
            // silently skip.
            if block_label != "CERTIFICATE" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("expected CERTIFICATE PEM block, got {block_label}"),
                ));
            }
            let cert = Certificate::from_der(&der).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("certificate DER parse failed: {e}"),
                )
            })?;
            der_blocks.push(der);
            parsed.push(cert);
        }

        let leaf_first = detect_leaf_first(&parsed)?;
        if !leaf_first {
            der_blocks.reverse();
        }

        Ok(Chain {
            // A bare PEM bundle states no peer identity and no §6.1.1
            // inputs.
            expected_peer_names: Vec::new(),
            initial_policy_inputs: InitialPolicyInputs::default(),
            aux_certs_der: Vec::new(),
            certs_der: der_blocks,
            crls: Vec::new(),
            root_in_chain: true,
            label,
            validation_time_unix: None,
        })
    }

    /// Attach a CRL bundle to this chain.
    ///
    /// Builder method: consumes `self`, returns a new `Chain` whose `crls`
    /// field is replaced with the supplied DER-encoded `CertificateList`
    /// bytes. An empty `crls` argument is equivalent to leaving the chain
    /// unchanged (oracles skip revocation when `crls` is empty).
    ///
    /// Use this from corpus loaders that have already constructed a `Chain`
    /// and now want to layer CRL bytes on top (typical pattern for the PKITS
    /// loader, where chain certs and CRLs come from sibling directories).
    #[must_use]
    pub fn with_crls(mut self, crls: Vec<Vec<u8>>) -> Self {
        self.crls = crls;
        self
    }

    /// Pin this chain's validation time.
    ///
    /// Builder method: consumes `self`, returns a new `Chain` whose
    /// `validation_time_unix` is set to `Some(secs)`. Every oracle that
    /// consumes the chain uses this instant instead of its current-time
    /// default. Use from corpus loaders that ship per-testcase clocks
    /// (limbo's `validation_time` field, RFC 3339 in the source data).
    #[must_use]
    pub fn with_validation_time(mut self, secs: u64) -> Self {
        self.validation_time_unix = Some(secs);
        self
    }
}

/// Detect whether a parsed chain is in leaf-first order.
///
/// Heuristic: in a leaf-first chain, the **last** cert is self-issued
/// (it's the trust anchor). In a root-first chain, the **first** cert is
/// self-issued. We use byte-equal DN comparison (RFC 5280 §3.2 self-issued
/// definition + §6.1 standard byte-equality fallback). RFC 4518 string-prep
/// is not applied here because (a) ordering detection is a heuristic, not a
/// security gate, and (b) PKITS and pyca corpora do not exercise §4518
/// equivalence on the root cert's subject == issuer.
///
/// Errors when the chain has 0 certs or when both ends are self-issued or
/// neither end is self-issued — those are corpus-quality problems the user
/// should fix or filter out at corpus-load time.
fn detect_leaf_first(certs: &[Certificate]) -> io::Result<bool> {
    if certs.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty chain"));
    }
    if certs.len() == 1 {
        // Single cert: leaf == root. There is no ordering to detect.
        // Return Ok(true) so the (unchanged) single-element vec is the
        // "canonical leaf-first" form. The pkix-path oracle will reject
        // this with a length error anyway.
        return Ok(true);
    }
    let first_si = is_self_issued(&certs[0]);
    let last_si = is_self_issued(&certs[certs.len() - 1]);
    match (first_si, last_si) {
        (false, true) => Ok(true),
        (true, false) => Ok(false),
        (false, false) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "chain ordering ambiguous: neither end is self-issued (root not in chain?)",
        )),
        (true, true) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "chain ordering ambiguous: both ends are self-issued",
        )),
    }
}

/// Byte-wise self-issued check.
///
/// RFC 5280 §3.2 says a cert is self-issued when subject and issuer DNs are
/// the same. The strict-byte-equal comparison here matches what both pkix-path
/// and OpenSSL do internally for the chain-walk's "is this self-issued?"
/// branch (§6.1.4(b) self-issued cert handling). It does NOT match what
/// pyca/cryptography does (which applies more aggressive normalisation), but
/// the only consequence is that the heuristic gives an ambiguity error on
/// the rare DN-only-equal-modulo-encoding chain — at which point the caller
/// can pre-normalise the input or store ordering out-of-band.
fn is_self_issued(cert: &Certificate) -> bool {
    let subj = cert.tbs_certificate().subject().to_der();
    let issuer = cert.tbs_certificate().issuer().to_der();
    matches!((subj, issuer), (Ok(s), Ok(i)) if s == i)
}

/// Split concatenated PEM into individual encapsulated-message slices.
///
/// `pem-rfc7468` 0.7 only decodes a single block per call (per upstream
/// `decoder.rs:153` comment). For multi-cert bundles we split here and then
/// hand each block to `decode_vec`. We deliberately do not import any
/// Boyer-Moore / memchr helper — the input is small (cert bundles are
/// kilobytes, not megabytes) and the simple windowed scan is plenty fast.
///
/// Return value contains slices into `bytes` covering each
/// `-----BEGIN ...-----\n...-----END ...-----\n` region. Trailing
/// whitespace / preamble between blocks is allowed and skipped.
fn split_pem_blocks(bytes: &[u8]) -> io::Result<Vec<&[u8]>> {
    const BEGIN: &[u8] = b"-----BEGIN ";
    const END: &[u8] = b"-----END ";

    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let Some(rel_begin) = find_subseq(&bytes[cursor..], BEGIN) else {
            break;
        };
        let block_start = cursor + rel_begin;
        // Find newline ending the BEGIN line.
        let Some(rel_eol) = find_byte(&bytes[block_start..], b'\n') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed PEM: BEGIN line has no terminating newline",
            ));
        };
        let after_begin = block_start + rel_eol + 1;
        // Find the matching END marker.
        let Some(rel_end) = find_subseq(&bytes[after_begin..], END) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed PEM: BEGIN block has no matching END marker",
            ));
        };
        let end_line_start = after_begin + rel_end;
        // Tolerate missing trailing newline on the last block (POSIX habit).
        let block_end = match find_byte(&bytes[end_line_start..], b'\n') {
            Some(n) => end_line_start + n + 1,
            None => bytes.len(),
        };
        out.push(&bytes[block_start..block_end]);
        cursor = block_end;
    }
    Ok(out)
}

fn find_subseq(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn find_byte(haystack: &[u8], byte: u8) -> Option<usize> {
    haystack.iter().position(|&b| b == byte)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_pem_blocks_rejects_block_with_no_end() {
        let bytes = b"-----BEGIN CERTIFICATE-----\nAAAA\n";
        let err = split_pem_blocks(bytes).unwrap_err();
        assert!(err.to_string().contains("END"));
    }

    #[test]
    fn split_pem_blocks_handles_two_blocks() {
        let bytes = b"\
-----BEGIN CERTIFICATE-----
AAAA
-----END CERTIFICATE-----
preamble text between blocks
-----BEGIN CERTIFICATE-----
BBBB
-----END CERTIFICATE-----
";
        let blocks = split_pem_blocks(bytes).unwrap();
        assert_eq!(blocks.len(), 2);
    }

    #[test]
    fn split_pem_blocks_tolerates_no_trailing_newline() {
        // No trailing \n on the END line. Many real-world PEM bundles end
        // exactly on -----END CERTIFICATE----- with no terminating newline.
        let bytes = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----";
        let blocks = split_pem_blocks(bytes).unwrap();
        assert_eq!(blocks.len(), 1);
    }

    #[test]
    fn split_pem_blocks_empty_input() {
        let blocks = split_pem_blocks(b"").unwrap();
        assert!(blocks.is_empty(), "expected empty, got {blocks:?}");
    }

    #[test]
    fn verdict_display() {
        assert_eq!(Verdict::Pass.to_string(), "Pass");
        assert_eq!(Verdict::Fail { reason: "x".into() }.to_string(), "Fail(x)");
    }

    #[test]
    fn oracle_name_str() {
        assert_eq!(OracleName::PkixPath.as_str(), "pkix-path");
        assert_eq!(OracleName::OpenSsl.as_str(), "openssl");
        assert_eq!(OracleName::Pyca.as_str(), "pyca");
    }

    #[test]
    fn chain_with_crls_attaches_bundle() {
        // Build a Chain via the public constructor path, then layer CRL
        // bytes on top via with_crls. Verify (a) the empty default and
        // (b) the post-attach state.
        //
        // We do not need a real CRL DER here — the field is a Vec<Vec<u8>>
        // with no parsing contract at the harness layer. Oracles parse it.
        let chain = Chain {
            expected_peer_names: Vec::new(),
            initial_policy_inputs: InitialPolicyInputs::default(),
            aux_certs_der: Vec::new(),
            certs_der: vec![vec![0u8; 4], vec![1u8; 4]],
            crls: Vec::new(),
            root_in_chain: true,
            label: "test".to_string(),
            validation_time_unix: None,
        };
        assert!(chain.crls.is_empty(), "default crls must be empty");

        let crl_der_a = vec![0xAAu8; 8];
        let crl_der_b = vec![0xBBu8; 8];
        let chain = chain.with_crls(vec![crl_der_a.clone(), crl_der_b.clone()]);
        assert_eq!(chain.crls.len(), 2, "with_crls must populate the field");
        assert_eq!(chain.crls[0], crl_der_a);
        assert_eq!(chain.crls[1], crl_der_b);

        // Idempotency / overwrite: with_crls(empty) restores the no-revocation
        // state. The builder is replace-semantics, not append-semantics.
        let chain = chain.with_crls(Vec::new());
        assert!(
            chain.crls.is_empty(),
            "with_crls(empty) must reset to no revocation"
        );
    }
}
