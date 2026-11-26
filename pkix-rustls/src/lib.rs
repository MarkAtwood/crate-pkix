#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! Use PKIX path validation as [`rustls`]'s certificate verifier.
//!
//! rustls asks one question of a certificate chain — *should I trust
//! this?* — and answers it by default with `rustls-webpki`. This crate
//! answers it with [`pkix_chain`] instead, which is the whole of what it
//! does.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use std::sync::Arc;
//! use pkix_rustls::PkixServerCertVerifier;
//!
//! // Trust anchors come from wherever you get them — this crate ships
//! // none, and neither does the rest of the workspace.
//! let anchors: Vec<pkix_chain::TrustAnchor> = vec![];
//!
//! // The verifier needs no CryptoProvider; rustls still needs one for
//! // the rest of TLS.
//! let verifier = PkixServerCertVerifier::new(anchors);
//!
//! let provider = Arc::new(rustls::crypto::ring::default_provider());
//! let config = rustls::ClientConfig::builder_with_provider(provider)
//!     .with_safe_default_protocol_versions()?
//!     .dangerous()
//!     .with_custom_certificate_verifier(Arc::new(verifier))
//!     .with_no_client_auth();
//! # let _ = config;
//! # Ok(())
//! # }
//! ```
//!
//! # What this replaces, and what it does not
//!
//! rustls's verifier trait covers three jobs, and only the first is a
//! PKI question:
//!
//! - **The certificate chain.** Answered here, by
//!   [`pkix_chain::verify_tls_server`]: path construction, signatures,
//!   validity, name constraints, policies, profile rules, revocation if
//!   you configure it, and RFC 6125 name matching.
//! - **The TLS 1.2 and 1.3 handshake signatures.** Not a PKI question
//!   in itself — it is the peer proving possession of the key in the
//!   certificate. But rustls's helper for it parses the certificate
//!   with webpki to extract that key, so delegating meant a second
//!   X.509 parser touching the same bytes. Done here instead, with
//!   this workspace's parser and [`pkix_path::SignatureVerifier`]; see
//!   the [`handshake`] module for what the TLS schemes require beyond
//!   an X.509 OID.
//! - **Which signature schemes to advertise.** Consequently ours, and
//!   exactly the set the handshake code implements.
//!
//! This crate still does not implement any cryptography: key exchange,
//! AEAD, HKDF and the TLS state machine are all rustls's, and the
//! signature primitives are `pkix-path`'s existing backends. What it
//! replaces is the trust decision and the certificate parsing that
//! feeds it.
//!
//! # What about `rustls-webpki`?
//!
//! It is still in the dependency tree, and nothing this crate can do
//! will remove it. rustls 0.23 depends on it unconditionally — not
//! behind a feature — because its crypto-provider API is built on
//! webpki's signature-algorithm types, which the handshake path uses
//! whatever verifier is installed.
//!
//! What changes is that none of it runs. With this verifier installed
//! webpki performs no path validation, no name matching, no trust
//! decision — and, since the handshake signatures are verified here
//! too, it does not parse the certificate either. The two live paths
//! into it are the default verifier, which is not installed, and
//! rustls's signature helpers, which are not called. It is linked and
//! dead.
//!
//! Getting it out of the tree altogether would take an upstream change
//! making the dependency optional, which is rustls's call and not
//! something a verifier can reach.
//!
//! # Errors keep their reason
//!
//! rustls's [`CertificateError`] is narrower than
//! [`pkix_chain::Error`], so some distinctions have nowhere to go. Every
//! error that maps onto a rustls variant gets it — `Expired`,
//! `NotValidYet`, `Revoked`, `UnknownIssuer`, `BadSignature`,
//! `NotValidForName` and the rest — and every error that does not is
//! carried intact inside [`CertificateError::Other`], which exists for
//! this purpose. Nothing is flattened into a generic failure, so an
//! application can still recover exactly why a chain was refused:
//!
//! ```no_run
//! # use rustls::CertificateError;
//! # fn f(e: rustls::Error) {
//! if let rustls::Error::InvalidCertificate(CertificateError::Other(other)) = &e {
//!     if let Some(ours) = other.0.downcast_ref::<pkix_chain::Error>() {
//!         eprintln!("pkix says: {ours}");
//!     }
//! }
//! # }
//! ```

use std::sync::Arc;

use der::Decode as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName as RustlsServerName, UnixTime};
use x509_cert::Certificate;

use pkix_chain::{
    AiaFetcher, DefaultVerifier, NoAiaFetcher, NoRevocation, Profile, RevocationChecker,
    SignatureVerifier, TrustAnchor,
};

mod error;
/// Verifying the TLS handshake signature with this workspace's parser
/// and crypto rather than rustls's helper. See the module
/// documentation for why.
pub mod handshake;

pub use error::map_error;
pub use handshake::CurveMismatch;

/// A rustls [`ServerCertVerifier`] that validates chains with
/// [`pkix_chain`].
///
/// Generic over the four things [`pkix_chain::verify_tls_server`] is
/// generic over, so nothing this workspace can express is shut out:
/// the signature backend, the certificate profile, the revocation
/// checker and the AIA fetcher. [`PkixServerCertVerifier::new`] fills
/// them with defaults for the common case; [`PkixServerCertVerifier::builder`]
/// replaces any of them.
#[derive(Debug, Clone)]
pub struct PkixServerCertVerifier<
    V = DefaultVerifier,
    P = pkix_profiles::BasicTlsProfile,
    R = NoRevocation,
    A = NoAiaFetcher,
> {
    anchors: Vec<TrustAnchor>,
    verifier: V,
    profile: P,
    revocation: R,
    aia: A,
}

impl PkixServerCertVerifier {
    /// Build a verifier over `anchors` with this workspace's defaults:
    /// [`DefaultVerifier`] for signatures,
    /// [`pkix_profiles::BasicTlsProfile`] for the certificate profile
    /// (RFC 5280 plus RFC 6125 plus the serverAuth EKU), and no
    /// revocation or AIA fetching.
    ///
    /// No [`rustls::crypto::CryptoProvider`] is needed. The handshake
    /// signatures are verified with `verifier` too, so nothing here
    /// defers to rustls's crypto and there is no provider to keep in
    /// step with the one the `ClientConfig` was built from.
    ///
    /// Revocation is off because a revocation checker needs a source of
    /// CRLs or OCSP responses, and silently having none would be worse
    /// than saying so. Add one with
    /// [`builder`](PkixServerCertVerifier::builder).
    #[must_use]
    pub fn new(anchors: Vec<TrustAnchor>) -> Self {
        Self {
            anchors,
            verifier: DefaultVerifier,
            profile: pkix_profiles::BasicTlsProfile,
            revocation: NoRevocation,
            aia: NoAiaFetcher,
        }
    }

    /// Start from the defaults of [`new`](PkixServerCertVerifier::new)
    /// and replace individual pieces.
    #[must_use]
    pub fn builder(anchors: Vec<TrustAnchor>) -> Self {
        Self::new(anchors)
    }
}

impl<V, P, R, A> PkixServerCertVerifier<V, P, R, A> {
    /// Use a different signature backend — `ring`, say, instead of
    /// RustCrypto.
    #[must_use]
    pub fn with_signature_verifier<V2>(self, verifier: V2) -> PkixServerCertVerifier<V2, P, R, A> {
        PkixServerCertVerifier {
            anchors: self.anchors,
            verifier,
            profile: self.profile,
            revocation: self.revocation,
            aia: self.aia,
        }
    }

    /// Use a different certificate profile — the CA/Browser Forum TLS
    /// Baseline Requirements, say, instead of bare RFC 5280.
    #[must_use]
    pub fn with_profile<P2>(self, profile: P2) -> PkixServerCertVerifier<V, P2, R, A> {
        PkixServerCertVerifier {
            anchors: self.anchors,
            verifier: self.verifier,
            profile,
            revocation: self.revocation,
            aia: self.aia,
        }
    }

    /// Check revocation. Without this nothing is checked, and a revoked
    /// certificate verifies.
    #[must_use]
    pub fn with_revocation<R2>(self, revocation: R2) -> PkixServerCertVerifier<V, P, R2, A> {
        PkixServerCertVerifier {
            anchors: self.anchors,
            verifier: self.verifier,
            profile: self.profile,
            revocation,
            aia: self.aia,
        }
    }

    /// Fetch missing intermediates over AIA.
    #[must_use]
    pub fn with_aia<A2>(self, aia: A2) -> PkixServerCertVerifier<V, P, R, A2> {
        PkixServerCertVerifier {
            anchors: self.anchors,
            verifier: self.verifier,
            profile: self.profile,
            revocation: self.revocation,
            aia,
        }
    }
}

impl<V, P, R, A> ServerCertVerifier for PkixServerCertVerifier<V, P, R, A>
where
    V: SignatureVerifier + std::fmt::Debug + Send + Sync,
    P: Profile + std::fmt::Debug + Send + Sync,
    R: RevocationChecker + std::fmt::Debug + Send + Sync,
    A: AiaFetcher + std::fmt::Debug + Send + Sync,
{
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &RustlsServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        // `_ocsp_response` is the stapled response from the handshake.
        // Using it needs a revocation checker that accepts a
        // caller-supplied response rather than fetching its own, which
        // is a separate piece of work; ignoring it is what rustls does
        // when no revocation checking is configured, and it is never
        // the reason a chain is accepted.
        let mut chain = Vec::with_capacity(1 + intermediates.len());
        for der in std::iter::once(end_entity).chain(intermediates) {
            chain.push(
                Certificate::from_der(der)
                    .map_err(|_| RustlsError::InvalidCertificate(CertificateError::BadEncoding))?,
            );
        }

        let name = convert_server_name(server_name)?;

        pkix_chain::verify_tls_server(
            &chain,
            &self.anchors,
            &name,
            &self.profile,
            now.as_secs(),
            &self.verifier,
            &self.revocation,
            &self.aia,
        )
        .map_err(|e| RustlsError::InvalidCertificate(map_error(e, &chain, now.as_secs())))?;

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        handshake::verify(
            &self.verifier,
            message,
            cert,
            dss.scheme,
            dss.signature(),
            handshake::Protocol::Tls12,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        handshake::verify(
            &self.verifier,
            message,
            cert,
            dss.scheme,
            dss.signature(),
            handshake::Protocol::Tls13,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // What this crate can actually verify, not what the provider
        // can: the handshake signatures no longer go through the
        // provider, so advertising its list would offer the peer
        // schemes that would then be refused.
        handshake::SUPPORTED_SCHEMES.to_vec()
    }
}

/// Convert the name rustls is connecting to into the one
/// [`pkix_chain::verify_tls_server`] matches against.
///
/// [`rustls_pki_types::ServerName`] is `#[non_exhaustive]`, so a future
/// rustls can name a kind of peer this crate has never heard of. That
/// arm refuses rather than falling through to something permissive: not
/// knowing what kind of name was asked for means the name check cannot
/// be performed at all, and a verifier that cannot perform its check
/// must not return success.
fn convert_server_name(
    name: &RustlsServerName<'_>,
) -> Result<pkix_identity::ServerName<'static>, RustlsError> {
    let as_str = match name {
        RustlsServerName::DnsName(dns) => dns.as_ref().to_owned(),
        // An IP literal, rendered textually; `ServerName::parse`
        // recognises both v4 and v6 forms.
        RustlsServerName::IpAddress(_) => name.to_str().into_owned(),
        _ => {
            return Err(RustlsError::InvalidCertificate(CertificateError::Other(
                rustls::OtherError(Arc::new(UnsupportedServerName)),
            )))
        }
    };

    pkix_identity::ServerName::parse(&as_str)
        .map(pkix_identity::ServerName::into_owned)
        .map_err(|e| {
            RustlsError::InvalidCertificate(CertificateError::Other(rustls::OtherError(Arc::new(
                e,
            ))))
        })
}

/// rustls asked about a kind of server name this crate does not know.
///
/// Reachable only if a future `rustls-pki-types` adds a
/// [`rustls_pki_types::ServerName`] variant, since the enum is
/// `#[non_exhaustive]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedServerName;

impl std::fmt::Display for UnsupportedServerName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "rustls supplied a ServerName variant this version of pkix-rustls \
             does not recognise, so the name could not be checked",
        )
    }
}

impl std::error::Error for UnsupportedServerName {}
