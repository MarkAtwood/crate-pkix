# Changelog

All notable changes to `pkix-chain` are documented here. The crate
follows [Keep a Changelog](https://keepachangelog.com/) headings and
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added — the sans-I/O verify surface

`pub mod sans_io`: the I/O-free core of chain verification, which a caller
drives itself.

- `ChainBuilder`, `ChainBuildState`, `BuildStep` — AIA reassembly as a
  state machine. `next_step` returns `Built`, `Fetch(uris)` or `Failed`;
  the caller fetches however it likes and folds the results back with
  `absorb`. `build_with` drives the whole loop for a caller whose I/O is
  synchronous.
- `revocation_targets` and `RevocationTarget` — the revocation checks a
  validated chain calls for, as a list. The caller can issue them
  concurrently, which the per-certificate `RevocationChecker` seam cannot.
- `Verifier::chain_builder` — the sans-I/O builder a configured verifier
  describes.

### Why this replaces the planned async twin

The decision recorded under `PKIX-j32w.3` was to grow an async twin of
the DANE-relevant verify entry points. Implementing it surfaced two
problems that decision had not anticipated.

First, `verify_tls_server` performs no validation itself: it reaches
`Verifier::verify_one`, which calls `build_with_aia` and
`run_revocation_checks`. An async path that is async all the way down —
which it must be, or it blocks the executor on revocation and AIA I/O —
therefore needed an async `Verifier` duplicating this crate's whole
orchestration layer. `build_with_aia` is where the AIA bounds live, and
two copies of a *bound* drifting is a security regression rather than a
maintenance annoyance.

Second, the async traits live in the std HTTP adapters, so being generic
over them would have meant `pkix-chain` depending on **two HTTP client
crates** — ureq and reqwest, and transitively tokio — purely to name two
traits. That is backwards for an orchestrator.

Sans-I/O avoids both. `pkix-chain` gains no `async` feature, no
`async-trait`, and no HTTP dependency; there is one copy of the bounds,
and it serves every runtime rather than the one an async twin would have
picked. The question of where the async traits should live dissolves
rather than getting answered — the same move the epic records for
`PKIX-apmt`.

A pre-fetch-everything design was considered first and does not work:
the AIA fetch targets depend on the previous round's results, so a
caller cannot know what to fetch in advance without reimplementing the
caps, the deduplication and the deadline.

### Changed

- `build_with_aia` now delegates to `sans_io::ChainBuilder::build_with`,
  so there is exactly one reassembly loop rather than one per path.
- `run_revocation_checks` now takes its work from
  `sans_io::revocation_targets`, so the sync path and a caller driving
  the checks itself cannot disagree about which certificates need
  checking.

Neither is a behaviour change; the existing AIA tests pass unchanged.

### Testing

`tests/sans_io.rs` drives reassembly from a `tokio` task with no async
trait, no `async-trait` and no HTTP client involved, which is the
property the design exists for. It also asserts the fetch cap, the depth
cap and the once-per-URI rule hold on this path and not only through the
convenience wrapper — a caller driving the loop must inherit the bounds,
not be trusted to reimplement them.


### Added

DANE composition, behind a new default-on `dane` feature.

- `verify_tls_server_dane` — `verify_tls_server` with a domain's TLSA
  records taken into account, covering all four usages.
- `TlsAuthorization` — how a certificate came to be accepted: `Pkix`,
  `PkixConstrained`, `DaneTrustAnchor`, or `DaneEndEntity`.
- `DaneFailurePolicy` (`Opportunistic` by default, or `Strict`) and
  `DaneConfig`, including `DaneConfig::disabled()` as the call-site
  override for pure PKIX in a DANE-enabled binary.
- `Error::Dane`.

### Features

- `dane` is **default-on** and pulls only `pkix-dane`: `no_std`, no I/O,
  no network. The DANE-aware API is therefore present for everyone.
- `dane-resolver` is **off** by default and pulls the DNS stack.
  Separating "DANE by default" from "DNS by default" is deliberate: with
  an opportunistic policy an offline caller would not break, but it
  would pay a failed lookup on *every* verification, which a batch audit
  feels as hours. Offline consumers need no `--no-default-features` to
  avoid that.

### Design notes

- **A separate entry point, not a new parameter.** DANE does not merely
  add a check: usage 2 replaces the trust anchor and usage 3 skips path
  validation entirely.
- **`TlsAuthorization` rather than `ValidatedPath`.** Usage 3 validates
  no path, so there is none to return. Synthesizing one with a
  meaningless `anchor_index` and `depth` would hide exactly the
  distinction a caller needs in order to log, or to apply policy to,
  DANE-authorized connections.
- **Usages are tried strongest-first** — DANE-EE, DANE-TA, PKIX-EE,
  PKIX-TA. RFC 7671 §4.1 makes any match sufficient and prescribes no
  order; strongest-first means a domain publishing usage 3 gets usage-3
  semantics rather than an outcome that depends on the client's trust
  store.
- **A DANE-TA anchor replaces the caller's trust store for that
  validation**, rather than joining it. Merging would implement "DANE-TA
  or any CA", which is weaker than either.
- **`Bogus` fails under every policy** and is not reachable by
  configuration. A knob that let a broken signature fall back to PKIX
  would let an attacker switch DANE off for any domain by corrupting the
  DNS answer.
- **`chain_der` must be the received bytes.** TLSA matching is
  byte-exact and `x509-cert` 0.3 normalizes a pre-2050
  `GeneralizedTime` validity date on re-encode, so re-deriving the bytes
  from the parsed chain would silently fail to match a correctly
  published record. A misaligned `chain_der` is reported rather than
  silently matching fewer certificates.

### Not yet: the async twin

An async `verify_tls_server_dane` is **not** in this release, and the
reason is worth recording because it is larger than it looks. To be
async all the way down — which it must be, or it would block the
executor on revocation and AIA I/O, the defect already open against
`pkix-revocation-http` — it needs an async `Verifier`, because
`verify_tls_server` reaches `Verifier::verify_one`, which calls
`build_with_aia` (~99 lines) and `run_revocation_checks`. That is
duplicating this crate's orchestration layer in async, not adding a
wrapper. Tracked separately.

### Testing

`tests/dane_e2e.rs` runs the composition against PKITS §4.1.1
certificates. Those carry no `dNSName` SAN, which makes one property
easy to demonstrate rather than merely assert: DANE-EE authorizes them
while pure PKIX rejects them on the identical inputs, so the name-check
bypass RFC 7671 §5.1 requires is shown to be real. The fall-through
cases assert the failure came from the PKIX half, which is what proves
the fall-through happened at all.


Planned release: **0.5.0** (breaking: pkix-path 0.4, x509-cert 0.3).

### Added

- Re-exports `VerificationError` and `VerificationErrorKind`, the new
  `SignatureVerifier` error type (**breaking** for implementors: the
  trait no longer returns `signature::Error`).
- `AiaConfig` (`max_depth`, `max_uris_per_cert`, `max_total_fetches`,
  `max_certs_per_response`, `deadline`) and `Verifier::with_aia_config`;
  `Error::AiaFetchLimitExceeded`, `Error::AiaDeadlineExceeded`.
- AIA responses may be a certs-only CMS `SignedData` (RFC 5280 §4.2.2.1).

### Changed

- `SignatureNotVerified` and `PathTooLong` from the supplied ordering fall back to rebuilding from
  the certificates as an unordered bag.
- `AiaDepthExceeded`'s Display text no longer prints the depth.

### Fixed

- AIA chain reassembly followed every caIssuers URI from unvalidated
  certificates with no fetch or time limit (one crafted leaf cost 4160
  fetches). Defaults: 2 URIs per certificate, 8 fetches, 30 s.
- A pool of same-name decoy intermediates (for example appended to an
  S/MIME certificate set) made a valid chain fail with
  `PathBuild(BudgetExceeded)`.
- OCSP responder delegation verified the responder signature over a
  re-encoded TBS that could differ from the signed bytes.
- Docs: `verify_tls_server` does not hardwire the verifier;
  `verify_one` documents the bag rebuild that happens with
  `NoAiaFetcher`.

### Fixed

- **OCSP responder delegation: cryptographic binding now enforced.**
  `verify_ocsp_responder` previously only checked that the responder
  cert's issuer DN equalled the supplied `issuer.subject`. RFC 6960
  §4.2.2.2 requires the responder be issued *directly by* the named CA;
  DN equality alone admits a DN-twin attack in cross-signed CA
  topologies (two CAs with colliding names but different keys), letting
  an attacker who controls one such CA mint a responder cert that
  DN-matches the legitimate issuer but is signed by a different key.
  The wrapper now verifies the responder cert's signature under
  `issuer`'s SPKI directly, in addition to the DN gate. Both failure
  modes still surface as `Error::OcspDelegation` with distinct
  diagnostic `reason` strings. (PKIX-q9hv.3)

### Added

- **AIA chain reassembly.** `Verifier::verify_one` and `verify_chain` now
  follow `id-ad-caIssuers` URIs on the leaf's `AuthorityInfoAccess`
  extension to fetch missing intermediates when the caller-supplied
  chain is incomplete. Fetched DER blobs feed `pkix_path_builder::CertPool`
  and `build_first_valid_path` runs against the augmented pool. The
  fetch loop walks up to `AIA_MAX_DEPTH` (5) levels of missing
  intermediates before surfacing `Error::AiaDepthExceeded`. The fast
  path (positional `pkix_path::validate_path` against a complete chain)
  is unchanged and never invokes the fetcher. (PKIX-zkjb.7)
- New `pub const AIA_MAX_DEPTH: usize = 5` documenting the recursion
  cap.
- `Error::Aia(pkix_aia::AiaError)` variant carrying the underlying AIA
  fetch failure. `Error::PathBuild(pkix_path_builder::Error)` variant
  carrying path-build failures. `Error::AiaDepthExceeded` for the
  iteration cap. All three variants are added behind the existing
  `#[non_exhaustive]` annotation; pattern-matches against the prior
  variants remain valid. (PKIX-zkjb.7)
- `From<pkix_aia::AiaError>` and `From<pkix_path_builder::Error>` impls
  on `Error`.

### Changed

- The `serde` feature now also enables `pkix-path-builder/serde` and
  `pkix-aia/serde` so `Error::PathBuild` and `Error::Aia` round-trip
  through the same wire form as the other `Error` variants (AGENTS.md
  non-negotiable #6). `pkix-aia` is now activated with the `std`
  feature unconditionally so its `core::error::Error` impl on
  `AiaError` is available behind `Error::Aia`.
- The use-case wrappers (`verify_tls_server`, `verify_tls_client_dns`,
  `verify_tls_client_mailbox`, `verify_smime_signer`,
  `verify_smime_recipient`, `verify_code_signer`,
  `verify_time_stamper`, `verify_ocsp_responder`) still bake
  `NoAiaFetcher` internally; their public signatures are unchanged.
  Callers wanting AIA fetching drop down to `verify_chain` or
  `Verifier::new` directly.

### Tested

- End-to-end AIA validation through `pkix-aia-http::HttpFetcher` and a
  `mockito` HTTP server in new `tests/aia_http_e2e.rs`: positive case
  (200 + intermediate DER → chain validates), 404 → `Error::Aia(HttpStatus(404))`,
  `ldap://` URI rewrite → `Error::Aia(UriUnsupported)`, and
  `NoAiaFetcher` short-circuit baseline. (PKIX-zkjb.8)

## [1.0.0] — TBD

First stable release.

### Breaking

- `Verifier` gains a 3rd generic parameter `A: AiaFetcher = NoAiaFetcher`
  (PKIX-zkjb.9, 1.0 API freeze). New field `aia: &'a A`. The
  `Verifier::new` constructor takes a 5th argument `aia: &'a A`; a
  new `Verifier::new_no_aia` convenience constructor wires
  `&NoAiaFetcher` for callers who want the historical behaviour.
  The free function `verify_chain` gains a 6th `aia: &impl
  AiaFetcher` argument; `verify_chain_default` keeps its 4-argument
  shape and internally wires `&NoAiaFetcher`. All eight use-case
  wrappers (`verify_tls_server`, `verify_tls_client_dns`,
  `verify_tls_client_mailbox`, `verify_smime_signer`,
  `verify_smime_recipient`, `verify_code_signer`,
  `verify_time_stamper`, `verify_ocsp_responder`) bake
  `NoAiaFetcher` internally — their signatures are unchanged.
  No actual AIA fetching is invoked anywhere; `NoAiaFetcher` returns
  `AiaError::FetchingDisabled` for every URI, preserving the
  pre-1.0 "caller supplies the complete chain" semantics. The
  point is to lock the API shape at 1.0 so a future point release
  can wire `pkix-aia-http` (PKIX-zkjb.5) through `Verifier`'s 3rd
  generic non-breakingly. Supersedes the "No `AiaFetcher` field
  yet" note in the prior `Verifier` entry below.

### Changed

- `verify_time_stamper` now enforces an RFC 3161 §2.1 #10 KeyUsage
  shape check on the TSA leaf: when the `KeyUsage` extension is
  present it MUST contain only `digitalSignature` and/or
  `nonRepudiation`. Any of `keyEncipherment`, `dataEncipherment`,
  `keyAgreement`, `keyCertSign`, `cRLSign`, `encipherOnly`, or
  `decipherOnly` triggers `Error::ProfileViolation`. Absent
  `KeyUsage` is accepted (RFC 5280 §4.2.1.3 does not require the
  extension on EE certs). This matches OpenSSL `-purpose
  timestampsign` behaviour exactly. The wrapper-level differential
  baseline (`baseline-verify-openssl.md`) now records 5/5 agreement
  with zero known divergences for the time-stamping wrapper.
  (PKIX-7cac.)

### Added

- `Verifier<'a, V, R>` — reusable verifier struct that packages trust
  anchors, signature verifier, revocation checker, and validation
  policy into a single value, exposing `verify_one` (single chain) and
  `verify_batch` (slice of chains) methods. The free function
  `verify_chain` is now a thin wrapper that constructs `Verifier::new`
  and calls `verify_one`; the two paths are byte-equivalent. Existing
  use-case wrappers (`verify_tls_server`, `verify_smime_*`,
  `verify_code_signer`, `verify_time_stamper`) continue to call
  `verify_chain` and route transparently through the new code path.
  Generic parameters (not trait objects) match the pre-existing
  `verify_chain<V, R>` shape; single lifetime `'a`; all fields
  borrowed. No `AiaFetcher` field yet — the trait is undecided per
  PKIX-fmtv.2 closure and will be added when it lands. (PKIX-gsd9.)
- `verify_tls_server` — RFC 6125 server-identity wrapper. Composes
  `verify_chain` with `pkix_identity::verify_dns_name`. Caller pre-parses
  the target hostname with `ServerName::dns_name` /
  `ServerName::ip_address`. Generic over `<P: Profile>` so the caller
  picks `BasicTlsProfile`, `WebPkiProfile`, or a custom profile. Baked
  `DefaultVerifier`. (PKIX-fmtv.11.2.)
- `verify_tls_client_dns` and `verify_tls_client_mailbox` — TLS
  client-auth wrappers with optional identity binding. Both take
  `Option<&ServerName>` / `Option<&MailboxName>`; `None` skips identity
  binding and validates only the path (useful for client-auth flows
  that read the identity from the Subject DN). `Some(_)` runs the
  same RFC 6125 / RFC 5280 §4.2.1.6 binding as the server / S/MIME
  wrappers. The two-function split (over a single `Option<&dyn
  Identity>` API) was decided in PKIX-fmtv.11.2.1 to preserve type
  discipline at the call site. The client-vs-server distinction is
  encoded in the caller-supplied `Profile` (which must require
  `id-kp-clientAuth` for production use — see
  `pkix_profiles::BasicTlsClientProfile`). (PKIX-fmtv.11.2,
  PKIX-uuiz.)
- `verify_smime_signer` and `verify_smime_recipient` — RFC 5280 §4.2.1.6
  / RFC 8398 mailbox-identity wrappers. Compose `verify_chain` with
  `pkix_identity::verify_mailbox`. Caller pre-parses the target mailbox
  with `MailboxName::parse`. Byte-identical bodies; the distinct names
  let callers communicate signer-vs-recipient intent at the call site.
  The KeyUsage distinction (`digitalSignature` for signer,
  `keyEncipherment` for recipient) is encoded in the caller-supplied
  `Profile`. (PKIX-fmtv.12.2.)
- `verify_code_signer` — thin code-signing wrapper. Composes
  `verify_chain` under a profile that requires `id-kp-codeSigning`. No
  identity binding (code signing has no caller-supplied identity
  target). (PKIX-fmtv.13.1.)
- `verify_time_stamper` — RFC 3161 TSA wrapper. Composes `verify_chain`
  with a post-validation check that the leaf's `ExtendedKeyUsage`
  extension is marked critical and contains only `id-kp-timeStamping`
  (RFC 3161 §2.3). (PKIX-fmtv.13.2.)
- `verify_ocsp_responder` — RFC 6960 §4.2.2.2 delegated-responder
  wrapper. Composes `verify_chain` under
  `pkix_profiles::BasicOcspResponderProfile` (which requires
  `id-kp-OCSPSigning` EKU) with two wrapper-side post-validation
  checks: (1) the responder cert at `chain[0]` is delegated by the
  caller-supplied `issuer` cert, verified by RFC 4518 string-prep DN
  equality between `chain[0].tbs.issuer` and `issuer.tbs.subject`; and
  (2) when the responder cert carries `id-pkix-ocsp-nocheck`
  (OID 1.3.6.1.5.5.7.48.1.5, RFC 6960 §4.2.2.2.1), the caller's
  revocation checker is bypassed for `chain[0]` only via a private
  `RevocationChecker` shim that identifies the leaf by (issuer DN,
  serial number). Handles delegated responders only; the CA-direct
  case is documented in the rustdoc with a worked
  `verify_chain`-based example. (PKIX-fmtv.13.3.)
- `Error::OcspDelegation { reason: &'static str }` — new
  non-exhaustive variant produced only by `verify_ocsp_responder` when
  the wrapper's RFC 6960 §4.2.2.2 delegation DN-equality check fails.
  Distinct from `Error::ProfileViolation` so callers can
  programmatically distinguish responder-delegation failures from
  other profile-level rejections. (PKIX-fmtv.13.3.)
- `Error::Identity(IdentityError)` — new non-exhaustive variant wrapping
  `pkix_identity::IdentityError`. Produced by the TLS server and S/MIME
  wrappers when identity binding fails after path validation succeeds.
  Has `From<pkix_identity::IdentityError>` and forwards `Display` and
  `std::error::Error::source` to the inner error. (PKIX-fmtv.11.2 /
  PKIX-fmtv.12.2.)
- `Error::ProfileViolation { reason: &'static str }` — new
  non-exhaustive variant for wrapper-side spec-mandated invariants that
  `ValidationPolicy` cannot express. Currently used by
  `verify_time_stamper` for the RFC 3161 §2.3 critical-and-sole EKU
  rule; future wrappers (`verify_ocsp_responder` delegation, etc.) can
  reuse it. (PKIX-fmtv.13.2.)
- Re-exports of `ServerName`, `MailboxName`, and `IdentityError` from
  `pkix-identity`, and `Profile` from `pkix-path`, so callers do not
  need to add `pkix-identity` or `pkix-profiles` directly to their
  `Cargo.toml` for the common use-case-wrapper invocation pattern.
- Re-exports of `AiaError`, `AiaFetcher`, and `NoAiaFetcher` from
  `pkix-aia` (workspace dep added; PKIX-zkjb.9). Plus the `pkix_aia`
  module re-export so callers can reach into the source crate without
  adding a direct `pkix-aia` dep.
- Integration test fixtures generated by `tests/fixtures/gen.py` via
  pyca/cryptography (P-256, validity 2000-2050) for each wrapper:
  positive case, identity-mismatch / EKU-mismatch / criticality
  negatives, and order-of-checks invariants (path validation runs
  before identity / profile checks).
- Curated RFC 5280 §4.2.1.6 / RFC 8398 mailbox-binding corpus in
  `tests/mailbox_corpus.rs`, exercising `verify_smime_signer` and
  `verify_smime_recipient` against rfc822Name and SmtpUTF8Mailbox SAN
  shapes (ASCII / internationalized / mixed / multi-mailbox /
  malformed) under both `Rfc5280Profile` and `BasicSmimeProfile`. Each
  case asserts identical outcomes from the two wrappers. Pass-rate
  baseline (22/22) and the strict-RFC-5321 local-part case-sensitivity
  decision are documented in `tests/mailbox_corpus_baseline.md`.
  (PKIX-fmtv.23.)
- Curated RFC 6125 hostname-binding corpus in
  `tests/hostname_corpus.rs`, exercising `verify_tls_server` against
  exact-match / wildcard / partial-label / internal-wildcard /
  public-suffix-shape / case-folding / IDN A-label / IDN U-label /
  IPv4 / IPv6 / cross-shape (IPv4-vs-IPv6, DNS-vs-IP) / multi-SAN /
  SAN-absent cases under both `Rfc5280Profile` and `BasicTlsProfile`.
  Pass-rate baseline (27/27) and the wildcard / case-folding / IDN
  / IP-shape decisions are documented in
  `tests/hostname_corpus_baseline.md`. (PKIX-fmtv.22.)
- `der` workspace dep added (was previously transitive) for the
  `verify_time_stamper` post-validation EKU parsing.

### Unchanged

- `verify_chain_default` keeps its 4-argument shape (it wires
  `&NoAiaFetcher` internally).
- All eight use-case wrappers keep their `<P: Profile, R:
  RevocationChecker>` signatures (they bake `&NoAiaFetcher`
  internally, parallel to baking `&DefaultVerifier`).
- `verify_chain` and `verify_chain_default` retain their
  `Result<ValidatedPath, Error>` return shapes; the new wrappers
  compose on top rather than replacing.

## [0.4.0] — 2026-05-08

### Changed (transitively breaking)

- Re-exports `pkix_path::ValidatedPath` which lost `Copy` and `Hash`
  derives in `pkix-path 0.3.0` to make room for the §6.1.5 wrap-up
  outputs (leaf subject DN, issuer DN, serial, SPKI). Bumped to 0.4.0
  even though `pkix-chain`'s own public API was unchanged so downstream
  `cargo update` does not silently apply the `ValidatedPath` shape
  change. See the workspace `CHANGELOG.md` 0.3 follow-up wave entry.

## [0.3.0] — 2026-05-07

Initial published version.
