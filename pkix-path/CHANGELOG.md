# Changelog

All notable changes to `pkix-path` are documented here. The crate
follows [Keep a Changelog](https://keepachangelog.com/) headings and
[Semantic Versioning](https://semver.org/).

## [Unreleased]

_Nothing yet._

## [1.0.0] — TBD

First stable release.

### Added

- Leaf-only `ValidationPolicy::required_leaf_policy_oids:
  Option<Vec<ObjectIdentifier>>` (PKIX-jbvb.4). When `Some`, the leaf
  must explicitly assert every OID via `CertificatePolicies`.
  `anyPolicy` does NOT satisfy a specific OID. Distinct from
  `initial_policy_set` (relying party's acceptable set) — this checks
  *assertion*. Violations produce the new
  `Error::MissingLeafPolicyOid { required: ObjectIdentifier }`.
  Defaults to `None`; existing callers see no behavior change.
- Leaf-only `ValidationPolicy::required_leaf_subject_dn_attrs:
  Option<DnAttrRule>` (PKIX-jbvb.4). When `Some`, the leaf's Subject DN
  must satisfy the rule. Violations produce the new
  `Error::SubjectDnAttrRuleUnmet`. Defaults to `None`.
- Public enum `DnAttrRule` (`#[non_exhaustive]`): `Field(ObjectIdentifier)`,
  `AllOf(Vec<DnAttrRule>)`, `AnyOf(Vec<DnAttrRule>)`. Derives `Clone +
  Debug + PartialEq + Eq`. Vacuity: `AllOf(vec![])` is trivially true,
  `AnyOf(vec![])` is trivially false. Designed to express CA/B Forum
  S/MIME BR tier rules such as `pseudonym OR (givenName AND surname)`.
  Enforcement lives at the leaf in `chain_walk` adjacent to
  `required_leaf_eku` (steps `(e3a)` and `(e3b)`).
- `Error::MissingLeafPolicyOid { required: ObjectIdentifier }` and
  `Error::SubjectDnAttrRuleUnmet` variants (additive under
  `#[non_exhaustive]`).
- Optional `serde` feature (PKIX-2l0v.1). Derives `Serialize` /
  `Deserialize` on `ValidatedPath`, `ValidationPolicy`, `TrustAnchor`,
  `PolicyTreeNode`, `DnAttrRule`, `Error`, `DerError`. New public
  module `serde_der` exposes format-adaptive (de)serializer helpers
  for downstream use. The wire form is format-adaptive: human-readable
  serializers (JSON, TOML, YAML) emit base64-encoded DER for fields
  backed by foreign DER types; binary serializers (postcard, bincode,
  MessagePack) emit raw DER bytes. New crate-level dep on `base64ct`
  (no_std, MSRV-friendly, RustCrypto-family).
- `Send + Sync` compile-time assertions on `ValidatedPath`, `Error`,
  `TrustAnchor`, and `ValidationPolicy` (PKIX-2l0v.2).
- `ValidationPolicy::require_crl_sign_on_cas: bool` (default `false`)
  (PKIX-0x9z). When `true`, an intermediate CA certificate whose
  `KeyUsage` extension is present but does not include `cRLSign` is
  rejected with the new `Error::CrlSignMissing { index }` variant.
  Default behaviour is unchanged (the RFC 5280 §6.1 literal reading
  does not require this check). Restores PKITS §4.7.4 / §4.7.5
  conformance for callers who opt in.
- `Error::CrlSignMissing { index: usize }` variant (additive under
  `#[non_exhaustive]`).
- ECDSA P-384 + SHA-384 `SignatureVerifier` (`EcdsaP384Verifier`)
  behind the new `p384` feature (PKIX-gphz.2). `DefaultVerifier`
  dispatches OID 1.2.840.10045.4.3.3 (ecdsa-with-SHA384, RFC 5758
  §3.2). The `rustcrypto` umbrella feature now pulls
  `p256 + p384 + rsa`.
- RSA-PKCS1v15 SHA-384 and SHA-512 `SignatureVerifier`s
  (`RsaPkcs1v15Sha384Verifier`, `RsaPkcs1v15Sha512Verifier`) behind
  the existing `rsa` feature (PKIX-gphz.4). `DefaultVerifier`
  dispatches OIDs 1.2.840.113549.1.1.12 (sha384WithRSAEncryption)
  and 1.2.840.113549.1.1.13 (sha512WithRSAEncryption).
- Integration tests under `pkix-path/tests/` now gated by feature
  attributes matching `DefaultVerifier`'s
  `any(feature = "p256", feature = "p384", feature = "rsa")` shape
  (PKIX-yg2r). `cargo test -p pkix-path --no-default-features` now
  compiles cleanly (yielding an empty test suite per integration
  test crate, which is the intended behaviour when no algorithm
  backend is enabled).
- Updated top-level `# Limitations` rustdoc section now that P-384
  has shipped; only Ed25519, P-521, RSA-PSS, and SHA-1 legacy
  algorithms remain (tracked under PKIX-gphz children). Cross-
  references PKIX-l63j (full RFC 4518 DN normalization).
  (PKIX-wlsr.6.)

## [0.3.1] — 2026-06-04

### Added

- ECDSA P-384 + SHA-384 `SignatureVerifier` (`EcdsaP384Verifier`)
  behind the new `p384` feature (PKIX-gphz.2). `DefaultVerifier`
  dispatches OID 1.2.840.10045.4.3.3 (ecdsa-with-SHA384, RFC 5758
  §3.2). The `rustcrypto` umbrella feature now pulls
  `p256 + p384 + rsa`.
- RSA-PKCS1v15 SHA-384 and SHA-512 `SignatureVerifier`s
  (`RsaPkcs1v15Sha384Verifier`, `RsaPkcs1v15Sha512Verifier`) behind
  the existing `rsa` feature (PKIX-gphz.4). `DefaultVerifier`
  dispatches OIDs 1.2.840.113549.1.1.12 (sha384WithRSAEncryption)
  and 1.2.840.113549.1.1.13 (sha512WithRSAEncryption).
- Integration tests gated by feature attributes matching
  `DefaultVerifier`'s algorithm dispatch (PKIX-yg2r).

## [0.3.0] — 2026-05-08

### Added — RFC 5280 §6.1.2(a) policy qualifier processing

- `ValidatedPath::valid_policy_tree: Option<Vec<PolicyTreeNode>>` —
  the final §6.1.5 valid_policy_tree, or `None` if reduced to NULL
  during validation. Each node carries the policy qualifiers
  attached to it at creation time, sourced per RFC 5280 §6.1.3(d)
  and §6.1.4(b)(1) (PKIX-an8h).
- Public struct `PolicyTreeNode` (`#[non_exhaustive]`) mirroring
  the internal `PolicyNode`. Fields: `depth`, `valid_policy`,
  `expected_policy_set`, `qualifiers`. Qualifiers are exposed as the
  upstream `x509_cert::ext::pkix::certpolicy::PolicyQualifierInfo`
  raw `(qualifier_id_oid, raw_any_value)` pair; decoding the `Any`
  content to `CpsUri` / `UserNotice` is left to the caller because
  `x509-cert 0.2.5` has a typo on `UserNotice.notice_ref`.
- `ValidatedPath::policy_qualifiers()` convenience iterator yielding
  `(&policy_oid, &PolicyQualifierInfo)` pairs across every tree
  node. Empty iterator when the tree is `None`.

  Path validation does NOT gate on qualifier validity — RFC 5280
  §6.1.2(a) explicitly says qualifier processing is application-
  specific. The new fields are pure read-side outputs.

### Added — §6.1.5 leaf-intrinsic outputs

- `ValidatedPath::leaf_subject: x509_cert::name::Name` (PKIX-qzmr).
- `ValidatedPath::leaf_issuer: x509_cert::name::Name`.
- `ValidatedPath::leaf_serial: x509_cert::serial_number::SerialNumber`.
- `ValidatedPath::leaf_spki: spki::SubjectPublicKeyInfoOwned` (carries
  algorithm OID, parameters, and public-key bits).

  Downstream code can now read the validated leaf's identity without
  re-parsing `chain[0]`. Common uses: revocation lookups (need
  `{ issuer, serial }`), application-layer signature verification
  using the validated leaf as a trust delegate (needs SPKI), audit
  logging (needs subject DN).

### Changed (breaking)

- `ValidatedPath` no longer derives `Copy`. The four new heap-backed
  leaf-intrinsic fields' types (`x509_cert::name::Name`,
  `x509_cert::serial_number::SerialNumber`,
  `spki::SubjectPublicKeyInfoOwned`) do not implement `Copy`
  upstream.

  Migration: callers that relied on bit-copy semantics need to insert
  an explicit `.clone()` or pass `&ValidatedPath` instead. No in-tree
  workspace consumer relied on this.
- `ValidatedPath` no longer derives `Hash`. Same rationale. Callers
  needing hashable identity for a validated path can hash any of the
  new fields (`leaf_serial`, `leaf_spki`'s DER encoding) directly.

## [0.2.1] — 2026-05-07

### Added

- `pub fn cert_is_ca(cert: &Certificate) -> Result<bool, DerError>` —
  RFC 5280 §4.2.1.9 `BasicConstraints` decode helper. Returns
  `Ok(true)` if the cert has `cA = TRUE`, `Ok(false)` if absent or
  `cA = FALSE`, `Err(DerError)` if the extension is present but
  malformed (fail-closed). Shared by `pkix-path-builder` and
  `pkix-revocation::crl` to avoid duplicate RFC 5280 §4.2.1.9
  decoders.

### Changed (non-breaking) — RFC 4518 `BMPString` DN AVA support

- `names_match` (and the underlying `ava_values_match`) now decodes
  `BMPString`-tagged `AttributeTypeAndValue` content from UCS-2
  big-endian to UTF-8 before applying the existing ASCII case-fold
  and insignificant-whitespace normalization (PKIX-l63j.1). Two AVAs
  that encode the same Unicode code points using different DER
  string types (`BMPString` vs
  `UTF8String` / `PrintableString` / `IA5String` / `VisibleString`)
  now compare equal where they previously fell through to raw DER
  byte comparison.

  Behaviour change for adversarial / malformed input: a `BMPString`
  with odd-length content bytes or 16-bit units in the UTF-16
  surrogate range (U+D800..=U+DFFF) is now rejected by
  `any_to_str_bytes` (returns `None`); the dispatcher then returns
  `false` for any comparison involving the malformed value
  (fail-closed). Real-world certificates with malformed `BMPString`
  content do not exist in the PKITS corpus or any other in-tree
  fixture.

  `UniversalString` AVAs continue to be parser-rejected upstream by
  `der 0.7`. `TeletexString` continues to fall through to raw DER
  byte comparison (committed policy; tracked under PKIX-l63j.3).
  NFKC and full RFC 4518 prep for non-ASCII Unicode tracked under
  PKIX-l63j.2.

## [0.2.0] — 2026-05-06

Initial substantive release. `chain_walk` implements RFC 5280 §6.1
across signature verification, validity period, name constraints
(with `nameConstraints` intersection/union and `nc_constrained_types`
tracking), policy tree (including `PolicyMappings` and
`InhibitAnyPolicy`), and the §6.1.5 wrap-up. PKITS happy-path subset
green.

Algorithm verifiers (behind feature flags):

- `EcdsaP256Verifier` (P-256 + SHA-256, OID 1.2.840.10045.4.3.2).
- `RsaPkcs1v15Sha256Verifier` (RSA-PKCS1v15 + SHA-256,
  OID 1.2.840.113549.1.1.11).

`DefaultVerifier` dispatches signature OIDs to the available
verifiers. NameConstraints (RFC 5280 §4.2.1.10) with seed state from
trust anchors. RFC 5280 §6.1.3 self-issued cert exemptions.

`no_std` + `forbid(unsafe_code)`. MSRV 1.73.

## Pre-history

Initial scaffold landed under `9b0995eb` (`feat: add stub crates,
specs, and READMEs`). Path validation entry point landed under
`9b1711f1` (`feat: implement validate_path + chain_walk +
DefaultVerifier`); algorithm verifiers landed under `b2cbf3d8`
(`feat(pkix-path): add trust anchor, P-256, and RSA verifiers`).
PKITS fixtures landed under `7a37ee51` (`test(pkix-path): add NIST
PKITS cert fixtures`). NameConstraints landed under `0c587814`
(`feat(pkix-path): implement NameConstraints (RFC 5280 §4.2.1.10)`).
