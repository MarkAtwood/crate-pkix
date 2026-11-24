# Changelog

All notable changes to `pkix-dnssec-anchor` are documented here. The
crate follows [Keep a Changelog](https://keepachangelog.com/) headings
and [Semantic Versioning](https://semver.org/).

## [Unreleased]

Planned release: **0.1.0**. First release.

### Added

The IANA DNS root zone trust anchors as inert data, with no
dependencies, no network access and no filesystem access.

- `RootAnchor` — one anchor, carrying both forms IANA publishes: the
  delegation-signer digest and the `DNSKEY` public key. `Clone + Copy +
  Debug + PartialEq + Eq + Hash`, `Send + Sync`, `#[non_exhaustive]`.
- `CURRENT` and `ALL` — the anchors that were unexpired at generation
  time, and every anchor IANA lists including withdrawn ones.
- `RootAnchor::new` plus `with_id` / `with_public_key` / `with_flags` /
  `with_validity`, so a caller can supply a private or test DNSSEC root.
  Without a constructor, `#[non_exhaustive]` would have made IANA's keys
  the only usable ones, which would defeat the point of the crate.
- `is_valid_at`, `is_withdrawn`, `is_key_signing_key`.
- `gen.sh` + `gen.py`, which fetch IANA's `root-anchors.xml`, **verify
  IANA's detached PKCS#7 signature over it** against the ICANN
  certificate, and only then generate `src/generated.rs`. The script
  fails closed if the signature does not verify.
- The three IANA artifacts committed under `iana/` and shipped in the
  published crate, so a release's provenance can be re-verified offline
  without trusting that `gen.sh` ran honestly.

### Design notes

- **A root key is a root of trust, so the caller supplies it.** This
  crate exists because `pkix-dane-resolver` should not bake one in, for
  the same reason `pkix-path` ships no root program's certificate list
  and `pkix-truststore` takes DER bytes without asking their origin.
  Shipping the anchors as their own versioned artifact means a KSK roll
  is a release of this crate and a `cargo update`, not a resolver
  release consumers must wait for. The shape follows `webpki-roots`.
- **No OS, no filesystem.** An earlier draft considered reading a system
  trust-anchor file (`/var/lib/unbound/root.key`) with a compiled-in
  fallback. Rejected: this workspace keeps platform-specific acquisition
  out of its crates by design.
- **More than one anchor is valid at a time.** IANA publishes a new KSK
  well before withdrawing the old one. A validator must accept any
  anchor in `CURRENT`; honouring only the newest is an outage waiting
  for the roll to finish. At the time of writing `CURRENT` holds two,
  key tags 20326 (2017) and 38696 (2024).
- **`flags == 0` means "not stated", not zero.** IANA's withdrawn 2010
  entry is digest-only, with no `PublicKey` and no `Flags`. Documented on
  the field, since zero is not a meaningful `DNSKEY` flag value and
  `is_key_signing_key` returning `false` there means "unstated".

### Keeping the anchors current

A release of this crate is a snapshot of IANA's anchor set, and it goes
stale on IANA's schedule. The failure is quiet: a consumer with a stale
set stops getting DANE, reported as "DNSSEC could not be established"
rather than as anything being wrong.

- **`gen.sh --check`** fetches IANA's anchors, verifies the signature, and
  reports drift against the committed set without writing anything. It
  compares the fields that matter — id, key tag, algorithm, digest type,
  digest, validity — rather than whole files, because IANA reformats and
  rewrites the `TrustAnchor` id without changing any anchor, and a byte
  comparison would cry wolf on that. It exits 2 rather than 1 when the
  signature fails to verify: that is not a key roll, and wants
  investigating rather than regenerating.

  It lives in `gen.sh` rather than a separate script so the IANA URLs and
  the signature verification exist in one place. A checker that drifted
  from the generator would be worse than no checker.

- **`.github/workflows/iana-anchors.yml`** runs it monthly, and on any
  pull request touching this crate so a regeneration is checked against
  IANA in the same change that performs it. Monthly rather than weekly: a
  root KSK roll is announced well in advance and has happened once since
  2010, and a job that runs more often than the thing it watches teaches
  people to ignore it. Separate from `quality-gates.yml` so an unrelated
  pull request does not fail because a third party published something.

- A **README**, which this crate previously lacked, covering the same
  ground for a reader on crates.io.

### Testing


18 tests. Two are provenance checks rather than unit tests: one re-runs
IANA's signature verification against the committed artifacts, and one
asserts every generated anchor appears in that committed XML with a
matching key tag and digest. Together they catch a hand-edited
`generated.rs` and a substituted `root-anchors.xml`.
