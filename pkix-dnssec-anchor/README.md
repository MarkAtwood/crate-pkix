# pkix-dnssec-anchor

The IANA DNS root zone trust anchors, as data.

**Status: implemented, unpublished.**

No validation, no network access, no filesystem access, no dependencies.
This crate is IANA's published root key material plus the machinery to
regenerate it, so that a DNSSEC validator can be handed a trust anchor
without having an opinion of its own about what to trust.

## Why this is a separate crate

A DNSSEC root key is a root of trust — the same kind of object as an X.509
trust anchor. This workspace does not bake those in: `pkix-path` ships no
root program's certificate list, `pkix-truststore` takes DER bytes without
asking where they came from, and OS trust stores live in the separate
`pkix-truststore-system` crate so platform-specific acquisition stays out of
the core.

Treating the DNSSEC root the same way buys three things:

- **Auditability.** The anchors are their own artifact with their own
  provenance, reviewable without reading a resolver's source.
- **Independent updates.** When IANA rolls the key-signing key, this crate is
  released and consumers `cargo update`. They do not wait for a
  `pkix-dane-resolver` release, and that crate needs no change.
- **No ambient dependencies.** Nothing here touches the filesystem or the
  operating system, so a consumer's trust configuration is whatever they
  passed in and nothing else.

The shape follows [`webpki-roots`](https://docs.rs/webpki-roots), which does
the same job for the Web PKI.

## Keeping it current

**This crate goes stale on someone else's schedule, and the failure is
quiet.** If IANA rolls the key-signing key and a consumer does not update,
DNSSEC validation stops succeeding — and under an opportunistic DANE policy
that is reported as "DNSSEC could not be established" rather than as
anything being wrong. A deployment can lose DANE without noticing.

Three things guard against that:

1. **A scheduled CI check.** `.github/workflows/iana-anchors.yml` runs
   `./gen.sh --check` monthly: it fetches IANA's anchors, verifies their
   signature, and fails with a diff if the committed set no longer matches.
   This is the only guard that does not depend on a human remembering.
2. **Auditable source.** Each anchor in `src/generated.rs` carries its IANA
   `KeyDigest` id, key tag and validity dates, so staleness is visible by
   reading the file.
3. **A caller-side escape hatch.** A consumer who needs a new key before a
   release can build one with `RootAnchor::new` and the `with_*` methods, and
   pass it directly. Nothing privileges the shipped anchors over a
   caller-supplied one.

As of writing, IANA lists three key digests and two are current: key tag
20326 (published 2017) and key tag 38696 (published 2024). The 2010 anchor,
key tag 19036, was withdrawn in 2019 and is retained in `ALL` for auditing.

**A validator must accept any anchor in `CURRENT`, not just the newest.**
IANA publishes a replacement well before withdrawing its predecessor, so two
are valid during the overlap; honouring only one is an outage waiting for the
roll to complete.

## Provenance

`src/generated.rs` is generated from IANA's `root-anchors.xml` by `gen.sh`,
which **verifies IANA's detached PKCS#7 signature over the XML** against the
ICANN certificate it chains to, and fails closed if it does not verify. The
XML, its signature and that certificate are committed under `iana/` and
shipped in the published crate, so a release's provenance can be re-checked
offline:

```sh
openssl smime -verify -inform DER -in iana/root-anchors.p7s \
    -content iana/root-anchors.xml -CAfile iana/icannbundle.pem
```

Two of the crate's tests are that check: one re-verifies the signature
against the committed artifacts, the other asserts every generated anchor
appears in that XML with a matching key tag and digest. Together they catch a
hand-edited `generated.rs` and a substituted `root-anchors.xml`.

Reviewing an update means re-running `./gen.sh` and diffing the result, not
trusting whoever edited the constants.

## Usage

```rust
// The anchors a validator wants.
let anchors = pkix_dnssec_anchor::CURRENT;

// Or your own, for a private DNSSEC root or a test root.
use pkix_dnssec_anchor::RootAnchor;
let private = RootAnchor::new(12345, 8, 2, &[0xab; 32])
    .with_id("corp-root")
    .with_public_key(&[0xcd; 260]);
```

`ALL` additionally holds withdrawn anchors. `CURRENT` is a snapshot taken at
generation time, so a consumer that must be exact about expiry should filter
`ALL` with `RootAnchor::is_valid_at` against the current time rather than
trusting `CURRENT` to be fresh.

## Regenerating

```sh
./gen.sh            # fetch from IANA, verify the signature, regenerate
./gen.sh --offline  # verify and regenerate from the committed iana/ copies
./gen.sh --check    # fetch, verify, report drift, write nothing
```

## License

Apache-2.0 OR MIT, at your option. The IANA artifacts under `iana/` are
IANA's publications, included for provenance.
