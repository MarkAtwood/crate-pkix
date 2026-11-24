# pkix-ct-google

Google's Certificate Transparency log-list signing key, as data.

**Status: implemented, unpublished.**

No validation, no network access, no filesystem access, no dependencies. This
crate is one public key plus the machinery to regenerate it, so that a
consumer verifying Google's signature over Google's CT log list can be handed
the key rather than having to go and find it.

```rust
use pkix_ct_google::GOOGLE;

// pkix_ct::CtLogList::from_google_log_list_json_verified takes the key as
// DER SubjectPublicKeyInfo, which is what GOOGLE.spki is.
let spki: &[u8] = GOOGLE.spki;
```

## A key is a fact

This crate ships a number. Verifying a signature with a published public key
is checking arithmetic, and the shape of the crate reflects that: no builder,
no policy, no configuration. A caller who has their own key does not need
this crate, because `pkix-ct` takes `&[u8]` directly.

That is also why shipping the key is a different act from shipping a log list.
**The list is policy** — it encodes which logs Google's program has decided to
trust, and it changes weekly. **The key is not**; it says only who signed.
Nothing here commits a consumer to Google's inclusion criteria. It commits
them only to being able to tell whether a list they fetched is the one Google
published.

## Why this is a separate crate

The same reason `pkix-dnssec-anchor` is: a root of trust belongs in its own
artifact, with its own provenance and its own release cadence.

- **The choice is visible.** `pkix-ct-google` in a `Cargo.toml` says plainly
  which program's key is being trusted. A constant inside `pkix-ct` would
  hide exactly that.
- **Rotation is a data update.** When Google rotates the signing key, this
  crate is released and consumers `cargo update`. No `pkix-ct` release, no
  change to `pkix-ct`.
- **Nothing is ambient.** No filesystem, no OS trust store, no network. A
  consumer's trust configuration is what they passed in.

## Google's acceptable-use policy

Chrome's log-list documentation offers the lists for certificate submitters
such as certification authorities and for CT monitors and auditors, and says
they "may not be used to facilitate CT enforcement in TLS clients other than
Chrome without explicit written permission from Chrome's CT team."

Recorded because a reader should know it exists. It is not a licence term on
this crate and does not travel with these bytes. An acceptable-use policy
draws its force from a service agreement accepted as a condition of access;
retrieving an unauthenticated public URL accepts nothing. And a public key is
a number — where a rightsholder has copyright or trademark to assert, they
assert it. None of this is legal advice; an operator with counsel should ask
them rather than a README.

**The warning inside the policy is worth keeping, though, whoever has
permission.** A client that pins Chrome's *log list* inherits Chrome's
inclusion and retirement decisions on Chrome's schedule, with no notice.
Holding a stale copy means either rejecting good certificates whose log is
newer than the list, or believing CT is enforced while checking against a set
that no longer describes the ecosystem — and neither failure announces itself.

That argues for knowing where your log list comes from and refreshing it, not
against being able to check a signature. Being able to check one is what makes
frequent refreshing safe, which is the opposite of pinning a snapshot.

## Provenance, and its limits

Weaker than `pkix-dnssec-anchor`'s, and worth stating rather than glossing.

IANA signs its trust-anchor file, so that crate's generator verifies a
detached signature and fails closed. **Google does not sign this key and
publishes no out-of-band copy of it** — no fingerprint in a signed artifact,
no copy in an independently distributed source tree. Chrome does not use this
path at all; it receives log lists through the component updater's PKI
Metadata component. The `gstatic.com` key and signature exist for third
parties.

So the chain ends at HTTPS to `gstatic.com` — which is to say in the Web PKI,
the thing Certificate Transparency exists to police. That circularity is
inherent to bootstrapping CT from the network and no care here removes it.

What `gen.sh` does instead is a cross-check that is still worth something: it
fetches the key, the log list, and Google's detached signature over that list,
then verifies the signature **using the fetched key**. A key that verifies
Google's current published list is Google's current signing key, or all three
artifacts were substituted together. That rules out a stale key, a truncated
or corrupted fetch, a wrong file at the URL, and a key from some other Google
program.

The crate's tests re-run that check against the committed sample list, so it
is a property of every release rather than of the day the key was captured:

```sh
openssl dgst -sha256 -verify google/log_list_pubkey.pem \
    -signature google/sample-log_list.sig google/sample-log_list.json
```

## Keeping it current

The key rotates far more rarely than the list it signs, which is what makes
this split practical. But a consumer pinning a rotated-away key sees
verification fail on a list that is genuine, which is a confusing failure.

```sh
./gen.sh            # fetch from Google, cross-verify, regenerate
./gen.sh --offline  # cross-verify and regenerate from the committed copies
./gen.sh --check    # fetch, cross-verify, report drift, write nothing
```

`.github/workflows/external-anchors.yml` runs `--check` on a schedule, so a
rotation is noticed without anyone remembering to look.

## License

Apache-2.0 OR MIT, at your option. The Google artifacts under `google/` are
Google's publications, included for provenance.
