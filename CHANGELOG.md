# Changelog

All notable changes to the workspace crates are documented here. The workspace
follows [Keep a Changelog](https://keepachangelog.com/) headings and
[Semantic Versioning](https://semver.org/) for each crate independently.

## [unreleased]

### `pkix-chain` 0.6.0: sans-I/O verify surface, replacing the planned async twin

`pub mod sans_io` exposes the I/O-free core of chain verification. A
caller drives it and performs every fetch itself: `ChainBuilder` returns
`Built`, `Fetch(uris)` or `Failed`, and `revocation_targets` hands back
the checks a validated chain calls for as a list the caller can issue
concurrently.

This supersedes the async twin decided under `PKIX-j32w.3`, which was
settled before two costs were visible. `verify_tls_server` performs no
validation itself — it reaches `Verifier::verify_one`, which calls
`build_with_aia` and `run_revocation_checks` — so an async path that is
async all the way down needed an async `Verifier` duplicating the whole
orchestration layer, and `build_with_aia` is where the AIA bounds live.
Separately, the async traits live in the std HTTP adapters, so being
generic over them would have made `pkix-chain` depend on ureq *and*
reqwest *and* tokio purely to name two traits.

Sans-I/O avoids both: no `async` feature, no `async-trait`, no HTTP
dependency, one copy of the bounds, and it serves any runtime. The
question of where the async traits belong dissolves rather than being
answered.

`build_with_aia` and `run_revocation_checks` now delegate to the shared
core, so there is one reassembly loop and one definition of what
revocation must check. Neither is a behaviour change.


### `pkix-chain` 0.6.0: DANE composition

`verify_tls_server_dane` composes PKIX validation with a domain's TLSA
records across all four usages, behind a new **default-on** `dane`
feature that pulls only the `no_std`, I/O-free `pkix-dane`. The DNS
stack stays behind `dane-resolver`, off by default.

It is a separate entry point rather than a parameter on
`verify_tls_server` because DANE does not merely add a check: usage 2
replaces the trust anchor and usage 3 skips path validation outright.
For the same reason it returns `TlsAuthorization` rather than
`ValidatedPath` — usage 3 validates no path, and inventing one with a
meaningless `anchor_index` would hide the distinction a caller needs to
log or apply policy to a DANE-authorized connection.

`DaneFailurePolicy` is `Opportunistic` by default with `Strict`
available, and a `Bogus` DNSSEC status fails under both — not
configurable, since a knob there would let an attacker switch DANE off
for any domain by corrupting the DNS answer. `DaneConfig::disabled()` is
the call-site override for pure PKIX in a DANE-enabled binary.

**The async twin is not in this release.** To be async all the way down,
which it must be or it blocks the executor on revocation and AIA I/O, it
needs an async `Verifier`: `verify_tls_server` reaches
`Verifier::verify_one`, which calls `build_with_aia` and
`run_revocation_checks`. That is duplicating this crate's orchestration
layer in async rather than adding a wrapper, and it is tracked
separately.

Planned version: `pkix-chain` 0.6.0. Nothing is published.


### `pkix-aia-http` 0.3.0: async fetcher family

`AsyncAiaFetcher` behind a new `async` feature, with a `reqwest`-backed
`AsyncHttpFetcher` behind `client-reqwest-async`. Both off by default.
The traits live in `pkix-aia-http`, not in the `no_std` `pkix-aia` core,
following the Option C placement `pkix-revocation-http` adopted. Needed
by `pkix-chain`'s async verify path: an async entry point that awaited
TLSA resolution and then called a *synchronous* AIA fetcher would block
the executor, which is the defect already open against
`pkix-revocation-http`.

`batch_fetch` runs concurrently by default, where the sync trait's
default loops — the reason the async family is worth having, since AIA
reassembly can have several candidate URIs per certificate.

**Security:** the first implementation had an SSRF hole, caught by its
own tests before release. `reqwest` does not consult a custom DNS
resolver when the URI host is an IP literal, so the resolution-time
destination filter — correct for names, and mirroring the sync
fetcher — was bypassed entirely by `http://169.254.169.254/` and
friends. A literal-host check now runs before the request; it is sound
where a pre-request check on a *name* would not be, since a literal
cannot change between check and connect.

Also removes the `PKIX-zkjb.5.1` references from the crate's docs,
manifest and README: they pointed at a bead that was never filed.

Planned version: `pkix-aia-http` 0.3.0. Nothing is published.


### `pkix-dane-resolver` 0.2.0: DNSSEC-validating TLSA resolution

Was a 0.1.0 namespace reservation. Now resolves TLSA records and
validates the DNSSEC chain over them, returning the `TlsaResponse` that
`pkix-dane`'s matching functions consume. Built on `hickory-resolver`
0.26, which is why the workspace MSRV moved to 1.88.

- **Async only.** Hickory is async, and a synchronous facade would have
  to either call `block_on` — which panics from inside a Tokio runtime —
  or hide a background runtime thread behind a blocking-looking
  signature. The sync path instead takes records as data: `pkix-dane`'s
  matchers are pure functions over `(certificate, TlsaResponse)`, so
  resolution and verification were always separable.
- **The caller supplies the trust anchor**; none ships here, and a
  resolver built without one is refused rather than silently never
  validating. IANA's are in the new `pkix-dnssec-anchor`.
- **Validation is local.** An upstream resolver's `AD` bit is a claim by
  a host on the network path, so signatures are verified here. The
  upstream needs no DNSSEC capability, only to pass `RRSIG` / `DNSKEY` /
  `DS` through unmangled — which `systemd-resolved`'s stub resolver
  notably does not, the case `PKIX_DANE_RESOLVER` exists for.
- **The weakest proof in an answer wins**, `Bogus` weakest of all, so one
  injected unvalidated record cannot get an RRset treated as secure.

Not yet: a TTL cache (the trait admits a wrapper; none ships), signed
negative answers reported as authenticated denial rather than
indeterminate, and the MX-derived lookup SMTP-DANE needs.

Planned version: `pkix-dane-resolver` 0.2.0. Nothing is published.


### SMTP DANE: the async driver

`pkix_dane_resolver::SmtpDiscovery` performs the lookups the state machine
asks for. The division is complete: `pkix-dane` decides, `pkix-dane-resolver`
fetches.

**The caller owns the loop.** `next_target()` advances discovery until it has
something to report — a target, a delay, or exhaustion — and calling it again
after a target offers the next MX host in preference order, which is how an
MTA retries after a failed delivery attempt. No callback: a delivery attempt
is itself async and borrows the caller's connection state, and handing
`pkix-dane`'s synchronous `resolve_with` an async closure is not possible.

`AsyncSmtpDiscovery` has three methods — MX, addresses, TLSA — each returning
an `MxAnswer` rather than a `Result`, because "the lookup failed" is one of
the answers the state machine interprets: §2.2.1 makes a failed TLSA lookup
mean the server is unreachable, which is a verdict rather than an error.
Implemented for `HickoryTlsaResolver`, with blanket impls for `&D` and
`Arc<D>` so a shared resolver need not be cloned.

Ordering is not the driver's responsibility. §2.2.2's address-before-TLSA rule
and §2.2.1's preference order are enforced by the state machine, which asks
for one lookup at a time — so a driver cannot get them wrong by answering
what it was asked. That is the payoff for the sans-IO split.

Verified live against real zones, with `PKIX_DANE_RESOLVER=9.9.9.9`:

- `freebsd.org` → `mx1.freebsd.org`, one usable DANE-EE(3) record,
  `mx_secure=true`: MX lookup, address lookup, TLSA lookup and DNSSEC
  validation against IANA's anchors, all against a zone nobody here controls.
- `huque.com` → `mail.huque.com`, usages `[3, 1, 3]`.

Live tests skip with a printed reason rather than failing, following
`resolve.rs`; the usual cause is `systemd-resolved`'s stub stripping DNSSEC
records rather than absent network.

### Fixed: a set of only PKIX usages is not DANE

Found by the `huque.com` live test failing on a wrong assumption. That zone
publishes **PKIX-EE(1) alongside DANE-EE(3)**, which exposed a real contract
problem rather than just a bad test.

`TlsaRecord::is_usable` asks whether a record parses and carries an assigned
usage — not whether this profile can authenticate with it. So usage-0 and
usage-1 records survived discovery's filter and made `dane_records()` report
`Some`, claiming DANE applied when nothing present could authenticate.

Now `dane_records()` and `identities()` require a DANE-EE(3) or DANE-TA(2)
record, and under mandatory DANE a PKIX-only set delays per §6 instead of
being offered. The records are still **carried** in `tlsa_response()`,
deliberately: the entry point needs them to report "the domain published only
PKIX usages" distinctly from "the domain published nothing", which is a
misconfiguration worth telling a postmaster about.

### Finding: `debian.org`'s TLSA RRset does not validate under hickory

`debian.org` was the first choice for the live test and is not used. Its
`_25._tcp.mailly.debian.org` RRset comes back `Indeterminate` with records
present, while `mail.huque.com`, `mx1.freebsd.org` and
`good.dane.huque.com` all come back `Secure` through the same resolver and
anchors. The zone has a DS record (`40756 8 2`, RSA/SHA-256) and the upstream
sets `AD`.

Pre-existing and not introduced here: `AsyncTlsaResolver::resolve` reports
the same, so it is a property of the resolver or the zone rather than of the
new driver. Filed separately, because a real domain that silently fails to
validate is worth understanding before anyone relies on DANE for it.

### SMTP DANE: the entry point

`pkix_chain::verify_smtp_server_dane` completes RFC 7672 support: it takes a
`DeliveryTarget` from discovery plus the chain the server presented, and
reports what DANE concluded.

**It reports; it does not decide.** Every outcome is `Ok`, including
authentication failure, and there is no failure-policy parameter. An MTA has
to be able to tag a message, route it to a different queue, defer it, bounce
it or deliver it anyway on the strength of a DANE failure — and it cannot do
any of that if the failure is indistinguishable from a malformed call. So the
verdict is an input to the MTA's decision rather than a substitute for it.

`SmtpDaneVerdict` has three cases, and the distinction between the last two
is the point of the type:

| Verdict | Meaning |
|---|---|
| `Authenticated` | the server proved it holds a key the domain published |
| `NotApplicable` | the domain published nothing usable; DANE had nothing to say |
| `Failed` | the domain published usable records and the server did **not** match |

`NotApplicable` is an ordinary pre-DANE connection. `Failed` means the server
presented a certificate the domain's own DNS contradicts. Collapsing them
would let a log claim an authenticated channel for a cleartext delivery, or
treat active interception as a quiet absence of DANE.

`rfc7672_permits_delivery()` is §3.2's MUST NOT as a predicate — false only
for `Failed` — so a conforming MTA is one line away and a non-conforming one
has to visibly ignore it. `is_authenticated()` is the narrower question, true
only for `Authenticated`, because the two are different and a log line needs
the second.

The documentation states why the RFC forbids delivering on failure, since
that is the thing worth knowing before overriding it: a DANE failure where
usable secure records exist means either the server is misconfigured **or the
connection is being intercepted**, and the sending client cannot tell which.
It also notes that delivering-with-the-failure-recorded is coherent for
deployments the RFC was not written for — a staged rollout measuring DANE
before enforcing it, in the manner of DMARC `p=none`.

`SmtpDaneFailure` separates four operational problems rather than collapsing
them, because an MTA reporting to a postmaster wants to say which: no record
matched, the chain did not reach the anchor the record names, the chain
matched but failed the §3.2.2 name check, or the domain published only PKIX
usages.

- **No trust-store parameter.** DANE-EE(3) validates no path; DANE-TA(2)
  validates to the anchor its own record supplies and to that anchor *alone*,
  since merging it with a caller's store would implement "DANE-TA or any CA",
  weaker than either; and PKIX-TA(0)/PKIX-EE(1), the usages that would consult
  a store, are unusable here per §3.1.3. No path reads caller anchors, so the
  signature does not accept them.

- **§6 completed in discovery.** "With mandatory DANE TLS, when no usable TLSA
  records are found, message delivery is delayed." Previously `mandatory` was
  enforced only at the MX step; a server that published nothing usable was
  still offered for unauthenticated delivery, which defeated the policy. Now a
  host without usable records is passed over, the next in preference order is
  tried, and only when none has any is delivery delayed — with
  `MandatoryDaneWithoutUsableTlsa` distinguishing it from the insecure-MX case,
  since the remedies differ.

### Finding: a Web PKI profile rejects RFC 7672's intended deployments

`BasicTlsProfile` sets `require_subject_alt_name`, correctly for the Web PKI.
RFC 7672 §3.2.3 consults the `commonName` precisely because MTA certificates
often carry their name only there — so that profile rejects those
certificates during **path validation**, before any name check runs, and the
symptom is the unhelpful `Failed(PathValidationFailed(Path(MissingSan)))`.

Documented on the function, affecting DANE-TA(2) only. The workspace ships no
SMTP profile yet; filed separately, because a caller reaching for the obvious
profile gets a silent incompatibility.

### SMTP DANE (RFC 7672 §2.1, §2.2): the MX lookup

`pkix_dane::smtp_lookup` — discovery as a sans-IO state machine, behind the
same `smtp` feature. `MxResolution::next_step` names the lookup to perform,
`absorb` takes the answer, and `resolve_with` drives the loop for a caller
with a synchronous resolver.

Sans-IO because the decisions are pure functions of DNS answers: which MX to
try next, whether an RRset is trustworthy, whether a TLSA query is worth
making. So the policy lives in `no_std` and the lookups stay with whoever
has a resolver — the split `pkix_chain::sans_io` already established. It also
means the surprising requirements below are testable without a resolver,
scripted answer by answer.

**Two MUSTs a straightforward implementation violates**, and both are tested
against the plausible wrong behaviour rather than the happy path:

- **MX preference outranks channel security** (§2.2.1). "an MX hostname with
  a worse (numerically higher) MX preference that has TLSA records MUST NOT
  preempt an MX hostname with a better (numerically lower) preference that
  has no TLSA records... prevention of delivery loops by obeying MX
  preferences MUST take precedence over channel security considerations."

  Preferring the host that offers DANE is a conformance bug, and a tempting
  one. Hosts are tried strictly in preference order, and the test gives the
  backup MX the TLSA records and the primary none, then asserts the primary
  is offered first *without* DANE. Confirmed to bite: reversing the sort in
  the implementation fails that test and two others.

- **Address lookups precede TLSA lookups** (§2.2.2). "the SMTP client MUST
  perform any A and/or AAAA queries for the destination before attempting to
  locate the associated TLSA records." Not an optimization: load-balancing
  nameservers at some large providers answer TLSA with SERVFAIL or NOTIMP
  rather than an insecure negative reply, so a client querying TLSA first
  would strand that mail. With an insecure address answer the TLSA query is
  **not issued at all**, which is the part that protects against those
  nameservers — a query that is never sent cannot fail.

Also implemented, with the reasoning in the rustdoc:

- `RrsetTrust` collapses `Indeterminate` into `Insecure` at the boundary, per
  §2.1.1 ("DNS records that would be classified 'indeterminate'... are simply
  classified as 'insecure'", and "All 'insecure' RRsets MUST be handled
  identically"), so no decision site has to remember to.
- A failed **TLSA** lookup makes that server unreachable (§2.2.1), the one
  place a failed lookup disqualifies a reachable host. Failing open would let
  anyone able to drop TLSA responses downgrade every connection.
- Insecure MX plus mandatory DANE delays delivery; an insecure CNAME *leading
  to* a signed MX RRset still counts as insecure, which §2.2.1 says in as
  many words and which a naive "last answer wins" reading would miss.
- `dane_despite_insecure_mx` serves §2.2.1's hosting-provider case — unsigned
  customer zone, signed provider zone — and narrows the reference identity to
  the MX hostname alone, which is tested.
- Bogus is evidence of tampering, so it delays rather than being read as "no
  records".
- `DeliveryTarget::mx_was_secure` and `next_hop` exist for §2.2.1's logging
  constraint: "Any successful authentication via an insecurely determined MX
  host MUST NOT be misrepresented in the mail logs as secure delivery to the
  intended next-hop domain."

Equal MX preferences keep input order rather than being randomized, so the
machine stays deterministic and testable; RFC 5321 §5.1 randomization is the
caller's to apply by shuffling first, and §2.2.1 explicitly does not oblige
an MTA to prefer the more secure of two equal-preference hosts.

### SMTP DANE (RFC 7672 §3.2): name checks

The first of three pieces of RFC 7672 support. This is the certificate-facing
half — the reference identifier set and the matching rule — with no DNS
lookups, no MX resolution and no TLSA matching, which belong elsewhere.

**Research first, and it overturned the plan.** The design on file claimed
RFC 7672 *requires* SMTP clients to ignore PKIX-TA(0) and PKIX-EE(1), making a
shared code path with the HTTPS entry point a policy violation. §3.1.3 says
something weaker: servers SHOULD NOT publish them for port 25, and client
treatment is **undefined**, with a MAY to treat them as unusable. Honouring
them would have been permitted. The separate entry point is still right, but
on the other two differences rather than that one.

- **`pkix_identity::verify_dns_name_with_cn_fallback`** implements §3.2.3:
  only DNS-IDs are matched when the certificate presents any, and the
  `commonName` is consulted only when it presents none.

  This is the behaviour `verify_dns_name` deliberately refuses, because
  RFC 6125 §6.4.4 deprecated it for the Web PKI. Both are right for their
  protocol: RFC 7672 is standards-track and current, and keeps CN fallback
  for MTA-to-MTA SMTP, where certificates are frequently old and
  self-managed and there is no user to prompt. It is a separate function
  rather than a flag so no caller acquires it by default, and the Web PKI
  path cannot be loosened by passing an argument.

  One implementation of the wildcard rule, not two: a second would be a
  divergence hazard, and wildcard bugs are security bugs.

- **`pkix_dane::smtp`** (new `smtp` feature) holds `SmtpIdentities`, the
  §3.2.2 reference identifier **set**, and `verify_smtp_name`.

  The set is what a single-hostname API cannot express. Its membership
  depends on how the TLSA base domain was reached, so there is a constructor
  per case rather than a bag of names: `secure_mx` carries the base domain
  plus the original next-hop domain and its CNAME expansion, `non_mx` adds
  the original next-hop only when the base domain is its expansion, and
  `insecure_mx` carries the MX hostname **alone**.

  That last exclusion is the security property, and it is tested as a pair:
  the same certificate naming the same next-hop domain is accepted after a
  secure MX lookup and rejected after insecure MX redirection. An attacker
  who can tamper with an unsigned MX RRset chooses the MX hostname, so a
  certificate matching the next-hop domain proves nothing about reaching the
  intended destination — and accepting it would let the delivery be logged as
  secure delivery to a domain that was never authenticated, which §2.2.1
  forbids in as many words.

  `verify_smtp_name` takes the usage rather than assuming a check is wanted,
  because §3.2.1 makes skipping it a MUST NOT for DANE-EE(3) rather than an
  optimization. It reports *which* identifier matched, because §2.2.1 requires
  logs to distinguish secure delivery to the intended next-hop from
  authentication via an insecurely determined MX host, and a boolean cannot.

Still to come, recorded with the research that bears on them: the
DNSSEC-validated MX lookup (§2.2.1 requires MX preference order to take
precedence over channel security, and §2.2.2 requires A/AAAA queries *before*
TLSA lookups to avoid known-broken nameservers), and the entry point that
drives them. §2.1.1 also folds "indeterminate" into "insecure" for this
profile, which the SMTP path must honour.

### New crate: `pkix-ct-google` — Google's CT log-list signing key as data

`pkix-ct` can verify Google's detached signature over the CT log list, but
ships no key, so every consumer had to go and fetch one. This crate is that
key, with its provenance, and nothing else: no validation, no network, no
filesystem, no dependencies.

**Shipping the key is not shipping the policy.** The log *list* encodes which
logs Google's program has decided to trust and changes weekly; the *key* says
only who signed. Nothing here commits a consumer to Google's inclusion
criteria — only to being able to tell whether a list they fetched is the one
Google published. That distinction is why the key can live in a crate while
the list cannot.

- **Provenance is weaker than `pkix-dnssec-anchor`'s, and says so.** IANA
  signs its anchor file; Google neither signs this key nor publishes any
  out-of-band copy of it — no fingerprint in a signed artifact, no copy in an
  independently distributed source tree. Chrome does not even use this path,
  receiving log lists through the component updater's PKI Metadata component.
  The chain therefore ends at HTTPS to `gstatic.com`, which is to say in the
  Web PKI that Certificate Transparency exists to police. That circularity is
  inherent to bootstrapping CT from the network.

- **`gen.sh` cross-checks instead.** It fetches the key, the log list and
  Google's signature over that list, then verifies the signature *using the
  fetched key* and fails closed. A key that verifies Google's current list is
  Google's current signing key, or all three were substituted together — which
  rules out a stale key, a truncated fetch, a wrong file at the URL, and a key
  from another Google program. The crate's tests re-run the same check against
  the committed sample, making it a property of every release rather than of
  the day the key was captured.

- **Rotation is watched.** `./gen.sh --check` reports drift without writing,
  and `external-anchors.yml` (renamed from `iana-anchors.yml`, now one job per
  publisher) runs it on a schedule. Exit 2 rather than 1 distinguishes "the
  key does not verify Google's list" from "the key changed": Google publishes
  key and list together, so a rotation leaves them consistent and an
  inconsistency means a bad fetch, not a roll.

- **Google's acceptable-use policy is recorded, not enforced.** It offers the
  lists for certificate submitters, monitors and auditors and restricts CT
  enforcement in non-Chrome TLS clients. It is Google's policy statement, not
  a licence term on these bytes: an acceptable-use policy draws its force from
  a service agreement accepted as a condition of access, and fetching an
  unauthenticated public URL accepts nothing. The crate states the fact and
  leaves the judgement to the operator.

  The *warning* inside it is kept, because it holds whoever has permission: a
  client pinning Chrome's log list inherits Chrome's inclusion and retirement
  decisions on Chrome's schedule, so a stale copy means either rejecting good
  certificates or believing CT is enforced against a set that no longer
  describes the ecosystem. That argues for refreshing the list, which is
  exactly what being able to verify a signature makes safe.

### `pkix-ct`: document Google's acceptable-use policy, and Apple's lack of a signature

Two facts a consumer of this module needs that it did not state.

- **Google's CT log lists carry an acceptable-use policy.** Chrome's CT
  documentation makes the lists available for certificate submitters such
  as certification authorities, and for CT monitors and auditors, and says
  they "may not be used to facilitate CT enforcement in TLS clients other
  than Chrome without explicit written permission from Chrome's CT team."

  It is Google's policy statement rather than a licence term, and it binds
  nothing in this workspace: an acceptable-use policy draws its force from a
  service agreement accepted as a condition of access, and fetching an
  unauthenticated public URL accepts nothing. It is quoted in the module
  documentation because a consumer should know it exists, with the judgement
  left to the operator.

  The warning inside it is kept on its merits, since it holds whoever has
  permission: a client pinning Google's list inherits Chrome's inclusion and
  retirement decisions on Chrome's schedule, and a stale copy means either
  rejecting good certificates or believing CT is enforced against a set that
  no longer describes the ecosystem.

- **Apple's log list is not signed.** There is no detached signature
  published alongside `current_log_list.json` and no signature field
  within it, so a consumer ingesting it is trusting HTTPS to Apple and
  nothing further. The module previously listed Apple alongside Google as
  an alternative source without distinguishing them, which — now that a
  verified constructor exists for Google's list — invited the inference
  that the alternatives were comparably authenticated.

Also records on `from_google_log_list_json_verified` that Google publishes
no out-of-band verification of the signing key itself: no fingerprint in a
signed artifact, no copy in an independently distributed source tree. Its
authenticity rests on HTTPS to `gstatic.com`, which is to say on the Web
PKI that Certificate Transparency exists to police. The strongest check
available is that a candidate key verifies Google's currently published
list.

### Workspace: bare-metal `no_std` builds verified and gated

`pkix-dane`'s `no_std` claim had only ever been checked at source level —
that `#![no_std]` was in force and `std::` was unreachable. Whether the
dependency tree actually resolves and compiles for a bare-metal target was
unverified, because the environment it was written in could not install
one.

Now verified, and not only for `pkix-dane`. **All eight crates carrying the
`no-std` category build for `thumbv7em-none-eabi`,
`riscv64gc-unknown-none-elf` and `x86_64-unknown-none`**: `pkix-ac`,
`pkix-aia`, `pkix-composite`, `pkix-dane`, `pkix-dnssec-anchor`,
`pkix-identity`, `pkix-path`, `pkix-path-builder`.

- **A new `no-std` CI job** derives that crate list from the `no-std`
  category in each manifest rather than hardcoding it, so adding the
  category opts a crate into the gate and a crate that cannot hold the
  claim fails there rather than in someone's firmware build. This is the
  same class of silent drift the MSRV job was added for: nothing in a
  normal push would otherwise notice a dependency acquiring a `std`
  requirement.

- **`x86_64-unknown-none` needs `RUSTFLAGS='--cfg sha2_backend="soft"'`.**
  Confirmed necessary and sufficient rather than carried over from the
  earlier note: without it `sha2` 0.11's x86 SIMD backend fails with
  `rustc-LLVM ERROR: Do not know how to split the result of this
  operator!` on that soft-float target. Documented in `pkix-dane`'s
  crate-level docs, where a consumer will meet it, and applied as its own
  CI step so a future `sha2` release fixing it is noticed by that step
  passing without the flag.

### Findings

- `pkix-lint` and `pkix-profiles` do **not** build for bare metal, and
  correctly do not claim the `no-std` category — neither declares
  `#![no_std]` and `pkix-lint` uses `std::borrow::Cow` directly. Nothing
  is misrepresented; the metadata was accurate and the test confirmed it.
- `pkix-revocation` builds for all three bare-metal targets but does not
  carry the `no-std` category, so its metadata understates what it
  supports. Not changed here — adding the category opts it into the new
  gate, which is a commitment worth making deliberately rather than as a
  side effect of this check.

### `pkix-ct`: verify Google's signature over the CT log list

`CtLogList::from_google_log_list_json` parsed Google's `log_list.json` on
trust. Google publishes a detached `log_list.sig` and the key that signs
it, and neither was looked at.

**`CtLogList::from_google_log_list_json_verified`** checks the signature
before parsing anything. RSA PKCS#1 v1.5 with SHA-256, which is what
Google signs with, confirmed against the published artifacts with
`openssl dgst` before any code was written. The algorithm is fixed
rather than a parameter: letting a caller choose would let anything able
to influence that choice downgrade the check.

Verification goes through the caller's
[`SignatureVerifier`](pkix_path::SignatureVerifier), and the signing key
is a caller-supplied DER `SubjectPublicKeyInfo`. The crate ships no key,
for the same reason it ships no log list and `pkix-path` ships no root
certificates. Google's log-list signing key rotates far more rarely than
the list it signs, so pinning the key is practical where pinning the
list is not — the inverse of `pkix-dnssec-anchor`, where the anchor
itself is the long-lived artifact.

### Why this is not cosmetic

A `log_id` is SHA-256 over the log's SPKI, which `CtLogList` already
checks, so a substituted list **cannot** forge an SCT for a log already
in it. What it can do is **add a log the attacker controls**, after which
SCTs from that log verify — which defeats the point of requiring SCTs.

Unlike a DNSSEC root key, the list is not a long-lived constant: logs
are added, frozen and retired continuously, so a deployment refetches on
the order of weeks and every fetch was previously unauthenticated.

`from_google_log_list_json` is unchanged and still exported — a list you
reviewed and committed yourself needs no signature check. Its
documentation now says plainly that it checks nothing and points at the
verifying constructor.

### Testing

Eight tests against the **real published artifacts**, committed with
refresh instructions in `tests/fixtures/REFRESH.md`. Using Google's
genuine list and signature rather than a synthetic pair is the point:
the test asserts this crate agrees with what Google actually signs. The
negative cases cover a byte flipped at three positions, an edit that
leaves valid JSON, a modified key, malformed keys and signatures, and
that nothing is parsed before the signature verifies.

The tests do not go stale as the list rotates — they assert the
signature verifies and that tampering is caught, neither of which
depends on the list being current.


### Workspace: `pkix-aia` and `pkix-identity` are unconditionally `no_std`

Follow-on from the `core::error::Error` change. Moving the `Error` impls
out from behind `std` left two crates whose `std` feature no longer
earned its place; `pkix-path` (19 `cfg(std)` sites) and
`pkix-revocation` (4) keep theirs, because theirs gate real
functionality.

- **`pkix-aia`: the `std` feature is gone.** Its eight remaining
  `cfg(std)` sites all served one thing — `AiaError::IoFailure`'s
  `kind: std::io::ErrorKind` field. `IoFailure` is now
  `IoFailure(String)`, matching `MalformedCertificate(String)` and
  `DestinationNotAllowed(String)` in the same enum.

  The field bought very little: of the five places `pkix-aia-http`
  constructed it, **four passed `ErrorKind::Other`** and the fifth had a
  real kind already being rendered into the message. Nothing in the
  workspace matched on it. Removing it also deleted a **170-line serde
  helper** that existed only because `io::ErrorKind` is
  `#[non_exhaustive]` and does not derive `Serialize`, so round-tripping
  it needed a hand-written label table. The adapter site that had a real
  kind now folds it into the message, so no information is lost.

- **`pkix-identity`: the `std` feature is gone.** After the `Error` impl
  moved to `core::error::Error` and the `From<IpAddr>` conversions to
  `core::net`, its only remaining `cfg(std)` site was the `no_std`
  attribute itself — the feature merely forwarded `x509-cert/std` and
  `idna/std`, which a consumer wanting them can enable directly.

Both crates now build with no features at all. `pkix-aia-http` and
`pkix-chain` no longer request a `std` feature from either.

This is breaking for anyone matching `AiaError::IoFailure { kind, .. }`
or enabling those `std` features. `pkix-aia` is published at 0.1.1 and
`pkix-identity` at 0.2.0, both pre-1.0, where semver makes breaking
changes the mechanism for getting the design right rather than a cost to
avoid — and a `std` type in the public API of a `no_std`-first crate is
exactly the kind of thing to fix before 1.0 rather than after.


### Workspace: error types implement `Error` without `std`

`core::error::Error` stabilized in Rust 1.81, below the workspace MSRV of
1.88. Every error type here now implements it unconditionally, so a
`no_std` consumer gets `source()` chains and `&dyn Error` coercion that
were previously behind a feature for no reason but the Rust version.

- `pkix-dane`: **the `std` feature is gone.** It did nothing but gate the
  `Error` impl — its own manifest comment said so. The crate is now
  plainly `#![no_std]`. `pkix-dane-resolver` and `pkix-chain` no longer
  request `features = ["std"]` from it.
- `pkix-path`: `Error` and `DerError` implement `core::error::Error`
  unconditionally, including their `source()` chains. The `std` feature
  stays — it forwards to `der/std`, `spki/std` and `x509-cert/std`,
  which is a separate job.
- `pkix-revocation`: same, and its `source()` returns `pkix_path::DerError`
  which is now unconditional too. `std` stays; it forwards, and `crl` and
  `ocsp` depend on it.
- `pkix-aia`: `Error` impl unconditional. `std` stays, and its only
  remaining job is gating the `IoFailure` variant, whose
  `kind: std::io::ErrorKind` field has no `core` equivalent.
- `pkix-identity`: `Error` impl unconditional, **and the three
  `From<IpAddr>` conversions are no longer `std`-gated** — they now use
  `core::net` (Rust 1.77), which holds the same types `std::net`
  re-exports. A `no_std` consumer could not previously build a
  `ServerName` from an IP address type at all.

`pkix-dane` and `pkix-aia` assert the property at compile time alongside
their other invariants, so a future `cfg` cannot quietly take it back.

Verified: every core crate still builds with `--no-default-features`, the
workspace checks on the declared MSRV, and the full suite passes.


### Workspace: MSRV-aware resolver, and CI that enforces the gates

**The declared MSRV was being violated and nothing noticed.** Checking the
workspace against its own `rust-version` for the first time failed:
`uuid` 1.29 — reached through `moka` and `hickory-resolver` from
`pkix-dane-resolver` — requires rustc 1.89 while the workspace declares
1.88. A consumer on the declared minimum could not build `pkix-chain`
with `dane-resolver` enabled. Nobody developing here could have seen it,
because current stable compiles it fine.

- **`resolver = "3"`** (was `"2"`). Resolver 3 is MSRV-aware: it prefers
  dependency versions compatible with `rust-version` instead of always
  taking the newest. Resolver 2 ignores `rust-version` entirely, which is
  how the violation arose. Re-resolving picked `uuid` 1.26 on its own,
  annotating the newer release as requiring 1.89 — so a consumer
  resolving fresh gets a working tree too, which a lockfile pin would not
  have given them.

- **`.github/workflows/quality-gates.yml`** — fmt, clippy, rustdoc,
  typos, the test suite, the declared MSRV, and the `--depth 2` feature
  matrix. Before this the only workflow was the differential-test
  harness; every gate above was run by hand, by whoever remembered. The
  MSRV job reads the version from `Cargo.toml` rather than naming one,
  because the comment this bead was filed to correct was itself a
  duplicated version number gone stale.

- The lint job **pins its toolchain** rather than tracking stable.
  Several crates opt into `clippy::pedantic`; with `-D warnings` and a
  floating `stable`, a new pedantic lint would turn CI red every few Rust
  releases for reasons unrelated to any change, which is how a gate gets
  switched off. Two such findings arrived during this work and are fixed
  below.

### Fixed

- `pkix-path`: `bmp_is_well_formed` uses `as_chunks::<2>()`. The
  companion site in `any_to_str_bytes` keeps `chunks_exact` under an
  `#[expect]` with a reason — the iterator is stored in
  `DirStringBytes::Bmp`, so converting it would rewrite that variant's
  field type and the `Iterator` impl that transcodes UCS-2 through it,
  which is a real edit to DN-comparison code for a style preference.
- `pkix-difftest`: `base64_encode` uses `as_chunks::<3>()`.
- `pkix-chain` re-exports `pkix-dane-resolver` as `dane_resolver` under
  the `dane-resolver` feature. It was previously an optional dependency
  that no code referenced, so enabling the feature pulled the DNS stack
  without giving the consumer access to it.


### Workspace: MSRV 1.88

Raised from 1.87 for `hickory-resolver` 0.26, which `pkix-dane-resolver`
is built on. Every 0.26.x release of that crate declares
`rust-version = "1.88"`; the 0.25 line is still at 1.71.1.

The alternatives were pinning `hickory-resolver` 0.25 — which leaves a
DNS parser of uncertain maintenance status inside a security library —
or a per-crate `rust-version` override on `pkix-dane-resolver` alone.
The workspace-wide bump was chosen so there stays exactly one MSRV to
reason about.

The cost is accepted knowingly: every crate inherits 1.88, `pkix-path`
included, even though it is `no_std` and targets embedded platforms that
will never compile a DNS resolver, and even though the `dane-resolver`
feature that needs hickory is off by default.

Note that nothing currently enforces the MSRV. The only CI workflow is
the differential-test harness, whose comment still names 1.73.


### `pkix-dane` 0.2.0: TLSA parsing and the four DANE usages

`pkix-dane` was a 0.1.0 namespace reservation with no public API. It now
ships DANE TLSA record parsing and per-usage matching per RFC 6698,
RFC 7218 (mnemonics) and RFC 7671 (operational rules), for all four
certificate usages: PKIX-TA, PKIX-EE, DANE-TA and DANE-EE.

No DNS. The `TlsaResolver` trait is the seam, with the zero-cost
`NoTlsaResolver` default; DNSSEC-validating resolution remains the
unshipped sibling `pkix-dane-resolver`, and so does the `pkix-chain`
integration.

- Matching hashes the certificate **as the peer presented it**, never a
  re-encoding. `x509-cert` 0.3 normalizes a pre-2050 `GeneralizedTime`
  validity date to `UTCTime`, the same behavior that required
  `pkix_path::tbs_certificate_der` for signature checks — but that
  function covers only the `tbsCertificate`, and TLSA selector 0 needs
  the whole certificate. `PresentedCert` carries the received octets.
- Resolution returns a `TlsaResponse` pairing records with the
  `DnssecStatus` they arrived under, so the four DNSSEC outcomes stay
  distinguishable: `Secure`, `Insecure`, `Indeterminate` and `Bogus`.
  Only `Bogus` forbids PKIX fallback, since treating a broken signature
  as "no DANE" would let an attacker strip DANE by corrupting the answer.
- `DnssecStatus` is checked before matching, and the verify functions
  take a `TlsaResponse` rather than a bare record slice so the check
  cannot be bypassed.
- Unusable records are skipped rather than fatal, per RFC 7671: a record
  set may carry a usage this client does not implement alongside one it
  does.

Planned version: `pkix-dane` 0.2.0. Nothing is published.


### Workspace: x509-cert 0.3 / RustCrypto 0.14 maintenance wave (Nov 2026)

**Breaking for every crate that exposes x509-cert, der, spki or
signature types.** The workspace moves from x509-cert 0.2, der 0.7,
spki 0.7, signature 2 and the p256/p384 0.13, rsa 0.9, sha2 0.10 stack
to x509-cert 0.3, der 0.8, spki 0.8, signature 3 (internal only; see
the `SignatureVerifier` entry below), p256/p384/p521 0.14,
ed25519-dalek 3, rsa 0.10, sha1/sha2 0.11 and x509-ocsp 0.3.0-rc.1
(pinned exactly; no stable 0.3 yet). The lockfile carries one copy of
the stack; RUSTSEC-2023-0071 (rsa 0.9, GitHub #8) and RUSTSEC-2026-0387
(crypto-bigint 0.5) are gone.

- **MSRV 1.87** (was 1.73): the minimum crypto-bigint 0.7,
  elliptic-curve 0.14, rsa 0.10 and x509-ocsp 0.3 accept. Edition stays
  2021.
- Workspace dependencies use `default-features = false`; `pkix-path`
  without `std` no longer pulls `std` (GitHub #2).
- `pkix_path::tbs_certificate_der` replaces `tbs_certificate().to_der()`
  for signature checks: x509-cert 0.3 re-encodes validity times
  (UTCTime before 2050), which broke signatures on certificates using
  GeneralizedTime for such dates (PKITS 4.2.4 / 4.2.7 during the port).
- Security and correctness fixes from a review of every crate; see the
  per-crate CHANGELOGs (pkix-path, pkix-revocation,
  pkix-revocation-http, pkix-chain, pkix-path-builder, pkix-aia-http,
  pkix-identity, pkix-truststore, pkix-zlint-bridge, pkix-policy-zlint)
  and the entries below.
- LICENSE-APACHE and LICENSE-MIT added (GitHub #4).

Planned versions: pkix-path, pkix-revocation, pkix-path-builder,
pkix-profiles 0.4.0; pkix-chain, pkix-chain-simple 0.5.0; pkix-lint
0.10.0; pkix-lint-cabf, pkix-profiles-cabf 0.3.0; pkix-identity,
pkix-truststore, pkix-ct, pkix-ac, pkix-composite, pkix-revocation-http,
pkix-aia-http, pkix-zlint-bridge, pkix-policy-zlint 0.2.0; pkix-aia
0.1.1.

#### `pkix-ct` 0.2.0

- **BREAKING:** `SctVerifier::verify_embedded_scts` returns
  `Vec<VerifiedSct>` (log ID, timestamp), at most one per log, instead
  of a count of verified list entries. A repeated SCT, or several SCTs
  from one log, used to count toward a "two SCTs" policy. New
  `count_embedded_sct_logs`.
- Readonly and retired logs from the v3 log list accept SCTs before
  their readonly/retired time (they rejected every SCT).
- SCT `extensions` longer than 65535 bytes return
  `Error::SctExtensionsTooLong` instead of panicking (debug) or
  truncating the length prefix (release).
- Precertificate reconstruction keeps validity times as parsed.

#### `SignatureVerifier` error type

**Breaking** for every `SignatureVerifier` implementor: the trait returns
pkix-path's own `VerificationError` (kinds `UnsupportedAlgorithm`,
`UnsupportedKey`, `MalformedKey`, `InvalidSignature`, plus an optional
source) instead of `signature::Error`, and `validate_path` reports
non-signature failures as the new `Error::SignatureNotVerified { index,
reason }`. pkix-chain re-exports both types and treats
`SignatureNotVerified` like `SignatureInvalid` when deciding to rebuild
a chain. pkix-composite and pkix-ct no longer depend on `signature`.

#### `pkix-chain-simple` 0.5.0, `pkix-ac` 0.2.0, `pkix-composite` 0.2.0

Dependency-driven breaking bumps (pkix-path 0.4, x509-cert 0.3).
pkix-composite's `CompositeVerifier` returns `UnsupportedAlgorithm`. pkix-chain-simple's Limitations no longer claim that name
constraints are not validated.

### Workspace: codify temporal-posture non-negotiable in AGENTS.md (PKIX-e3nl)

New non-negotiable #7 in `AGENTS.md`: **current-regime only;
historical and version-pinned postures go out-of-process.** The
workspace's fast in-process `Profile` and `Lint` types snapshot the
current BR text and evaluate "is this cert conforming under today's
rules?" — including rules the spec itself writes as time-keyed (e.g.
SC-081 phased validity cap), because the time-keying is part of the
current rule's definition, not historical replay. The workspace does
NOT ship validators that evaluate against rules in force at a past
time (historical-regime replay) or against a caller-pinned spec
version (version-frozen replay); both postures go through
`pkix-policy-zlint` with a version-pinned lint set.

The rule cuts on a different axis from non-negotiable #5: #5 governs
*who owns* the policy specification (standards-body /
industry-forum / site-local); #7 governs *when* the policy is
evaluated (current-regime in-process / historical or version-pinned
out-of-process). Documents an existing ambiguity in
`ValidationPolicy::new(now_unix)`: the parameter selects the moment
at which validity-period checks are evaluated, NOT the moment whose
rules are in force. The corresponding rustdoc clarification on
`ValidationPolicy::new`, `Profile::policy`, and the
`pkix-chain` use-case wrappers ships separately (PKIX-kgnk).

Pure docs amendment; no behavior change, no code change.

### Workspace: optional `serde` feature on cache-friendly result types (PKIX-2l0v.1)

Five crates gain an optional `serde` feature that derives
`serde::Serialize` / `serde::Deserialize` on their load-bearing
public types, satisfying AGENTS.md non-negotiable #6's
cache-friendliness requirement. The wire form is **format-adaptive**:
human-readable serializers (JSON, TOML, YAML) emit base64-encoded
DER for fields backed by foreign DER types; binary serializers
(postcard, bincode, MessagePack) emit raw DER bytes. Selection is
driven by `serde::Serializer::is_human_readable`.

* **`pkix-path`**: new `serde` feature. Derives on `ValidatedPath`,
  `ValidationPolicy`, `TrustAnchor`, `PolicyTreeNode`, `DnAttrRule`,
  `Error`, `DerError`. New public module `pkix_path::serde_der`
  exposes the format-adaptive (de)serializer helpers for downstream
  use. New crate-level dep on `base64ct` (no_std, MSRV-friendly,
  RustCrypto-family).
* **`pkix-truststore`**: new `serde` feature. Derives on `Error`
  and the new `IoFailure` type.
* **`pkix-revocation`**: new `serde` feature. Derives on `Error`
  and `OutOfScopeReason`. `Option<CrlReason>` wire form uses the
  RFC 5280 §5.3.1 numeric codes (`KeyCompromise = 1`, etc.).
* **`pkix-chain`**: new `serde` feature. Derives on `Error`.
  Activates `serde` on all three wrapped error sources.
* **`pkix-identity`**: new `serde` feature. Derives on `IdentityError`.

Additionally, two structural refactors land alongside the serde
derives because the upstream types they wrap are not
serde-friendly:

* **`pkix-path::DerError`** is no longer a `pub struct DerError(der::Error)`
  tuple struct. It now owns a `Box<str>` Display message that
  survives serde round-trips alongside an `Option<der::Error>` inner
  value. `std::error::Error::source` returns the inner when present;
  it is `None` after a deserialize. `PartialEq` compares only the
  rendered message — two `DerError`s with identical Display output
  are equal regardless of whether their inner field is populated.
  Pre-refactor behaviour is preserved in practice because two
  `der::Error`s with identical `{kind, position}` produce identical
  Display output. `DerError::new(e: der::Error)` is now `pub` so
  sibling workspace crates (`pkix-revocation`, `pkix-truststore`)
  can construct their own `Error::Der`-equivalent variants without
  defining a duplicate type.

* **`pkix-truststore::Error::Io`** changes payload type from
  `std::io::Error` to a new `IoFailure { kind: io::ErrorKind,
  message: String }` struct. This is a **breaking change** —
  pattern matches that bind the inner value need to update; matches
  that bind `_` are unaffected. The OS error code is dropped (low
  value for cache-replay use cases); `io::ErrorKind` and the
  rendered message are preserved. `pkix-truststore` is at version
  0.0.0; the next published 0.x release should bump appropriately.

* **`pkix-truststore::Error::Pem`/`Error::Der`** change payload type
  from `der::Error` to the re-exported `pkix_path::DerError`. Same
  breaking-change classification.

* **`pkix-revocation::DerError`** is now a re-export of
  `pkix_path::DerError` rather than an independent type with
  identical shape. Pattern matches on `pkix_revocation::DerError`
  still work; constructions via the (formerly tuple) `DerError(e)`
  syntax are updated to `DerError::new(e)`.

* **`pkix-chain::Error::ProfileViolation::reason`** and
  **`Error::OcspDelegation::reason`** change field type from
  `&'static str` to `Cow<'static, str>`. Producer code still
  supplies `Cow::Borrowed("literal")`; the deserialize path produces
  `Cow::Owned(String)`. `PartialEq` on `Cow` is content-based, so
  round-trip preserves equality. Pattern matches that bind `reason`
  see a `Cow` instead of a `&str` — callers using `reason.contains(...)`,
  `format!("{reason}")`, or any `Deref`-backed method continue to
  work unchanged.

Departure from PKIX-2l0v.1 cleanup-note locked-in `serde_with = "3"`:
the bead-cleanup pass dismissed the bead's own escalation that bare
`"3"` would draw in a non-MSRV-compatible release. Verified
empirically — `serde_with = "3"` resolves to 3.20.x which requires
rustc 1.88; workspace MSRV is 1.73. A hand-written helper module
(`pkix_path::serde_der`) implements the same format-adaptive wire
form Mark's D1 decision called for, without the dep and without
MSRV risk.

Round-trip integration tests land per crate
(`tests/serde_round_trip.rs`) with independent oracles: hand-computed
expected JSON for wire-form assertions; per-field DER canonicality
(every recovered DER-encodable field re-encodes to bytes byte-equal
to the original) for round-trip assertions.

### `pkix-path`: leaf-only `required_leaf_policy_oids` + `required_leaf_subject_dn_attrs` (PKIX-jbvb.4)

`ValidationPolicy` gains two additive leaf-only predicate fields plus a
new `DnAttrRule` expression type. Both fields default to `None`, so
existing callers see no behavior change. The additions unblock per-tier
S/MIME subscriber-profile differentiation in `pkix-profiles-cabf`
(PKIX-jbvb.1 / .2 / .3) without requiring a custom `Profile`-side
post-validation pass.

- `ValidationPolicy::required_leaf_policy_oids:
  Option<Vec<ObjectIdentifier>>` — when `Some`, the leaf must explicitly
  assert every OID via `CertificatePolicies`. `anyPolicy` does **not**
  satisfy a specific OID. Distinct from `initial_policy_set` (relying
  party's acceptable set) — this checks *assertion*. Violations produce
  the new `Error::MissingLeafPolicyOid { required: ObjectIdentifier }`.
- `ValidationPolicy::required_leaf_subject_dn_attrs:
  Option<DnAttrRule>` — when `Some`, the leaf's Subject DN must satisfy
  the rule. Violations produce the new `Error::SubjectDnAttrRuleUnmet`.
- New public enum `pkix_path::DnAttrRule`: `Field(ObjectIdentifier)`,
  `AllOf(Vec<DnAttrRule>)`, `AnyOf(Vec<DnAttrRule>)`. `#[non_exhaustive]`,
  derives `Clone + Debug + PartialEq + Eq`. Vacuity: `AllOf(vec![])` is
  trivially true, `AnyOf(vec![])` is trivially false. Designed to express
  CA/B Forum S/MIME BR tier rules such as `pseudonym OR (givenName AND
  surname)`. Serde derives gated on the workspace `serde` feature land
  with PKIX-2l0v.1.
- Two new `Error` variants (additive under `#[non_exhaustive]`):
  `MissingLeafPolicyOid { required }` and `SubjectDnAttrRuleUnmet`.
- Enforcement lives at the leaf in `chain_walk` adjacent to
  `required_leaf_eku` (steps `(e3a)` and `(e3b)`). When the policy
  fields are `None`, the new code paths are skipped.
- 20 new tests: 11 unit tests of `evaluate_dn_attr_rule` against
  synthetic `Name` values (composition, vacuity, OID matching) + 9
  integration tests in `tests/required_leaf_policy_dn_pkits.rs` that
  exercise the `Some(cp_ext)` branch and a multi-attribute Subject DN
  via PKITS `AllCertificatesSamePoliciesTest10EE`
  (independently-sourced oracle).

### `pkix-profiles` + `pkix-profiles-cabf`: per-profile shape-check aliases (PKIX-9vnx.9.2)

Profile types now implement `pkix_lint::LintProfile` alongside `Profile`,
exposing their canonical lint set, and ship one-line `check_*_shape`
convenience functions over `pkix_lint::check_shape`.

`pkix-profiles`:

- `BasicTlsProfile` + `impl LintProfile` bundling six RFC 5280 / 6125
  lints (Rfc6125TlsServerSanLint, Rfc5280EkuServerAuthLint,
  Rfc5280BasicConstraintsCaLeafLint,
  Rfc5280SanRequiredWhenSubjectEmptyLint,
  Rfc5280SignatureAlgorithmMatchLint, Rfc5280MaxSerialLengthLint).
- `BasicSmimeProfile` + `impl LintProfile` bundling five RFC 8551 /
  8398 / 5280 lints (Rfc8398SmimeSanLint,
  Rfc8551EkuEmailProtectionLint, Rfc8398SmimeMailboxEquivalenceLint,
  Rfc5280SignatureAlgorithmMatchLint, Rfc5280MaxSerialLengthLint).
- `pub fn check_basic_tls_shape(cert, now_unix) -> Result<(), Vec<Finding>>`.
- `pub fn check_basic_smime_shape(cert, now_unix) -> Result<(), Vec<Finding>>`.
- New runtime deps: `pkix-lint`, `x509-cert`.

`pkix-profiles-cabf`:

- `SmimeProfile` + `impl LintProfile` (currently empty Vec: no
  `cabf_smime_br` module ships in `pkix-lint-cabf` yet).
- `CodeSigningProfile` + `impl LintProfile` (currently empty Vec: no
  `cabf_cs_br` module ships in `pkix-lint-cabf` yet).
- `pub fn check_web_pki_shape(cert, now_unix) -> Result<(), Vec<Finding>>`.
- `pub fn check_smime_shape(cert, now_unix) -> Result<(), Vec<Finding>>`.
- `pub fn check_code_signing_shape(cert, now_unix) -> Result<(), Vec<Finding>>`.
- Already-shipped `WebPkiProfile::impl LintProfile` from PKIX-9vnx.9.2.2
  remains; `check_web_pki_shape` exposes it as a one-line alias.
- New runtime dep: `x509-cert`.

Layered semantics across the five aliases:

- `pkix_profiles::check_basic_*_shape` — RFC baseline only (no CA/B
  Forum overlay).
- `pkix_profiles_cabf::check_*_shape` — CA/B Forum overlay only (no
  RFC-baseline lints duplicated). Callers wanting full coverage run
  both halves.

The cabf S/MIME and CS aliases are intentionally near-no-op today; that
contract is pinned by tests so adding `cabf_smime_br` / `cabf_cs_br`
lint modules to `pkix-lint-cabf` later surfaces the contract change
deliberately rather than silently.

10 new tests across `pkix-profiles/tests/check_shape_aliases.rs` and
`pkix-profiles-cabf/tests/check_shape_aliases.rs`.

### `pkix-policy-zlint` 0.0.0: thin Lint adapter over `pkix-zlint-bridge` (2026-05-13)

New crate. Wraps each zlint catalog check (~400 at the time of writing)
as a workspace `pkix_lint::Lint`, so callers can mix zlint's predicate-
comprehensive CA/B Forum coverage into a `pkix_lint::LintRunner`
alongside the workspace's own RFC-conformance and `-cabf` reference
lints.

Per AGENTS.md non-negotiable #5 (three-mode policy-class model) and the
spec-taxonomy principle (PKIX-mzsk), this is the principled path for
**predicate-comprehensive** CA/B Forum coverage. The hand-authored
`pkix-lint-cabf` reference set covers a small curated subset of marquee
BR predicates; this crate covers the whole catalog.

Public API:

- `pkix_policy_zlint::ZlintLint` — one `Lint` per zlint check.
- `pkix_policy_zlint::all_lints(bridge) -> Result<Vec<Box<dyn Lint>>, BridgeError>`
  — enumerate zlint's catalog and wrap each check.

Design notes:

- `Lint::id()` and `Lint::citation()` return `&'static str`. The bridge's
  `ZlintLintInfo` is `String`-typed (runtime catalog), so `all_lints`
  leaks each `ZlintLintInfo` once at construction via `Box::leak`.
  Bounded leak (~400 small records, one-time at startup); avoids
  broadening the workspace `Lint` trait to `Cow<'static, str>` or
  `Box<str>` for the sake of a single adapter.
- Per-cert subprocess cost is amortised by the bridge's SHA-256 verdict
  cache; each `ZlintLint::check_cert` looks up its check ID in a
  per-cert verdict map produced by one underlying `run_on_cert` call.
- Verdict mapping is fixed: `NotApplicable` → `LintResult::NotApplicable`,
  `Pass` → `LintResult::Pass`, `Notice` and `Warn` → `LintResult::Warn`,
  `Error` → `LintResult::Error`, `Fatal` → `LintResult::Fatal`.

Tested round-trip against the real `zlint` binary using PKITS Trust
Anchor Root Certificate fixture. Integration test auto-skipped when
`zlint` is not on `PATH`, same pattern as `pkix-zlint-bridge`'s own
integration tests.

Tracked as [PKIX-jy95.10].

[PKIX-jy95.10]: https://github.com/MarkAtwood/crate-pkix  "pkix-policy-zlint adapter"

### AGENTS.md: spec-taxonomy principle for `-cabf` crates (2026-05-13)

Articulates what the `-cabf` unprincipled exception in AGENTS.md
non-negotiable #5 actually covers, replacing the ambiguous "small
curated reference set" / "small marquee-violation reference" language.

Decided principle:

- Subscriber-cert taxonomy is **in scope** — one `Profile` per
  BR-named subscriber-cert tier (TLS BR `WebPkiProfile`; S/MIME BR
  four mailbox-binding tiers; Code Signing BR plus EV variant plus
  Time-Stamping). Variant subdivisions within a subscriber profile
  (e.g., EV vs. non-EV TLS) are included.
- CA-cert / Root-cert profiles are **out of scope** — those are
  path-validator concerns handled by RFC 5280 §6.1 in `pkix-path`.
- Per-predicate Lint enforcement is **out of scope** —
  `pkix-policy-zlint` owns predicate-comprehensive coverage. The
  `-cabf` crates own taxonomy coverage; the adapter crate owns
  predicate coverage.
- Maintenance threshold revised: "what AI can grind faithfully from
  each BR refresh under human review," not "what one human can author
  by hand."

The "not a template" bar still holds horizontally: no `-mozilla`,
`-fedramp`, `-dod`, `-etsi` crates without explicit human re-decision.
The principle decides *what* a hypothetical `-X` crate would cover if
admitted, not *which* specs get admitted.

No code change in this commit; the principle was already followed in
practice. The amendment makes the boundary explicit so future agents
and contributors pick it up at session start.

Tracked as [PKIX-mzsk].

[PKIX-mzsk]: https://github.com/MarkAtwood/crate-pkix  "AGENTS.md spec-taxonomy amendment"

### Send + Sync compile-time assertions on result types (2026-05-13)

AGENTS.md non-negotiable #6 requires load-bearing result and error types
to be `Send + Sync` so callers can move values across threads and store
them in shared caches. The rule was previously aspirational — every type
satisfied it via auto-derive (no `Rc<T>`, `RefCell<T>`, or raw
pointers anywhere), but a future field adding `Rc<T>` to an `Error`
variant would silently regress without any compile-time check.

This change adds a `const _: fn() = || { _assert_send_sync::<T>() }`
block to each crate that defines such a type, promoting the
auto-derived `Send + Sync` from happenstance to a compile-time
invariant. Asserted types:

- `pkix-path`: `ValidatedPath`, `Error`, `TrustAnchor`, `ValidationPolicy`
- `pkix-chain`: `Error`
- `pkix-revocation`: `Error`
- `pkix-truststore`: `Error` (the `TrustAnchor` re-export is covered by
  the `pkix-path` assertion)
- `pkix-lint`: `Finding`

No new dependencies (no `static_assertions` crate); the
`const _: fn() = || { ... }` pattern uses only stable Rust.

No behavior change. No version bumps; the assertions are private
`const _` items that do not affect any crate's public API.

Tracked as [PKIX-2l0v.2].

[PKIX-2l0v.2]: https://github.com/MarkAtwood/crate-pkix  "Send+Sync compile-time audit"

### `pkix-lint` 0.9.0: three deferred RFC-conformance lints (2026-05-13)

`pkix-lint` ships the three remaining lints from the PKIX-9vnx.9.2.1
candidate list ([PKIX-9vnx.9.2.1.1]), closing out the 8-of-8 acceptance
criterion for the parent [PKIX-9vnx.9.2.1] batch.

Three new public `Lint` impls:

- `rfc5280::Rfc5280SanRequiredWhenSubjectEmptyLint` — RFC 5280 §4.2.1.6:
  certificates whose Subject is the zero-length `RDNSequence` MUST
  include a `subjectAltName` extension marked as critical. Lint is a
  no-op (`Pass`) for certs with a non-empty Subject; on empty-Subject
  certs it fires `Error` if SAN is absent or not critical.
- `rfc5280::Rfc5280SignatureAlgorithmMatchLint` — RFC 5280 §4.1.1.2:
  the outer `Certificate.signatureAlgorithm` MUST equal the inner
  `tbsCertificate.signature`. Compares both fields structurally using
  x509-cert's `AlgorithmIdentifier` `PartialEq` impl, which catches
  both OID mismatches and parameter-encoding inconsistencies (e.g.
  NULL parameters on one side, absent parameters on the other for
  RSA-PKCS1 — RFC 4055 §2.1 mandates NULL; real-world encoder bugs
  produce mismatches).
- `rfc8398::Rfc8398SmimeMailboxEquivalenceLint` — RFC 8398 §3: when
  both `rfc822Name` and `id-on-SmtpUTF8Mailbox` `OtherName` SAN
  entries are present, every entry of one kind must match some entry
  of the other under byte-equal local-parts and IDN A-label ↔ U-label
  equivalent domains. Domain conversion uses the workspace `idna`
  crate. The pure equivalence helper (`mailbox_equivalent`) is
  unit-tested exhaustively against a hand-written oracle table cross-
  checked with `python3 -c 'import idna; print(idna.encode(...))'`
  for IDN reference encodings.

Tests follow the existing module pattern: at least one positive case
against an existing `pkix-path/tests/fixtures/policy-checks/` fixture,
plus a metadata test pinning `id`, `citation`, `severity`, `scope`,
`applies_to`, `spec_section_id`, and `spec_url`. Negative cases for
all three lints require fixture generation outside the well-behaved
OpenSSL / pyca production path (empty-subject leaf, mismatched
outer/inner sigalg, disagreeing rfc822Name/SmtpUTF8Mailbox pair); per
the bead, those fixtures are explicitly out of scope here and the
positive-only test coverage is the shippable bar.

19 new tests in total (3 lint positive-path cases per RFC module + 3
metadata tests + 9 `mailbox_equivalent` helper tests = 19, contributing
to the lint test count rising from 222 to 241).

One new dependency: `idna` (workspace pin, `default-features = false`,
`features = ["alloc", "compiled_data"]`) added to `pkix-lint`. The
workspace already depended on it transitively via `pkix-identity`.

`pkix-lint` minor-bumped to 0.9.0 (additive: new public types and a
new dependency). No breaking changes; existing 0.8 callers compile
unchanged.

[PKIX-9vnx.9.2.1]: https://github.com/MarkAtwood/crate-pkix  "RFC-conformance shape-check lints batch"
[PKIX-9vnx.9.2.1.1]: https://github.com/MarkAtwood/crate-pkix  "Three deferred RFC-conformance lints"

### `pkix-lint` 0.8.0: `Severity::Notice` variant (2026-05-12)

`pkix-lint::Severity` gains a `Notice` variant slotted between `Info`
and `Warn`. The resulting ordering
`Info < Notice < Warn < Error < Fatal` aligns with both the zlint
catalog ranking (`pass(3) < notice(4) < warn(5) < error(6) <
fatal(7)`) and syslog RFC 5424 §6.2.1 severity ranking
(Informational > Notice > Warning).

The variant is added in support of the planned `pkix-zlint-bridge`
adapter (filed as [PKIX-jy95.7]): zlint catalog `notice`-level checks
need a workspace severity that is distinct from both `Info`
(advisory / best-practice) and `Warn` (SHOULD/RECOMMENDED violation).
Lint-metadata severity comes from the zlint catalog ranking, NOT from
the per-cert verdict level — see the
[PKIX-jy95.2 decision][PKIX-jy95.2].

Additive change. `Severity` is `#[non_exhaustive]`, so adding a
variant is non-breaking for callers that already include a wildcard
arm on external matches. In-tree exhaustive matches in
`pkix-lint::oscal::emit::severity_label` and
`pkix-lint::oscal::parse::parse_action` gain a `Notice` arm
(`"notice"` label, symmetric with the existing
`info`/`warn`/`error`/`fatal` labels).

A new `severity_ordering_is_info_notice_warn_error_fatal` unit test
pins the documented ordering contract so a future variant insertion
cannot silently reorder existing variants.

Out of scope (deferred to [PKIX-jy95.7]): mapping zlint per-cert
verdict levels (`notice`, `warn`, `error`, `fatal`) into
`LintResult` — those continue to map to
`LintResult::error(detail)` regardless of the lint's declared
severity, per the [PKIX-jy95.2 decision][PKIX-jy95.2].

[PKIX-jy95.7]: https://github.com/MarkAtwood/crate-pkix  "Create pkix-zlint-bridge crate"
[PKIX-jy95.2]: https://github.com/MarkAtwood/crate-pkix  "Severity-mapping decision for zlint verdicts"

### `pkix-lint`: RFC-conformance shape-check lints (2026-05-12)

`pkix-lint` gains five new RFC-conformance `Lint` impls covering the
shape-check requirements for `BasicTlsProfile` and `BasicSmimeProfile`
in `pkix-profiles`. These replace what would otherwise be near-empty
`LintProfile::lints()` methods on those profiles, making
`check_basic_tls_shape` / `check_basic_smime_shape` (filed under
[PKIX-9vnx.9.2]) substantive shape-checks once their convenience aliases
land.

Five new lints across four RFC source modules:

- `rfc5280::Rfc5280BasicConstraintsCaLeafLint` — RFC 5280 §4.2.1.9:
  end-entity certs MUST NOT assert `BasicConstraints.cA=TRUE`. Complement
  of `pkix_lint_cabf::cabf_tls_br::BcCaFlagLint` (which requires cA=TRUE
  on intermediates).
- `rfc5280::Rfc5280EkuServerAuthLint` — RFC 5280 §4.2.1.12: TLS server
  end-entity certs MUST assert `id-kp-serverAuth` in `ExtendedKeyUsage`.
  RFC-conformance variant of
  `pkix_lint_cabf::cabf_tls_br::EkuServerAuthLint`.
- `rfc6125::Rfc6125TlsServerSanLint` — RFC 6125 §6.4.1: TLS server certs
  MUST carry a `subjectAltName` containing at least one `dNSName` or
  `iPAddress` entry. Tightens the CABF "SAN required" lint with the
  RFC 6125 type requirement.
- `rfc8398::Rfc8398SmimeSanLint` — RFC 8398 §3 + RFC 5280 §4.2.1.6:
  S/MIME certs MUST carry a `subjectAltName` containing at least one
  `rfc822Name` or `otherName` of type `id-on-SmtpUTF8Mailbox`.
- `rfc8551::Rfc8551EkuEmailProtectionLint` — RFC 5280 §4.2.1.12 + RFC
  8551 §3.3: S/MIME certs MUST assert `id-kp-emailProtection` in
  `ExtendedKeyUsage`.

Two new public modules expose these lints alongside the existing
`rfc5280` module: `rfc6125`, `rfc8398`, `rfc8551`. Module structure
mirrors the workspace convention of one module per standards-body source
(established by `rfc5280`).

Tests use independent oracles: `openssl x509 -text` readings of the
existing fixtures under `pkix-path/tests/fixtures/policy-checks/`. Each
new lint has at least one positive test plus one negative per failure
mode, plus a metadata test pinning `id`, `citation`, `severity`,
`scope`, `applies_to`, `spec_section_id`, and `spec_url`. 13 new tests
total (in addition to the existing 91 lib tests; 104 total).

`pkix-lint` minor-bumped to 0.7.0 (additive: new public modules and
lint impls). No breaking changes; existing 0.6 callers compile
unchanged.

Three further RFC-conformance lints from the original
[PKIX-9vnx.9.2.1] candidate list are deferred to follow-on beads:

- RFC 5280 §4.2.1.6 SAN-when-subject-empty (needs RDN-emptiness logic).
- RFC 5280 §4.1 signatureAlgorithm match between outer `Certificate`
  and `tbsCertificate.signature` (needs `AlgorithmIdentifier` equality).
- RFC 8398 §3 rfc822Name / SmtpUTF8Mailbox pair-equivalence (needs
  cross-SAN-entry semantic comparison).

[PKIX-9vnx.9.2]: https://github.com/MarkAtwood/crate-pkix
[PKIX-9vnx.9.2.1]: https://github.com/MarkAtwood/crate-pkix

### `pkix-chain` + `pkix-profiles`: use-case verify wrappers (2026-05-12)

Five of seven canonical use-case wrappers from PKIX-fmtv.7's
five-axis resolution ship in `pkix-chain`, with matching RFC-baseline
profiles in `pkix-profiles`. Implementation beads:
[PKIX-fmtv.11.2] (TLS server), [PKIX-fmtv.12.2] (S/MIME signer +
recipient), [PKIX-fmtv.13.1] (code signer), [PKIX-fmtv.13.2] (time
stamper).

`pkix-chain` additions:

- `verify_tls_server` — composes `verify_chain` with RFC 6125 SAN
  hostname binding. Caller pre-parses with `ServerName::dns_name` /
  `ServerName::ip_address`.
- `verify_smime_signer` and `verify_smime_recipient` — compose
  `verify_chain` with RFC 5280 §4.2.1.6 / RFC 8398 mailbox binding.
  Caller pre-parses with `MailboxName::parse`. Distinct names
  communicate intent at the call site; the KeyUsage distinction
  (digitalSignature vs keyEncipherment) is encoded in the
  caller-supplied `Profile`.
- `verify_code_signer` — thin composition of `verify_chain` under a
  profile requiring `id-kp-codeSigning`. No identity binding.
- `verify_time_stamper` — composes `verify_chain` with a
  post-validation check enforcing the RFC 3161 §2.3 critical-and-sole
  `id-kp-timeStamping` EKU rule.
- `Error::Identity(IdentityError)` — additive non-exhaustive variant
  for identity-binding failures.
- `Error::ProfileViolation { reason: &'static str }` — additive
  non-exhaustive variant for wrapper-side spec invariants that
  `ValidationPolicy` cannot express (used by `verify_time_stamper`
  for the RFC 3161 §2.3 rule; reusable by future wrappers).
- Re-exports `ServerName`, `MailboxName`, `IdentityError`, and
  `Profile` so callers don't need direct deps on the underlying
  crates.

`pkix-profiles` additions:

- `BasicCodeSigningProfile` + `basic_code_signing_policy` — RFC 5280
  EKU baseline (id-kp-codeSigning only, no SAN requirement).
- `BasicTimeStampingProfile` + `basic_time_stamping_policy` — RFC 3161
  §2.3 EKU baseline (id-kp-timeStamping). The critical-and-sole rule
  is enforced at the wrapper layer rather than in the profile.
- `BasicTlsClientProfile` + `basic_tls_client_policy` — RFC 5280
  §4.2.1.12 EKU baseline (id-kp-clientAuth). Unlike `BasicTlsProfile`
  this does NOT require a SAN at the path layer; client-auth
  deployments commonly carry the identity in the Subject DN, and the
  wrapper layer (`verify_tls_client_dns` / `verify_tls_client_mailbox`)
  handles caller-supplied SAN binding independently. (PKIX-uuiz,
  2026-05-12.)

Two wrappers from the seven-set are deferred pending human design
clarification: `verify_tls_client` ([PKIX-fmtv.11.2.1]) and
`verify_ocsp_responder` ([PKIX-fmtv.13.3]). Both filed as
`human`-labeled beads with concrete option enumerations.

**Update 2026-05-12:** [PKIX-fmtv.11.2.1] resolved; the client half
ships as **two** wrappers — `verify_tls_client_dns(Option<&ServerName>)`
and `verify_tls_client_mailbox(Option<&MailboxName>)` — preserving
type discipline at the call site. Both accept `None` to skip identity
binding (path-only mode). `verify_ocsp_responder` remains deferred.

[PKIX-fmtv.11.2]: https://github.com/MarkAtwood/crate-pkix
[PKIX-fmtv.12.2]: https://github.com/MarkAtwood/crate-pkix
[PKIX-fmtv.13.1]: https://github.com/MarkAtwood/crate-pkix
[PKIX-fmtv.13.2]: https://github.com/MarkAtwood/crate-pkix
[PKIX-fmtv.11.2.1]: https://github.com/MarkAtwood/crate-pkix
[PKIX-fmtv.13.3]: https://github.com/MarkAtwood/crate-pkix

### `pkix-lint 0.6.0`: `Lint::rfc_section_id` / `rfc_url` renamed to `spec_section_id` / `spec_url` (2026-05-12)

Additive rename of two `Lint` trait default methods to reflect that the
slot was never RFC-specific — it accepts CA/B Forum BR, ITU-T X.509,
NIST SP, and other standards-body section identifiers. Filed under
[PKIX-ncab.11] as part of the post-OSCAL-demotion framing cleanup
([PKIX-ncab]).

- `Lint::spec_section_id() -> Option<&str>` is the new canonical name.
- `Lint::spec_url() -> Option<&str>` is the new canonical name.
- `Lint::rfc_section_id()` and `Lint::rfc_url()` remain as
  `#[deprecated(since = "0.6.0")]` default methods that return `None`.
  Override and call the new names; the deprecated aliases are
  independent default impls, so calling them on a lint that overrides
  only the new name returns `None`.
- Doc comments on `title`, `description`, `spec_section_id`, `spec_url`,
  `parameters`, and `set_parameter` were softened to reflect that
  OSCAL emit is one consumer of this metadata rather than its sole
  purpose (post-OSCAL-demotion framing, [`AGENTS.md`][AGENTS]
  non-negotiable #5).
- In-tree consumers updated: `pkix-lint/src/rfc5280.rs` (RFC 5280
  serial-length lint), `pkix-lint/src/oscal/catalog.rs` (Catalog
  emitter and test fixture), `pkix-lint/src/oscal/profile.rs` (test
  fixture), `pkix-lint-cabf/src/cabf_tls_br.rs` (six lint impls), and
  `pkix-lint-cabf/tests/cabf_tls_br_tests.rs` (metadata test
  assertions).
- The deprecated aliases will be removed in a future minor release
  (no earlier than `pkix-lint 0.7.0`).

[PKIX-ncab]: https://github.com/MarkAtwood/crate-pkix  "OSCAL demotion cleanup"
[PKIX-ncab.11]: https://github.com/MarkAtwood/crate-pkix  "Apply .6 decision to Lint trait OSCAL-Control metadata methods"

### pkix-identity — RFC 6125 §6.4 + RFC 5280/8398 identity binding (2026-05-11)

PKIX-fmtv.11.1 and PKIX-fmtv.12.1 fill in the pkix-identity scaffold
with the RFC 6125 §6.4 hostname-binding and RFC 5280 §4.2.1.6 + RFC
8398 mailbox-binding implementations:

- `ServerName::dns_name` — LDH + length validation, ASCII lower-casing,
  IDN U-label → A-label conversion via the `idna` crate.
- `ServerName::ip_address` — IPv4 dotted-quad and IPv6 (with or
  without brackets) → canonical 4- or 16-byte form.
- `verify_dns_name` — walks the leaf's Subject Alternative Name
  extension, matches `GeneralName::DnsName` and `GeneralName::IpAddress`
  entries with case-insensitive exact comparison plus single
  leftmost-label wildcards. CN fallback is intentionally not performed
  (RFC 6125 §6.4.4 deprecates it).
- `MailboxName::parse` — RFC 5322 dot-atom local-part validation,
  non-ASCII local-parts pass through verbatim (RFC 6532), domain
  normalized to lower-case A-label form via the `idna` crate.
- `verify_mailbox` — walks `Rfc822Name` SAN entries for ASCII targets
  and `OtherName(id-on-SmtpUTF8Mailbox)` SAN entries (OID
  1.3.6.1.5.5.7.8.9, RFC 8398 §3) for internationalized targets.
  Decodes the inner `UTF8String` of each `OtherName.value`. Local-part
  match is byte-equal; domain match is ASCII case-insensitive against
  the A-label form so U-label SAN and A-label target (and vice versa)
  interoperate.
- New error variant `IdentityError::MalformedSan` for SAN extensions
  that fail to parse.

Workspace gained an `idna` dependency entry (1.x, no_std + `alloc` +
`compiled_data`); only pkix-identity consumes it. `pkix-identity`'s own
deps gained `idna` and `der` (the `0.1.0` scaffold had only
`x509-cert`).

The `pkix-chain` `verify_tls_server` / `verify_tls_client` /
`verify_smime_signer` / `verify_smime_recipient` wrappers are split
out as PKIX-fmtv.11.2 and PKIX-fmtv.12.2, still blocked on the
PKIX-fmtv.7 wrapper-set decision.

### pkix-identity 0.1.0 — initial scaffold (2026-05-11)

New workspace crate (PKIX-fmtv.21) for cert-side identity matching:
RFC 6125 hostname binding, RFC 5280 §4.2.1.6 + RFC 8398 mailbox
binding, IP literal matching. Pure function over (cert,
identity-string); no chain context, no trust anchors. `no_std`. The
`0.1.0` release ships the public API surface (`ServerName`,
`MailboxName`, `IdentityError`, `verify_dns_name`, `verify_mailbox`)
with stub bodies that return `IdentityError::NotYetImplemented`.
Bodies fill in via PKIX-fmtv.11 (`verify_dns_name` + IDN
normalization) and PKIX-fmtv.12 (`verify_mailbox` + SmtpUTF8Mailbox
handling). The split-out crate is precedented by
`rustls-pki-types::ServerName` + `webpki::SubjectNameRef`; identity
matching is a stateless data transform that does not fit the
`Profile` trait. See [`pkix-identity/README.md`][pi-readme] for
in-scope / out-of-scope discipline. [PKIX-fmtv.21]

[pi-readme]: pkix-identity/README.md

### Workspace: framework / policy split (2026-05-11)

The workspace stance encoded in [`AGENTS.md`][AGENTS] non-negotiable #6
(PKIX-amgn) splits standards-body mechanisms from industry-forum policy
content across crate boundaries. Core crates ship the framework + RFC
baselines; CA/B Forum content lives in sibling `-cabf` reference crates
marked "not authoritative."

Crate boundary changes that landed across the PKIX-amgn umbrella:

```
pkix-profiles  →  pkix-profiles-cabf  (WebPkiProfile, SmimeProfile,
                                       CodeSigningProfile, sc081_validity_cap,
                                       CABF_*_ALLOWED_ALGS)             [PKIX-amgn.4]
pkix-lint      →  pkix-lint-cabf      (cabf_tls_br module: ValidityMaxLint,
                                       Sha1ProhibitedLint, RsaMinKeySizeLint,
                                       SanRequiredLint, EkuServerAuthLint,
                                       BcCaFlagLint, CabfTlsBrProfile,
                                       all_lints)                       [PKIX-amgn.5]
```

The `-cabf` crates carry a "reference, not authoritative" rustdoc header
and are explicitly not maintained as canonical CA/B Forum encodings. They
are intended as a starting point: fork and adapt to your deployment's
current interpretation of the BR text.

Migration for downstream consumers:

```toml
# Cargo.toml — add a dep on the relevant -cabf crate
pkix-profiles      = "0.3"
pkix-profiles-cabf = "0.2"  # CA/B Forum Profile types
pkix-lint          = "0.5"
pkix-lint-cabf     = "0.2"  # CA/B Forum lint bundles
```

```rust
// Profile types
- use pkix_profiles::{WebPkiProfile, SmimeProfile, CodeSigningProfile};
+ use pkix_profiles_cabf::{WebPkiProfile, SmimeProfile, CodeSigningProfile};

// SC-081 helper
- use pkix_profiles::sc081_validity_cap;
+ use pkix_profiles_cabf::sc081_validity_cap;

// CA/B Forum lint bundle
- use pkix_lint::cabf_tls_br::CabfTlsBrProfile;
+ use pkix_lint_cabf::cabf_tls_br::CabfTlsBrProfile;
```

Retained in `pkix-profiles` 0.3.0:

- `Profile` trait + `ValidationPolicy` re-exports.
- `BasicTlsProfile` — RFC 5280 + RFC 6125 + universally-required
  `id-kp-serverAuth` EKU.
- `BasicSmimeProfile` — RFC 8551 §3 baseline (`id-kp-emailProtection`
  EKU + `rfc822Name` SAN).
- Deprecated re-exports of the CA/B Forum types from
  `pkix-profiles-cabf` (drop in 0.4.0).

Retained in `pkix-lint` 0.5.0:

- Framework: `Lint`, `LintRunner`, `LintProfile`, `Finding`,
  `EvaluationReport`, `Deviation`, `DeviationStore`, `DeviationRunner`.
- OSCAL Catalog + Profile machinery (`oscal::catalog::catalog_from_lints`,
  `oscal::parse::lint_ids_from_catalog`, `oscal::profile::resolve_profile`,
  `oscal::emit::assessment_results`).
- RFC-conformance lint bundle (`rfc5280::Rfc5280MaxSerialLengthLint`).

See [PKIX-amgn] for the full rationale and the framework/policy stance
encoded in [`AGENTS.md`][AGENTS] non-negotiable #6.

[AGENTS]: ./AGENTS.md
[PKIX-amgn]: ./AGENTS.md

### `pkix-lint 0.5.0` + `pkix-lint-cabf 0.2.0`: CA/B Forum bundle migration (2026-05-11)

**BREAKING.** PKIX-amgn.5 — refactor `pkix-lint` to ship only the framework
plus standards-body (RFC) conformance lints; the CA/B Forum TLS BR lint
bundle (`cabf_tls_br`) moves to the sibling `pkix-lint-cabf` reference
crate per the workspace framework-not-policy stance (`AGENTS.md`
non-negotiable #6, PKIX-amgn).

Moved out of `pkix-lint` 0.4.0 → into `pkix-lint-cabf` 0.2.0:

- `cabf_tls_br` module
  - Types: `ValidityMaxLint`, `Sha1ProhibitedLint`, `RsaMinKeySizeLint`,
    `SanRequiredLint`, `EkuServerAuthLint`, `BcCaFlagLint`,
    `CabfTlsBrProfile`.
  - Free function: `all_lints() -> Vec<Box<dyn Lint>>`.
- Integration tests (`tests/cabf_tls_br_tests.rs`).

Stays in `pkix-lint` 0.5.0:

- Framework: `Lint`, `LintRunner`, `LintProfile`, `LintResult`, `Finding`,
  `Scope`, `Severity`, `SubjectKind`, `LintParameter`, `ParameterError`.
- `report::EvaluationReport`, `deviation::DeviationStore`,
  `deviation::DeviationRunner`, `deviation::Deviation`.
- OSCAL Catalog + Profile machinery (`oscal::catalog::catalog_from_lints`,
  `oscal::parse::lint_ids_from_catalog`, `oscal::profile::resolve_profile`,
  `oscal::emit::*`).
- RFC-conformance lints (`rfc5280::Rfc5280MaxSerialLengthLint`).

Migration:

```rust
// before (pkix-lint 0.4.0):
use pkix_lint::cabf_tls_br::CabfTlsBrProfile;

// after (pkix-lint 0.5.0 + pkix-lint-cabf 0.2.0):
use pkix_lint_cabf::cabf_tls_br::CabfTlsBrProfile;
```

Downstream consumers must add `pkix-lint-cabf` to their `Cargo.toml` to
continue using the CA/B Forum TLS BR lint bundle. `pkix-lint` no longer
depends on `pkix-profiles-cabf`; that dep moves to `pkix-lint-cabf`.

OSCAL catalog/profile tests inside `pkix-lint` previously used
`cabf_tls_br::ValidityMaxLint` and `cabf_tls_br::all_lints()` as
fixtures. Those tests now use a self-contained `PolicyShapedLint` test
fixture (rfc_section_id set, rfc_url left None — same metadata shape)
and an in-crate `multi_lint_fixture()` so `pkix-lint`'s tests stay
independent of CA/B Forum policy content. Cross-crate round-trip
coverage against the real CA/B Forum lint set continues in
`pkix-lint-cabf`'s integration tests.

`pkix-lint-cabf` 0.2.0 carries the same "reference / not authoritative"
crate-level rustdoc disclaimer as the existing 0.1.0 stub. Future bundles
(`cabf_smime_br`, `cabf_cs_br`) and zlint-derived OSCAL Catalogs will
land via PKIX-amgn.8 and friends.

### `pkix-path-builder 0.3.1`: `build_first_valid_path<V>` helper (2026-05-11)

**Additive.** PKIX-lwr9.4.2 — closes the consumer ergonomics gap surfaced
by PKIX-lwr9.4 / BetterTLS tc60: [`build_path`] is single-shot and has no
[`SignatureVerifier`] dependency, so it cannot know which of its DFS
candidates will be rejected downstream by [`pkix_path::validate_path`]
(e.g., cross-signed pools containing an intermediate signed under an
algorithm the verifier does not dispatch).

New functions in `pkix_path_builder`:

```rust
pub fn build_first_valid_path<V>(
    target: &Certificate,
    pool: &CertPool,
    anchors: &[pkix_path::TrustAnchor],
    policy: &pkix_path::ValidationPolicy,
    verifier: &V,
) -> Result<Vec<Certificate>>
where
    V: pkix_path::SignatureVerifier;

pub fn build_first_valid_path_with_config<V>(
    target: &Certificate,
    pool: &CertPool,
    anchors: &[pkix_path::TrustAnchor],
    policy: &pkix_path::ValidationPolicy,
    verifier: &V,
    config: &PathBuilderConfig,
) -> Result<Vec<Certificate>>
where
    V: pkix_path::SignatureVerifier;
```

Semantics: iterate [`build_path_candidates`] until the first candidate
chain passes [`pkix_path::validate_path`]. Return that chain. If every
candidate is rejected, surface the new `Error::NoValidPath { tried,
last_error }` variant. Zero-yield exhaustion still surfaces as
`Error::NoPathFound` (matches `build_path`'s contract).

New error variant on the `#[non_exhaustive]` `Error` enum:

```rust
NoValidPath {
    tried: usize,
    last_error: String,
},
```

The inner `pkix_path::Error` is rendered to `String` rather than carried
verbatim so the builder's `Error` enum retains its `Hash` derive
(`pkix_path::Error` is not `Hash`). Consumers needing programmatic match
on inner errors should drop to `build_path_candidates` and call
`validate_path` per candidate themselves.

Rustdoc updates: `build_path`, `PathCandidates`, and the new helpers
cross-reference each other under a three-way "Choosing between ..."
heading. Existing signatures unchanged.

Three new integration tests in `tests/build_first_valid_path.rs`:

- Positive: BetterTLS tc60 fixture (cross-signed depth-6 pool, one
  intermediate uses ecdsa-with-SHA1 which `DefaultVerifier` does not
  dispatch). `build_path` returns a chain that `validate_path` rejects
  with `SignatureInvalid { index: 3 }`; `build_first_valid_path` iterates
  past that candidate and returns a SHA-256-only chain that validates.
- `NoValidPath`: PKITS §4.1.1 chain paired with an `AlwaysRejectVerifier`
  that rejects every signature. Confirms `tried >= 1` and `last_error`
  populated.
- `NoPathFound` passthrough: empty pool. Confirms zero-yield exhaustion
  surfaces as `NoPathFound`, not `NoValidPath { tried: 0 }`.

New dev-dependencies (workspace-pinned): `spki`, `signature`. Required to
spell out the `SignatureVerifier` trait's argument types in the
`AlwaysRejectVerifier` impl in the new test.

### `pkix-lint 0.4.0`: OSCAL Catalog round-trip + id-pair runner (2026-05-11)

**Additive.** PKIX-9vnx.6.3 — closes the OSCAL Catalog round-trip loop.

New function in `pkix_lint::oscal::parse`:

```rust
pub fn lint_ids_from_catalog(value: &Value) -> Result<Vec<String>, ParseError>
```

Walks an OSCAL Catalog JSON Value and returns the ordered list of
Control ids. Parser is intentionally narrow — it accepts the shape
emitted by `catalog_from_lints`, not arbitrary OSCAL Catalogs nested
inside `groups[]` or keyed off `class`.

New method on `LintRunner` (feature-gated behind `oscal`):

```rust
pub fn filter_to_ids(self, ids: &[String])
    -> Result<LintRunner, oscal::parse::ParseError>
```

Returns a new `LintRunner` containing only the lints whose `id()`
appears in `ids`, in the order `ids` requests them. Unknown ids
(`UnknownLintId`) error. Duplicates in `ids` are silently deduplicated
(OSCAL Catalogs forbid duplicate Control ids). `bundle_version` is
preserved.

`ParseError` grew six Catalog-side variants (`CatalogNotObject`,
`CatalogMissingWrapper`, `ControlsNotArray`, `ControlNotObject`,
`ControlMissingId`, `ControlIdNotString`, `ControlIdEmpty`) plus
`UnknownLintId` for the filter step. `non_exhaustive` made these
additions non-breaking.

Ten new tests in `oscal::catalog::tests`: id extraction order, full
emit → serialise → parse → filter → run round-trip on the six CABF
lints with a fixture chain asserting identical Findings (independent
oracle: the pkix-lint engine itself is shared substrate, the test
verifies the lint-set survives round-trip), unknown-id error path,
id-order preservation, subset drop, bundle-version preservation, and
four malformed-input rejection paths (non-object root, missing
wrapper, non-array controls, control missing id).

Test counts: oscal 211 (was 201), all-features 217 (was 207).

### `pkix-lint 0.4.0`: OSCAL Catalog JSON emitter for registered lints (2026-05-11)

**Additive.** PKIX-9vnx.6.2 — new module
`pkix_lint::oscal::catalog::catalog_from_lints` projects a slice of
`Box<dyn Lint>` onto an OSCAL Catalog v1.1.2 JSON Value.

```rust
pub fn catalog_from_lints(
    lints: &[Box<dyn crate::Lint>],
    catalog_id: &str,
    catalog_version: &str,
) -> serde_json::Value
```

Each `Lint` impl maps to one OSCAL Control: `id` from `Lint::id`,
`title` from `Lint::title`, citation / severity / scope / applies-to /
section-id / lint-id / control-uuid as `pkix-lint.*` props,
`Lint::rfc_url` as a `rel="reference"` link,
`Lint::description` (when `Some`) as a `parts[statement]` prose block,
and `Lint::parameters` as OSCAL `params[]` with the parameter id
namespaced as `<lint_id>.<param_id>` to avoid collisions across lints.

UUIDs are derived deterministically from `(catalog_id, catalog_version,
lint_id, param_id)` via the existing `uuid_v8` helper (SHA-256-seeded
RFC 9562 §5.8 UUIDv8); `metadata.last-modified` is pinned to
`1970-01-01T00:00:00Z` for byte-deterministic output. Callers needing
a wall-clock timestamp post-edit the returned Value.

Parameters land in this bead rather than waiting for PKIX-9vnx.6.5 —
the Catalog Control is the natural place to *declare* parameters with
defaults; `.6.5` covers the Profile-side `modify` directive that
*overrides* them at composition time, which is a distinct concern.

`emit::prop`, `emit::uuid_v8`, `emit::severity_label`, and two new
helpers (`scope_label`, `subject_kind_label`) became `pub(super)` so
the catalog submodule can share them without duplication.

Eight new tests under `oscal::catalog::tests` cover structural
required-field presence, the rfc5280 → Control mapping, the CABF
no-rfc-url omission case, byte determinism, UUID derivation
independent-oracle recomputation, version-change UUID invalidation,
empty input, and parameter id namespacing. Test counts:
`pkix-lint --features oscal` 201 (was 193), `--all-features` 207 (was 199).

### `pkix-lint 0.4.0`: `LintParameter` + first RFC-conformance lint (2026-05-11)

**Additive.** PKIX-9vnx.6.4 — Lint parameter mechanism and the first
RFC-conformance lint demonstrate it end-to-end.

New public types in `pkix-lint`:

```rust
pub struct LintParameter {
    pub id: Cow<'static, str>,
    pub label: Cow<'static, str>,
    pub default_value: Cow<'static, str>,
}

pub enum ParameterError {
    UnknownParameter(String),
    InvalidValue { id: String, reason: String },
}
```

New default-provided trait methods on `Lint`:

```rust
fn parameters(&self) -> &[LintParameter] { &[] }
fn set_parameter(&mut self, id: &str, value: &str)
    -> Result<(), ParameterError> { ... default rejects all ids ... }
```

`LintParameter` is descriptor-only — it maps onto an OSCAL Catalog
`Parameter` (id, label, default value) and does not hold the lint's
current value. Lints store typed state directly (`usize`, `Duration`,
etc.); `set_parameter` parses the string-rendered override into that
state. `&mut self` is required because parameter updates change
behaviour; callers configure parameters before installing the lint
into a `LintRunner` (the runner exposes no mutation).

New module `pkix_lint::rfc5280` with the first RFC-conformance lint:

* **`Rfc5280MaxSerialLengthLint`** — RFC 5280 §4.1.2.2: certificate
  serialNumber must not exceed 20 octets. Parametric on `max-octets`
  (default 20). First built-in lint in `pkix-lint` proper; all other
  shipped lints are still CA/B Forum-shaped in `cabf_tls_br` (they
  migrate to `pkix-lint-cabf` via PKIX-amgn.5).

Nine new tests cover the lint's behaviour, parameter machinery,
boundary conditions, and metadata, with `openssl x509 -serial` as the
independent oracle for fixture serial-length values. Test counts:
pkix-lint default 130 (was 121), `--features oscal` 193 (was 184),
`--all-features` 199 (was 190).

### `pkix-lint 0.4.0`: `Lint` trait grows OSCAL-Control metadata methods (2026-05-11)

**Additive.** Four new default-provided methods on the `Lint` trait
(PKIX-9vnx.6.1 — first step toward emitting each `Lint` impl as an OSCAL
Catalog `Control`):

```rust
fn title(&self) -> &str { self.id() }
fn description(&self) -> Option<&str> { None }
fn rfc_section_id(&self) -> Option<&str> { None }
fn rfc_url(&self) -> Option<&str> { None }
```

`title` defaults to `id()`; the other three default to `None`. All
existing `Lint` impls keep compiling unchanged. The six CABF TLS BR
lints in `cabf_tls_br.rs` override `title` and `rfc_section_id` with
human-readable titles and OSCAL Control-id-shaped strings
(`cabf-tls-br-<section>`). `rfc_url` stays `None` for CABF lints
because the CA/B Forum publishes BR documents as versioned PDFs without
stable per-section anchors.

`rfc_section_id` accepts any standards-body section identifier in
`<source>-<section>` shape — IETF RFC (`rfc5280-4.2.1.9`), CA/B Forum
(`cabf-tls-br-6.3.2`), ITU-T X.509, NIST SP, etc. The method name is
kept as-spec'd by PKIX-9vnx.6's design discussion; the rustdoc
documents the generic semantics.

Seven new tests in `tests/cabf_tls_br_tests.rs` pin the metadata for
each CABF lint plus the default behavior of an override-less `Lint`
impl.

### `pkix-lint 0.4.0`: `DeviationScope` refactor to open-ended kind + props bag (2026-05-11)

**BREAKING.** Replaces `pub enum DeviationScope { Any, IssuerDnContains(String),
IssuerDnExact(Name), SerialRange { ... } }` with a struct:

```rust
pub struct DeviationScope {
    pub kind: String,                            // e.g. "pkix-lint.scope.issuer-dn-exact"
    pub props: Vec<(String, ScopePropValue)>,
}

#[non_exhaustive]
pub enum ScopePropValue {
    Text(String),
    Bytes(Vec<u8>),
}
```

The shape mirrors OSCAL Subject (kind discriminator + typed props bag) per
the workspace OSCAL alignment stance (PKIX-9vnx / PKIX-ztmr). Future scope
axes (PKIX-8mzp's planned `SubjectDnContains`, `PolicyOid`, etc.) are now
expressible via new `kind` strings + props without growing the public Rust
enum surface.

**Migration** — replace direct enum-variant construction with the new
constructors:

```rust
// Before (pkix-lint 0.3.x):
let s = DeviationScope::Any;
let s = DeviationScope::IssuerDnContains("agency x".to_string());
let s = DeviationScope::IssuerDnExact(cert.tbs_certificate.subject.clone());
let s = DeviationScope::SerialRange {
    issuer: cert.tbs_certificate.subject.clone(),
    start: vec![0x01], end: vec![0x02],
};

// After (pkix-lint 0.4.x):
let s = DeviationScope::any();
let s = DeviationScope::issuer_dn_contains("agency x");
let s = DeviationScope::issuer_dn_exact(&cert.tbs_certificate.subject)?;
let s = DeviationScope::serial_range(&cert.tbs_certificate.subject, vec![0x01], vec![0x02])?;
```

Public constants are exported for the four canonical kind discriminators
and the four canonical prop names: `SCOPE_KIND_ANY`,
`SCOPE_KIND_ISSUER_DN_CONTAINS`, `SCOPE_KIND_ISSUER_DN_EXACT`,
`SCOPE_KIND_SERIAL_RANGE`; `PROP_ISSUER_DN_SUBSTRING`,
`PROP_ISSUER_DN_DER`, `PROP_SERIAL_START`, `PROP_SERIAL_END`.

**Round-trip preservation.** The OSCAL emit and parse layers are unchanged
at the JSON-wire level — the same subject `type` discriminators and prop
names. Stores that round-trip through OSCAL JSON before and after this
release produce bit-identical output.

**Fail-closed semantics.** `DeviationScope::matches` returns `false` for
unknown kinds, for missing props, for wrong-typed props (e.g. `Text` where
`Bytes` is expected), and for malformed DER under the
`pkix-lint.issuer-dn-der` prop. Code-built scopes go through constructors
and cannot hit these paths; only hand-built scopes (or hand-edited OSCAL
JSON that bypasses the parser) can. The OSCAL parser rejects malformed
input before constructing a `DeviationScope`.

Tracked as PKIX-9vnx.11.

### `pkix-path`: integration tests gated on algorithm features (2026-05-11)

Test-only. `cargo test -p pkix-path --no-default-features` previously
failed to compile the integration test crates because they
unconditionally import `DefaultVerifier`, which is itself gated on
`any(feature = "p256", feature = "p384", feature = "rsa")`. Each of the
nine integration test files now carries the matching `#![cfg(...)]`
attribute, so `--no-default-features` compiles cleanly (yielding an
empty test suite per the integration test crate, which is the
intended behaviour when no algorithm backend is enabled). No runtime
behaviour change. Tracked as PKIX-yg2r.

### `pkix-profiles 0.3.0` + `pkix-profiles-cabf 0.2.0`: framework-not-policy split (2026-05-11)

**BREAKING for `pkix-profiles 0.3.0`. Substantive content release for `pkix-profiles-cabf 0.2.0`.**

CA/Browser Forum-specific profile content moved from `pkix-profiles` to
the sibling `pkix-profiles-cabf` crate per the framework-not-policy
workspace stance (PKIX-amgn):

- `WebPkiProfile`, `SmimeProfile`, `CodeSigningProfile` and their
  `web_pki_policy`/`smime_policy`/`code_signing_policy` aliases.
- `sc081_validity_cap()` (CA/B Forum SC-081 phased validity).
- `CABF_TLS_BR_ALLOWED_ALGS`, `CABF_SMIME_BR_ALLOWED_ALGS`,
  `CABF_CS_BR_ALLOWED_ALGS` (the latter three are now `pub` in
  `pkix-profiles-cabf`; in `pkix-profiles 0.2.x` they were
  crate-private).

`pkix-profiles 0.3.0` keeps RFC-baseline content:

- `Rfc5280Profile` / `rfc5280_policy` (unchanged from 0.2.x).
- New `BasicTlsProfile` / `basic_tls_policy` — RFC 5280 + RFC 6125 +
  `id-kp-serverAuth` EKU. No CA/B Forum overlay.
- New `BasicSmimeProfile` / `basic_smime_policy` — RFC 8551 §3 baseline:
  `id-kp-emailProtection` EKU + `rfc822Name` SAN. No CA/B Forum overlay.

`pkix-profiles 0.3.x` carries deprecated `pub use` re-exports of the
moved symbols (`WebPkiProfile`, `SmimeProfile`, `CodeSigningProfile`,
`web_pki_policy`, `smime_policy`, `code_signing_policy`,
`sc081_validity_cap`) so existing `use pkix_profiles::WebPkiProfile;`
imports continue to compile with a deprecation warning. The re-exports
drop in `pkix-profiles 0.4.0`. Migration:

```rust
// Before (pkix-profiles 0.2.x):
use pkix_profiles::{WebPkiProfile, web_pki_policy, sc081_validity_cap};

// After (pkix-profiles-cabf 0.2.x):
use pkix_profiles_cabf::{WebPkiProfile, web_pki_policy, sc081_validity_cap};
```

`pkix-lint`'s `cabf_tls_br` module migrated to the new crate as part of
this change; the `pkix-profiles` dependency was replaced with
`pkix-profiles-cabf` in `pkix-lint`'s `Cargo.toml`. (`cabf_tls_br` itself
is slated to move to `pkix-lint-cabf` via PKIX-amgn.5.)

`pkix-profiles-cabf 0.1.0` was a namespace-reservation stub with no
public types; `0.2.0` is the first substantive content release. Tracked
as PKIX-amgn.4.

### `pkix-path`: `ValidationPolicy::require_crl_sign_on_cas` opt-in flag (2026-05-11)

Additive. New `ValidationPolicy::require_crl_sign_on_cas: bool` (default
`false`). When `true`, an intermediate CA certificate whose `KeyUsage`
extension is present but does not include `cRLSign` is rejected with the
new `Error::CrlSignMissing { index }` variant. Default behaviour is
unchanged (the RFC 5280 §6.1 literal reading does not require this check).
Restores PKITS §4.7.4 / §4.7.5 conformance for callers who opt in.
`Error` is `#[non_exhaustive]`, so the new variant is additive. See
`INTEROP.md` §7 for the divergence rationale. Tracked as PKIX-0x9z.

### `pkix-revocation`: path-level CRL signer discovery (RFC 5280 §6.3.3(f)) (2026-05-11)

Additive. New public API for locating a CRL's signer in a caller-supplied
bundle without inverting the workspace's one-way dep direction
(`pkix-chain` → `pkix-revocation` → `pkix-path`):

- New free helper `pkix_revocation::discover_crl_signer(bundle, &crl) ->
  Option<&Certificate>`. AKI/SKI walk (RFC 5280 §4.2.1.1 / §4.2.1.2) with
  issuer-DN fallback. No signature verification — discovery only.
- New constructor `CrlChecker::new_with_signer_discovery(crl_der, bundle,
  cert_to_check, now, verifier)`. Runs discovery, gates the result on
  `cRLSign` in `KeyUsage` per §6.3.3(f), and performs a structural
  anchor-reachability walk (the discovered signer must reach a self-signed
  cert by repeated AKI/SKI or issuer-DN steps within the bundle).
- New `Error` variants: `CrlSignerNotFound`, `CrlSignerNotTrusted`. `Error`
  is `#[non_exhaustive]`, so this is additive.
- PKITS §4.5 integration tests (`pkix-revocation/tests/pkits_4_5.rs`)
  rewritten to use the new constructor in place of the prior manual
  AKI/SKI workaround.

The structural anchor-reachability check is intentionally lenient: it
does NOT verify signatures along the signer's chain. Full RFC 5280 §6.1
validation of the signer's path remains the responsibility of higher-layer
composers such as `pkix-chain`. Tradeoff stance tracked as PKIX-yi7k.1.
Tracked as PKIX-cqwt.

### Policy: drop v0.x milestone gating (2026-05-11)

Dropped v0.x milestone gating across the workspace. The project drives to
full RFC 5280 and adjacent-RFC coverage; no features are gated by a version
milestone. Per-crate `# Limitations` rustdoc sections continue to describe
current shipped behavior and shrink as features land — not by editorial
fiat, but when the underlying code changes. Sweep tracked as PKIX-agp7.

### Coordinated 0.3 follow-up wave (May 2026)

The `pkix-path 0.3.0` release on git is the centerpiece of a coordinated
follow-up to the May-2026 0.3 wave already published on crates.io. Five
crates ship together to keep the dep graph consistent across crates.io
once published:

| Crate | Old (crates.io) | New (this release) | Type |
|---|---|---|---|
| `pkix-path` | 0.2.1 | **0.3.0** | BREAKING (`ValidatedPath` loses `Copy` / `Hash`; new owned-data fields) |
| `pkix-revocation` | 0.3.0 | **0.3.2** | additive (CDP/IDP variant + RevocationFetchFailed variant + dep on pkix-path 0.3) |
| `pkix-chain` | 0.3.0 | **0.4.0** | TRANSITIVELY BREAKING (re-exports `pkix-path::ValidatedPath`) |
| `pkix-chain-simple` | 0.3.0 | **0.4.0** | TRANSITIVELY BREAKING (same rationale) |
| `pkix-path-builder` | 0.2.1 | **0.3.0** | BREAKING (dep major bump + skip-not-fail behavior change) |

Why a follow-up release: `pkix-revocation 0.3.0` was published on
crates.io on 2026-05-08 with a frozen `pkix-path = "^0.2.1"` dep. With
`pkix-path 0.3.0` on git, the published `pkix-revocation 0.3.0` cannot
depend on it (Cargo pre-1.0 SemVer treats 0.2.x and 0.3.x as
incompatible). The 0.3.1 / 0.4.0 / 0.3.0 bumps below restore a clean
dep graph on crates.io once the wave is published.

Publish order (dependency-graph-respecting):
1. `pkix-path 0.3.0`
2. `pkix-revocation 0.3.2`
3. `pkix-path-builder 0.3.0`
4. `pkix-chain 0.4.0`
5. `pkix-chain-simple 0.4.0`

`pkix-profiles`, `pkix-lint`, `pkix-difftest` are NOT bumped in this
wave — they have low download counts on crates.io, no urgent consumer
need, and can ride a future 0.3.x wave when they actually change.
Consumers who pull these crates from crates.io will continue to get
their existing 0.2.x versions (which depend on `pkix-path 0.2.x` from
crates.io); a fresh project that wants `pkix-path 0.3.0` features
should consume `pkix-path` directly rather than transitively via these
secondary crates until they ship updates.

### `pkix-lint 0.3.0`

BREAKING. Two coordinated changes ship in 0.3.0:

1. `LintResult` detail field migrated to `Cow<'static, str>` (PKIX-ua6q).
2. `Finding.cert_sha256: Option<[u8; 32]>` added for evidence-pack
   provenance (PKIX-a86q).

The first sub-change is the LintResult migration: `LintResult::Warn`,
`LintResult::Error`, and `LintResult::Fatal` now carry `Cow<'static, str>`
instead of `&'static str`. Static string literals stay zero-allocation
(via `Cow::Borrowed`); runtime-formatted strings (e.g. `format!(...)`)
work without leaking memory (via `Cow::Owned`).

#### Changed (breaking)

- `LintResult::Warn(&'static str)` → `LintResult::Warn(Cow<'static, str>)`.
  Same for `Error` and `Fatal`.
- `LintResult::detail` returns `Option<&str>` (borrowed from `self`) rather
  than `Option<&'static str>`. The borrow's lifetime is tied to `self`.
- `Finding`, `DeviatedFinding`, and `EvaluationReport` lose their
  `'de: 'static` serde deserialization bound. Deserialization no longer
  leaks heap allocations from `LintResult` detail strings, fixing the
  long-running-service memory growth documented in the prior crate's
  `de_static_str` rustdoc. `serde_json::from_slice` (which could not be
  used before because of `'de: 'static`) now works.
- The internal `de_static_str` serde helper is removed (no longer needed).

#### Added

- `LintResult::warn`, `LintResult::error`, and `LintResult::fatal`
  constructor helpers taking `impl Into<Cow<'static, str>>`. Use these for
  ergonomic construction from both static literals and runtime strings:

  ```rust
  use pkix_lint::LintResult;
  let r1 = LintResult::warn("static text");           // Cow::Borrowed
  let bits = 1024u32;
  let r2 = LintResult::error(format!("RSA modulus {bits} bits < 2048"));
  ```

- One new lint detail in `cabf_tls_br::Sc081ValidityMaxLint` demonstrates
  `Cow::Owned` usage: the cap-violation error now reports the actual cert
  duration in days and the cap in effect at issuance, instead of a static
  "exceeds cap" message. Audit trails see the offending value.

- `Finding.cert_sha256: Option<[u8; 32]>` (PKIX-a86q). SHA-256 of the
  DER-encoded certificate that triggered the finding, pinning the
  finding to a specific cert by content hash so evidence packs are
  replayable. `Some(hash)` for cert-scope findings (populated by
  `LintRunner::run_cert`), `None` for path-scope findings (no single
  triggering cert). JSON serialisation uses a lowercase 64-char hex
  string; binary serde formats emit the same hex-string form for
  consistency. Adds a direct `sha2` dependency (already transitive via
  `x509-cert`, so the binary footprint cost is zero).

- `oscal` cargo feature exposing `pkix_lint::oscal::emit::assessment_results`,
  `pkix_lint::oscal::emit::risks_from_store`, and
  `pkix_lint::oscal::parse::deviation_store_from_risks`
  (PKIX-9vnx.3 + .4 + .5 + .10, Architecture 2 per PKIX-ztmr).
  - `assessment_results(&EvaluationReport) -> serde_json::Value` projects
    an evaluation run into a NIST OSCAL v1.1.2 Assessment Results
    `serde_json::Value` document — top-level `assessment-results` with
    `metadata`, `import-ap`, and one `results[]` entry containing
    evidence-deduplicated Observations and per-lint Findings.
    Observations are keyed by `(cert_sha256, cert_index)` so multiple
    Findings sharing one piece of evidence (e.g., multiple lints on the
    same cert) reference one Observation via `related-observations`,
    matching OSCAL's intended 1:N Observation:Finding cardinality.
    Path-scope findings (both keys `None`) share a single
    "path-scope" Observation. Each Finding's `target.status.state` is
    `satisfied` for Pass/NotApplicable and `not-satisfied` for
    Warn/Error/Fatal; lint-specific metadata (`lint-id`, `citation`,
    `severity`) lives on the Finding side as props. Per-run
    `DeviatedFinding`s become Risks with `status="deviation-approved"`.
  - `risks_from_store(&DeviationStore) -> Vec<serde_json::Value>`
    projects a deviation policy as a JSON array of OSCAL Risk objects.
    Each `Deviation` becomes one Risk carrying the full set of props
    needed for lossless reconstruction (id, target_lint, action,
    authorized_by, effective_start/end, evidence_uri), plus the scope
    encoded as OSCAL Subjects with type-specific props. `IssuerDnExact`
    and `SerialRange` scopes carry both a human-readable DN string and
    the DER bytes hex-encoded for lossless reconstruction.
  - `deviation_store_from_risks(&serde_json::Value) -> Result<DeviationStore, ParseError>`
    is the inverse of `risks_from_store`: it reconstructs a
    `DeviationStore` from a JSON array of OSCAL Risk objects in the
    shape this crate emits. `(emit . parse)` over any non-empty store
    yields an `Eq`-equal store, closing the round-trip loop for
    deviation-policy persistence. The parser is intentionally narrow —
    it accepts the exact shape emitted by `risks_from_store`, not
    arbitrary OSCAL Risk documents authored by other tools — which
    keeps the error surface tight and the round-trip contract
    guaranteed by construction. The DN-DER prop
    (`pkix-lint.issuer-dn-der`) is the canonical oracle for `Name`
    reconstruction; the companion RFC-4514 string prop is
    informational and ignored by the parser. `Deviation` and
    `DeviationStore` now derive `PartialEq, Eq` to support the
    round-trip assertion (additive change; pattern-matching unchanged).
  - UUIDs are deterministically derived (RFC 9562 §5.8 v8 using SHA-256)
    so identical inputs yield byte-identical OSCAL output. The feature
    gates a new optional `serde_json` dependency; default builds are
    unchanged. Internal `EvaluationReport` / `Finding` / `Deviation` /
    `DeviationStore` shapes are NOT reshaped to mirror OSCAL
    field-for-field — the emitter projects, per the Architecture 2
    stance.

#### Migration

Pattern-matches stay unchanged — `LintResult::Warn(_)` still works.

Construction sites change:

```rust
// Before (0.2.x):
LintResult::Error("static text")

// After (0.3.0):
LintResult::error("static text")
// or equivalently:
LintResult::Error(std::borrow::Cow::Borrowed("static text"))
```

The constructor-helper form (`LintResult::error("...")`) is recommended.
It is zero-cost for static strings and also accepts `String` /
`format!(...)` output:

```rust
LintResult::error(format!("duration {days} > {cap_days}"))
```

Code that used `Box::leak` on JSON input to satisfy the prior
`'de: 'static` bound can drop the leak — `serde_json::from_str` and
`from_slice` both work directly on any owned String / slice now.

Construction sites that build a `Finding` via struct literal must add
`cert_sha256: None` (or the appropriate `Some([u8; 32])`) to the field
list — adding a public field to a non-`#[non_exhaustive]` struct is a
breaking change for external code that constructs via struct literal.
`LintRunner::run_cert` populates the field automatically; callers using
the runner do not need to construct `Finding` manually.

### `pkix-revocation 0.3.2`

#### Added

- `Error::RevocationFetchFailed { description: String }` variant.
  Returned by network-fetching adapters (`pkix-revocation-http`'s
  `HttpCrlFetcher` / `HttpOcspFetcher`, future LDAP / out-of-band
  adapters) when every URL extracted from the certificate failed
  either at the transport layer (network, TLS, HTTP error) or at the
  response layer (DER parse, signature, validity). Distinct from
  `Revoked`, `OcspStatusUnknown`, and `OutOfScope`. Hard-fail callers
  MUST reject the chain on this variant; soft-fail callers MAY treat
  it permissively.

  `Error` is `#[non_exhaustive]`, so adding the variant is
  non-breaking. Callers that exhaustively match on `Error` should add
  an arm (or use `_`) to be forward-compatible. Tracked as PKIX-a1yc.5
  in the project beads.

### `pkix-revocation 0.3.1`

#### Added

- `OutOfScopeReason::CrlIdpDistributionPointMismatch` variant. Returned
  by `CrlChecker::check_revocation` and `check_revocation_against_anchor`
  when the CRL's `IssuingDistributionPoint.distributionPoint` does not
  match (or is incompatible with) any of the certificate's
  `cRLDistributionPoints` extension entries (RFC 5280 §6.3.3(b)(1)).
  `OutOfScopeReason` is `#[non_exhaustive]`, so adding the variant is
  non-breaking.

  See the existing 0.3.0 entry below for the surrounding `Error::OutOfScope`
  contract that this variant participates in.

#### Changed (non-breaking)

- `CrlChecker` now performs RFC 5280 §6.3.3(b)(1) distribution-point
  name matching as part of the existing IDP scope check. Both
  `DistributionPointName::FullName` and
  `DistributionPointName::NameRelativeToCRLIssuer` forms are supported
  with cross-form resolution. PKITS §4.14.3, §4.14.8, §4.14.9
  (previously `#[ignore]`'d) now pass.

  See `pkix-revocation/src/crl.rs` rustdoc for the algorithm and
  documented limitations (per-DP `cRLIssuer` field not honored when
  resolving the cert's CDP base DN; reasons-subset check on
  `onlySomeReasons` not yet implemented).

  Tracked as PKIX-zg9y in the project beads.

#### Migration

- Dep bump: `pkix-revocation = "0.3.1"` and `pkix-path = "0.3"`.
  Callers that match on `Error::OutOfScope(_)` should add an arm for
  `OutOfScopeReason::CrlIdpDistributionPointMismatch` (or use a
  catch-all `_` arm) to be ready for future variants.

### `pkix-chain 0.4.0` — TRANSITIVELY BREAKING

#### Migration

- Bump `pkix-chain = "0.3"` to `pkix-chain = "0.4"` in your
  `Cargo.toml`.
- The re-exported `pkix_path::ValidatedPath` no longer derives `Copy`
  or `Hash`. If you relied on bit-copy semantics, add `.clone()` calls
  or pass `&ValidatedPath` instead. See `pkix-path 0.3.0` migration
  for full details.
- Transitively picks up `pkix-revocation 0.3.1`'s
  `CrlIdpDistributionPointMismatch` variant on `Error::OutOfScope`.

#### No surface changes

`pkix-chain`'s own public API (the `verify_chain` function family) is
unchanged. The break is purely the `ValidatedPath` re-export shape
change and the `Error` re-export's new variant.

### `pkix-chain-simple 0.4.0` — TRANSITIVELY BREAKING

Same migration and rationale as `pkix-chain 0.4.0` above.

### `pkix-path-builder 0.3.0` — BREAKING

#### Migration

- Bump `pkix-path-builder = "0.2"` to `pkix-path-builder = "0.3"` in
  your `Cargo.toml`.
- Behavior change: `build_path`, `build_path_with_config`, and the
  `PathCandidates` iterator now silently **skip** candidate
  intermediates whose `BasicConstraints` extension is present but
  cannot be DER-decoded, rather than aborting the search with
  `Error::MalformedIntermediate`. See the previous unreleased section
  for the full skip-not-fail rationale.
- Dep major bump on `pkix-path` (0.2 → 0.3); the `pkix-path-builder`
  public API is otherwise unchanged.

  Tracked as PKIX-qgw1 in the project beads.

### `pkix-path 0.3.0` — BREAKING

#### Added — RFC 5280 §6.1.2(a) policy qualifier processing

- `ValidatedPath::valid_policy_tree: Option<Vec<PolicyTreeNode>>` — the
  final §6.1.5 valid_policy_tree, or `None` if reduced to NULL during
  validation. Each node carries the policy qualifiers attached to it at
  creation time, sourced per RFC 5280:
  - §6.1.3(d)(1)(i)/(ii): from the cert's per-policy `policy_qualifiers`.
  - §6.1.3(d)(2) (anyPolicy expansion): from the cert's anyPolicy entry.
  - §6.1.4(b)(1) (PolicyMappings synthesis): from the cert's anyPolicy
    entry per RFC §6.1.4(b)(1)(ii).
  - §6.1.5(g)(iii)(3) (initial-policy-set materialization): inherited
    from the leaf anyPolicy node about to be deleted.

- `pub struct PolicyTreeNode` — public mirror of the internal
  `PolicyNode`. `#[non_exhaustive]`. Fields: `depth`, `valid_policy`,
  `expected_policy_set`, `qualifiers`. Qualifiers are exposed as the
  upstream `x509_cert::ext::pkix::certpolicy::PolicyQualifierInfo` raw
  (a `(qualifier_id_oid, raw_any_value)` pair); decoding the `Any`
  content to `CpsUri`/`UserNotice` is left to the caller because
  x509-cert 0.2.5 has a typo on `UserNotice.notice_ref` (declared
  `Option<GeneralizedTime>` instead of `Option<NoticeReference>`) and
  upstream-side decoding would silently mishandle real-world
  UserNotice qualifiers.

- `ValidatedPath::policy_qualifiers()` — convenience iterator yielding
  `(&policy_oid, &PolicyQualifierInfo)` pairs across every tree node.
  Returns an empty iterator when the tree is `None`.

  Path validation does NOT gate on qualifier validity — RFC 5280 §6.1.2(a)
  explicitly says qualifier processing is application-specific. The new
  fields are pure read-side outputs.

  Tracked as PKIX-an8h in the project beads. Decoding the `Any` content
  side of `PolicyQualifierInfo` is deferred until x509-cert ships a fix
  for `UserNotice.notice_ref`.

#### Changed (breaking)

- **`ValidatedPath` no longer derives `Copy`.** Four new heap-backed fields
  surface the §6.1.5 leaf-intrinsic outputs (`leaf_subject`, `leaf_issuer`,
  `leaf_serial`, `leaf_spki`); none of the field types
  (`x509_cert::name::Name`, `x509_cert::serial_number::SerialNumber`,
  `spki::SubjectPublicKeyInfoOwned`) implement `Copy` upstream, so the
  derive must be removed.

  **Migration**: callers that relied on bit-copy semantics (passing
  `ValidatedPath` by value to multiple consumers without `.clone()`) need
  to either insert an explicit `.clone()` or pass `&ValidatedPath` instead.
  No in-tree workspace consumer relied on this; downstream impact is
  expected to be minimal.

- **`ValidatedPath` no longer derives `Hash`.** None of the new field
  types implement `Hash` upstream. Existing usage of `ValidatedPath` as
  a `HashMap`/`HashSet` key — none observed in this workspace — is no
  longer possible. Callers needing hashable identity for a validated path
  can hash any of the new fields (`leaf_serial`, `leaf_spki`'s DER
  encoding) directly.

#### Added

- `ValidatedPath::leaf_subject: x509_cert::name::Name` — RFC 5280 §6.1.5
  output: subject DN of the validated leaf certificate (`chain[0]`).
- `ValidatedPath::leaf_issuer: x509_cert::name::Name` — issuer DN of the
  validated leaf certificate.
- `ValidatedPath::leaf_serial: x509_cert::serial_number::SerialNumber` —
  serial number of the validated leaf certificate.
- `ValidatedPath::leaf_spki: spki::SubjectPublicKeyInfoOwned` —
  `SubjectPublicKeyInfo` of the validated leaf certificate (carries
  algorithm OID, parameters, and public-key bits).

  These four fields let downstream code read the validated leaf's
  identity without re-parsing `chain[0]`. Common uses include revocation
  lookups (need `{ issuer, serial }`), application-layer signature
  verification using the validated leaf as a trust delegate (needs SPKI),
  and audit logging (needs subject DN).

  Tracked as PKIX-qzmr in the project beads.

### `pkix-revocation` — CDP/IDP `distributionPoint` matching (RFC 5280 §6.3.3(b)(1))

#### Added

- `OutOfScopeReason::CrlIdpDistributionPointMismatch` variant. Returned by
  `CrlChecker::check_revocation` and `check_revocation_against_anchor` when
  the CRL's `IssuingDistributionPoint.distributionPoint` does not match (or
  is incompatible with) any of the certificate's `cRLDistributionPoints`
  extension entries. `Error` and `OutOfScopeReason` are both
  `#[non_exhaustive]`, so adding this variant is **non-breaking** for
  callers using `match` arms.

#### Changed (non-breaking)

- `CrlChecker` now performs RFC 5280 §6.3.3(b)(1) distribution-point name
  matching as part of the existing IssuingDistributionPoint scope check.
  Both `DistributionPointName::FullName` and
  `DistributionPointName::NameRelativeToCRLIssuer` forms are supported,
  with `NameRelativeToCRLIssuer` resolved by appending the relative RDN to
  the appropriate base DN (the certificate's issuer for the cert's CDP,
  the CRL signer's subject for the CRL's IDP). Cross-form matching works:
  a cert whose CDP uses `NameRelativeToCRLIssuer` matches a CRL whose IDP
  uses `FullName` when both resolve to the same DN.

  `GeneralName::DirectoryName` entries compare via `pkix_path::names_match`
  (proper RFC 4518 DN equivalence including the new BMPString support).
  Other `GeneralName` variants (URI, dNSName, rfc822Name, IP address, OID,
  etc.) compare via byte-exact DER encoding equality.

  PKITS §4.14.3, §4.14.8, and §4.14.9 — the three `#[ignore]`d tests for
  CDP/IDP name matching — now pass with assertions tightened to expect
  `Err(OutOfScope(CrlIdpDistributionPointMismatch))` specifically. PKITS
  §4.14.4 (cross-form match: cert `NameRelativeToCRLIssuer`, CRL
  `FullName`) continues to pass.

  Limitations:
  - The per-`DistributionPoint` `cRLIssuer` field is not honored when
    resolving the cert's CDP base DN; the certificate's own issuer is
    always used. This is correct for the common case (RFC 5280 §4.2.1.13
    requires conforming CAs to omit `cRLIssuer` when the cert issuer also
    issues the CRL) and is sufficient for all PKITS §4.14 fixtures.
  - The reasons-subset check (`onlySomeReasons` on IDP must cover the
    reasons the cert's CDP asks to be checked) is not implemented. PKITS
    §4.14 fixtures do not exercise it. Tracked as future work; a separate
    `OutOfScopeReason` variant will be added at that time.

  Tracked as PKIX-zg9y in the project beads.

### `pkix-path` — `BMPString` AVA values are now compared after UCS-2-BE → UTF-8 transcoding

#### Changed (non-breaking)

- `names_match` (and the underlying `ava_values_match`) now decodes
  `BMPString`-tagged `AttributeTypeAndValue` content from UCS-2 big-endian
  to UTF-8 before applying the existing ASCII case-fold and
  insignificant-whitespace normalization. As a result, two AVAs that
  encode the same Unicode code points using different DER string types
  (`BMPString` vs `UTF8String`/`PrintableString`/`IA5String`/`VisibleString`)
  now compare equal where they previously fell through to raw DER byte
  comparison and compared unequal.

  Behaviour change for adversarial / malformed input: a `BMPString` with
  odd-length content bytes or 16-bit units in the UTF-16 surrogate range
  (U+D800..=U+DFFF) is now rejected by `any_to_str_bytes` (returns
  `None`); the dispatcher in `ava_values_match` then returns `false` for
  any comparison involving the malformed value (fail-closed). Previously
  malformed `BMPString` values fell through to raw DER byte comparison,
  so two byte-identical malformed values would have compared equal.
  Real-world certificates with malformed `BMPString` content do not
  exist in the PKITS corpus or any other in-tree fixture; the change is
  cosmetic for non-adversarial input.

  `UniversalString` AVAs continue to be parser-rejected upstream by
  `der` 0.7 (tag 0x1C is absent from `der::Tag::try_from`) and never
  reach this comparator. `TeletexString` continues to fall through to
  raw DER byte comparison (deferred pending a clear interoperability
  target — see PKIX-l63j.3).

  No new dependencies. `no_std` preserved. `pkix-path` stays at 0.2.x.

  Tracked as PKIX-l63j.1 (subset of the PKIX-l63j RFC 4518 epic) in the
  project beads. NFKC and full RFC 4518 prep for non-ASCII Unicode is
  tracked separately as PKIX-l63j.2.

### `pkix-path-builder` — skip-not-fail on malformed `BasicConstraints`

#### Changed (non-breaking)

- `build_path`, `build_path_with_config`, and the `PathCandidates` iterator
  now silently **skip** candidate intermediates whose `BasicConstraints`
  extension is present but cannot be DER-decoded, rather than aborting the
  search with `Error::MalformedIntermediate`. This matches the existing
  treatment of candidates with `cA = FALSE` or no `BasicConstraints` at all.

  Rationale: real-world certificate pools (notably CMS
  `SignedData.certificates` bags) routinely include unsolicited or corrupt
  certs the verifier did not request — for other recipients in a
  multi-recipient encrypted message, intermediates from unrelated CAs that
  rode along, or expired/corrupt artefacts from someone's pipeline. One bad
  cert in the bag must not poison verification of an otherwise-valid chain.

  When skipping all malformed candidates would leave no path to a trust
  anchor, `build_path` returns `Error::NoPathFound` (as it would for any
  other no-path scenario). The `Error::MalformedIntermediate` variant is
  retained because `Error` is `#[non_exhaustive]` and may be repurposed by
  a future diagnostic mode.

  Tracked as PKIX-qgw1 in the project beads.

### `pkix-ct` — SCT parser, delivery adapters, and CT log list

#### Added

- `SignedCertificateTimestamp` and `SctList` now carry parsed values
  rather than placeholder fields. `SignedCertificateTimestamp` exposes
  `version`, `log_id` (32 bytes), `timestamp_ms` (u64 BE), `extensions`
  (Vec<u8>), `hash_alg`, `sig_alg`, and `signature` (raw bytes).
- `SignedCertificateTimestamp::from_bytes` parses a single SCT.
- `SctList::from_extension_value` parses the value of a cert's SCT-list
  extension (OID 1.3.6.1.4.1.11129.2.4.2). It peels the inner DER
  OCTET STRING that RFC 6962 §3.3 wraps the `SignedCertificateTimestampList`
  in. The outer extension OCTET STRING is assumed to be already stripped
  by the extension framework (e.g. via `x509_cert::ext::Extension::extn_value.as_bytes()`).
- `SctList::from_serialized_list` parses bare `SerializedSCTList` bytes
  for callers handling TLS-handshake-extension or OCSP-extension delivery
  (the OCSP and TLS forms are not double-wrapped).
- `sct_list_from_tls_extension` parses the payload of TLS handshake
  extension 18 (`signed_certificate_timestamp`). Thin alias over
  `SctList::from_serialized_list` since the TLS-wire form is not
  OCTET-STRING-wrapped.
- `sct_list_from_ocsp_response` parses an OCSP `BasicOcspResponse` DER
  and extracts the first `SignedCertificateTimestampList` extension found
  (single-response extensions first, then top-level response extensions).
  Gated behind a new `ocsp` crate feature; pulls in `x509-ocsp`.
- `CtLog` and `CtLogList` types (behind a new `log-list` feature) hold
  the trust anchor set for SCT verification. `CtLogList::insert`
  enforces `log_id == SHA-256(key_der)` per RFC 6962 §3.2. Includes
  `new` / `insert` / `get` / `len` / `is_empty` / `iter` accessors.
- `CtLogList::from_google_log_list_json` (behind a new `log-list-json`
  feature, which implies `log-list`) parses the Chrome / Google
  `log_list.json` schema v3 published at
  <https://www.gstatic.com/ct/log_list/v3/log_list.json>. Unknown JSON
  fields are ignored; `state.usable.timestamp` and `state.retired.timestamp`
  are extracted as `usable_from_ms` and `retired_at_ms`.
- New `Error` variants `UnsupportedVersion(u8)` and `TruncatedOrTrailing`
  (`Error` is `#[non_exhaustive]`; adding variants is non-breaking).

#### Changed

- The crate is now `no_std` + `alloc` by default (default features is
  the empty set). A new `std` feature gates the `std::error::Error` impl
  on `Error` and propagates `std` to `der`, `x509-cert`, `signature`,
  and optionally `x509-ocsp` / `sha2`. Consumers wanting std-only
  behaviour add `features = ["std"]`. No consumer code is currently
  broken: the previous default included `std::error::Error`; the new
  default does not, so a consumer that relied on `Error: std::error::Error`
  will need to enable the feature. pkix-ct is at `0.0.0` and not
  published, so the impact is contained to in-tree consumers.

- `verify_scts` removed from the crate root. Replaced by methods on
  [`SctVerifier`]: `verify_sct_for_cert` (RFC 6962 `x509_entry`),
  `verify_sct_for_precert` (`precert_entry`), and `verify_embedded_scts`
  (count-returning loop helper for cert-embedded SCT-list extensions).
  BREAKING for any in-tree caller of `pkix_ct::verify_scts`; none
  exist, and pkix-ct remains at 0.0.0 (unpublished). The non-`log-list`
  stub `CtLogList` was retired together with the old standalone
  helper. Tracked as PKIX-baac.7.

- Error variants `NoTrustedSct` and `PrecertEntryNotImplemented` removed
  from `Error`: both were only emitted by the prior `verify_scts` stub
  / pre-cert stub paths that no longer exist. New variant
  `LeafMissingSctList` added for the `verify_sct_for_precert` case
  where the leaf has no SCT-list extension. `Error` remains
  `#[non_exhaustive]`.

- The `Limitations` rustdoc section is updated to describe what's
  implemented (parsing + delivery adapters + log list + signature
  verification for both `x509_entry` and `precert_entry`) vs what is
  not (Merkle inclusion proofs, tracked as PKIX-baac.5).

  Tracked as PKIX-baac.1 (parser), PKIX-baac.6 (delivery adapters),
  PKIX-baac.2 (log list), PKIX-baac.3 (`x509_entry` verifier),
  PKIX-baac.4 (`precert_entry` verifier), PKIX-baac.5
  (Merkle inclusion + STH signature verification, see below), and
  PKIX-baac.7 (`verify_embedded_scts`).

- `SctVerifier::verify_inclusion` verifies an RFC 6962 §2.1.1 / RFC
  9162 §2.1.3.2 Merkle audit path against a trusted root hash. Helper
  `merkle_leaf_hash` computes the §2.1 leaf hash. New types
  `MerkleAuditPath` and `SignedTreeHead`. Tracked as PKIX-baac.5.

- `SctVerifier::verify_sth` verifies the signature on a Signed Tree
  Head (RFC 6962 §3.5) against the log's public key. Tampered
  timestamps, tree sizes, or root hashes all surface as
  `Error::InvalidSignature`.

- Error variants added: `MerkleProofInvalid` (verification failed —
  reconstructed root mismatch or out-of-range index) and
  `MerkleProofMalformed` (proof shape inconsistent — empty tree,
  audit path longer than tree height permits).

## [0.3.0 / 0.2.1] — 2026-05-07

This release groups three concurrent crate versions:

- `pkix-revocation 0.3.0`, `pkix-chain 0.3.0`, `pkix-chain-simple 0.3.0` — semver-breaking.
- `pkix-path 0.2.1`, `pkix-path-builder 0.2.1`, `pkix-profiles 0.2.1` — additive.
- `pkix-lint 0.2.0` — first publish.

### `pkix-revocation 0.3.0` — BREAKING

#### Changed (breaking)

- **`Error::OutOfScope(OutOfScopeReason)` variant added** and is now returned at
  six previously-`Ok(())` sites in `CrlChecker::check_revocation` and
  `CrlChecker::check_revocation_against_anchor` corresponding to the three
  `IssuingDistributionPoint` scope-flag mismatches in RFC 5280 §5.2.5
  (`onlyContainsAttributeCerts`, `onlyContainsUserCerts`, `onlyContainsCACerts`).

  The pre-0.3.0 API documented `Ok(())` as having "dual semantics" — it could
  mean either "verified not-revoked" OR "no determination made (out of scope)".
  Hard-fail callers had no programmatic way to distinguish.

  Under 0.3.0, `Ok(())` is unambiguous "verified not-revoked"; "not covered"
  surfaces as `Err(Error::OutOfScope(reason))` for CRL or
  `Err(Error::OcspStatusUnknown)` for OCSP.

  **Migration**: callers that used `match` on `pkix_revocation::Error` MUST
  add a match arm for `Error::OutOfScope(_)` (the enum is `#[non_exhaustive]`,
  so this is a warning rather than a compile error, but the behavior change
  is silent without the new arm). Hard-fail revocation policies should treat
  `Error::OutOfScope` as a failure. Soft-fail callers can match on the
  specific `OutOfScopeReason` (`CrlOnlyAttributeCerts`, `CrlOnlyUserCerts`,
  `CrlOnlyCaCerts`) and decide which scopes to tolerate.

  Tracked as PKIX-qwzx.11 in the project beads.

#### Added

- `pub enum OutOfScopeReason` with variants `CrlOnlyAttributeCerts`,
  `CrlOnlyUserCerts`, `CrlOnlyCaCerts`. Derives `Clone`, `Copy`, `Debug`,
  `PartialEq`, `Eq`, `Hash`. Has a `Display` impl. `#[non_exhaustive]`.
- `Error::OutOfScope(OutOfScopeReason)` variant. `Display` formats as
  `"revocation source out of scope: {reason}"`.

#### Documentation

- `RevocationChecker::check_revocation` trait doc rewritten to remove the
  "dual semantics" warning and to document the new `OutOfScope` /
  `OcspStatusUnknown` distinction between CRL and OCSP "not covered" paths.

### `pkix-chain 0.3.0` — transitively breaking

Re-exports `pkix-revocation::Error` via `Error::Revocation(_)`. The
`OutOfScope` variant change above propagates: cases that previously surfaced
as `Ok(())` from `verify_chain` / `verify_chain_default` now surface as
`Err(Error::Revocation(Error::OutOfScope(_)))`. No `pkix-chain` API
surface changes beyond the dependency bump.

### `pkix-chain-simple 0.3.0` — transitively breaking

Same rationale as `pkix-chain 0.3.0`.

### `pkix-path 0.2.1`

#### Added

- `pub fn cert_is_ca(cert: &Certificate) -> Result<bool, DerError>` — RFC 5280
  §4.2.1.9 `BasicConstraints` decode helper. Returns `Ok(true)` if the cert
  has `cA = TRUE`, `Ok(false)` if absent or `cA = FALSE`, `Err(DerError)` if
  the extension is present but malformed (fail-closed). Shared by
  `pkix-path-builder` and `pkix-revocation::crl` to avoid duplicate
  RFC 5280 §4.2.1.9 decoders.

### `pkix-path-builder 0.2.1`

#### Added

- `PathBuilderConfig` and `build_path_with_config` (originally landed in
  earlier 0.2 work; full surface stable in 0.2.1).

#### Changed (non-breaking)

- `cert_is_ca` is now a thin wrapper over `pkix_path::cert_is_ca` with
  `.map_err(|_| Error::MalformedIntermediate)`. Behavior unchanged.
- `Error::DepthExceeded` doc and `Display` no longer hardcode "(10)";
  reference `PathBuilderConfig::max_depth` and `DEFAULT_MAX_DEPTH`.

### `pkix-profiles 0.2.1`

Documentation and lint adjustments. No public API changes.

### `pkix-lint 0.2.0` — first publish

First crates.io release. Lint engine for X.509 certificates with structured
soft-fail and advisory results. CABF TLS Baseline Requirements lints,
deviation tracking, OSCAL-style reports.

#### Notable

- `serial_lex_ge` / `serial_lex_le` consolidated into `serial_cmp` returning
  `core::cmp::Ordering`. Internal change; not on the public API surface.

### New workspace member: `pkix-truststore`

Tier 1 trust anchor loading. Bytes-in (PEM or DER), `Vec<TrustAnchor>`-out.
File-reading convenience wrappers and a `from_der_iter` entry point that
adapter crates (system stores, HSMs, cloud KMS) feed.

Binding project stance recorded in `AGENTS.md`: no compiled-in CA bundle,
no baked-in trust source. Platform / HSM / cloud trust stores are
out-of-tree adapter crates (`pkix-truststore-system` (PKIX-8h87),
`pkix-truststore-pkcs11` (PKIX-p8vz), etc.) that fetch DER bytes from a
source-specific API and feed them into `pkix_truststore::from_der_iter(...)`.

Initial version `0.0.0` per the workspace stub-crate convention; bumped
to `0.1.0` on first publish.

### Stub crates

The following crates remain at `0.0.0` placeholder versions and are NOT
published in this release:

- `pkix-revocation-http` (online CRL/OCSP fetching — not yet implemented)
- `pkix-ct` (Certificate Transparency SCT verification — not yet implemented)
- `pkix-composite` (composite classical+PQC signatures — not yet implemented)
- `pkix-ac` (RFC 5755 attribute certificates — not yet implemented)
- `pkix-truststore` (PEM/DER trust anchor loading — implemented, unpublished
  pending first crates.io release decision)

The 0.1.1 versions of these stubs on crates.io are placeholder releases that
predate the 0.0.0 reset; consumers should not depend on them.

## [0.2.0] — 2026-05-06

Initial 0.2 release. Workspace structure stabilized; PKITS happy-path subset
green; `pkix-path` `chain_walk` implements RFC 5280 §6.1 across signature
verification, validity period, name constraints (with `nameConstraints`
intersection/union and `nc_constrained_types` tracking), policy tree
(including `PolicyMappings` and `InhibitAnyPolicy`), and the §6.1.5 wrap-up.

## [0.1.x] — 2026-05-05 and earlier

Pre-release iteration. See git log for details.
