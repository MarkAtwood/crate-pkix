# pkix-tlsrpt

TLSRPT — SMTP TLS Reporting, per [RFC 8460].

A recipient domain publishes a reporting endpoint; senders send it daily
summaries of TLS negotiation and policy-validation failures. This crate holds
the `_smtp._tls` record (§3), the report schema (§4.4), the result types
(§4.3) and the report filename (§5.1).

No DNS, no HTTP, no SMTP, no clock — the same shape as `pkix-mta-sts`.

## Why a sender should bother

MTA-STS's `testing` mode exists so a domain can deploy a policy and find out
what would break **before** enforcing it. Without senders that report,
`testing` tells the domain nothing: it is a policy that never applies.

So a sender implementing MTA-STS or DANE without TLSRPT is a free rider on
the domains that do report — it takes the protection and contributes nothing
to anyone else's rollout.

Note that this is not a security argument. A report protects the
**recipient's deployment**, not the sender's mail.

## What a report says about someone else

A report states which of a domain's MX hosts failed TLS, how, and from which
sending IP. That is operational detail about a third party, sent to an address
that third party nominated in **unsigned** DNS — the `_smtp._tls` record
carries no authentication, exactly like `_mta-sts`.

§7 covers the consequences. Two follow directly:

- A `rua` address is not trustworthy merely because it came from the domain it
  describes. An attacker who can forge the TXT answer redirects a domain's
  failure reports to themselves.
- A report is a map of which of a domain's hosts have broken TLS, which is
  reconnaissance if it reaches the wrong party.

So this crate carries only what §4.4 defines and nothing more helpful.
`FailureDetail::failure_reason_code` is the only free-text field, it is
optional, and its documentation says what not to put in it. The classifiers
produce a short classification — `no-trusted-path`, `http-status-404` — never
the error's own text, which can carry a URL or an internal hostname.

## Classifying your own failures

`classify::*` maps the workspace's errors onto §4.3's vocabulary, behind
features so a DANE-only reporter does not pull in MTA-STS:

| feature | maps |
|---|---|
| `mta-sts` | `PolicyOutcome` → `certificate-host-mismatch` |
| `mta-sts-http` | `FetchError` → `sts-policy-*` |
| `dane` | `SmtpDaneFailure`, `pkix_chain::Error`, `pkix_path::Error` |

### `sts-webpki-invalid` has exactly one source

§4.3.2.2 defines it as "the MTA-STS Policy could not be authenticated using
PKIX validation" — the most security-relevant thing a report can say about
MTA-STS, because the HTTPS certificate is the policy's **only**
authentication: the `_mta-sts` TXT record is unsigned and the policy body
carries no signature.

It is produced from `FetchError::TlsValidation` and nothing else.
`FetchError::Transport` is deliberately not mapped to it: a refused connection
means the web server is down, and reporting that as a certificate failure
would send an operator after a certificate that is fine.

Those two were one variant until `pkix-mta-sts-http` was changed to tell them
apart, which is why the test asserting *nothing else* maps to
`sts-webpki-invalid` is still there — the harm it guards against has not
changed, only the ability to distinguish the cases has.

## What is deliberately not here

**Report delivery.** Not unfinished — excluded for two reasons:

- `mailto` delivery **MUST** carry a DKIM signature by the reporting domain
  (§3), without the `l=` body-length attribute, and an unsigned report MUST be
  ignored by the recipient. That means a mail library and a signing key inside
  a PKI library, and sending a report without it is wasted work.
- §5.3: "when sending failure reports via SMTP, Sending MTAs MUST NOT honor
  MTA-STS or DANE TLSA failures" — a sender must deliver a report about a
  domain's broken TLS *to that domain*, possibly unencrypted. That is MTA
  policy, not PKI.

`https` delivery is a POST that a caller with an HTTP client writes in a line;
§3 even allows ignoring certificate errors when submitting, since refusing to
deliver a report over a certificate problem would suppress exactly the reports
most worth sending.

**Compression** (§5.2, a SHOULD). It needs a gzip dependency this crate does
not otherwise want. `ReportFilename::extension` already distinguishes the two
cases, and `GZIP_MEDIA_TYPE` is the MIME type for the mail attachment.

**Report aggregation over time.** The schema is here and the counting is a
sender's own: it knows its delivery attempts, and nothing in this crate should
hold a day of them.

## License

Apache-2.0 OR MIT, at your option.

[RFC 8460]: https://www.rfc-editor.org/rfc/rfc8460
