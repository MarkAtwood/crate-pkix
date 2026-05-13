# pkix-chain test fixtures

DER fixtures for the use-case wrapper integration tests (`verify_tls_server`
et al.). Each test needs a real two-cert chain because the wrappers run full
RFC 5280 §6.1 path validation before identity binding.

| Fixture | Role | Contents |
|---|---|---|
| `root.der` | trust anchor | P-256 self-signed CA, cA=TRUE, KU=keyCertSign\|cRLSign |
| `leaf-san-www-example.der` | end-entity | EE signed by `root`, EKU=serverAuth, SAN=DNS:www.example.com |
| `leaf-no-san.der` | end-entity | EE signed by `root`, EKU=serverAuth, **no SAN extension** |
| `leaf-san-alice-example.der` | end-entity | EE signed by `root`, EKU=emailProtection, SAN=rfc822Name:alice@example.com |
| `leaf-codesigning.der` | end-entity | EE signed by `root`, EKU=codeSigning, no SAN |
| `leaf-timestamping.der` | end-entity | EE signed by `root`, EKU=timeStamping (critical, sole) — RFC 3161 §2.3 compliant TSA |
| `leaf-timestamping-not-critical.der` | end-entity | EE signed by `root`, EKU=timeStamping (NOT critical) — RFC 3161 §2.3 negative case |
| `leaf-timestamping-not-sole.der` | end-entity | EE signed by `root`, EKU=timeStamping+codeSigning (critical) — RFC 3161 §2.3 negative case |

PKIX-fmtv.23 mailbox-binding corpus (EKU=emailProtection throughout):

| Fixture | Role | Contents |
|---|---|---|
| `mailbox-rfc822-user-example.der` | end-entity | SAN rfc822Name=`user@example.com` |
| `mailbox-rfc822-user-EXAMPLE.der` | end-entity | SAN rfc822Name=`user@EXAMPLE.com` (domain mixed-case) |
| `mailbox-rfc822-User-example.der` | end-entity | SAN rfc822Name=`User@example.com` (local-part mixed-case) |
| `mailbox-smtputf8-only.der` | end-entity | SAN otherName(SmtpUTF8Mailbox)=`用户@example.com` |
| `mailbox-mixed.der` | end-entity | SAN rfc822Name=`user@example.com` + SmtpUTF8Mailbox=`用户@example.com` |
| `mailbox-multi-rfc822.der` | end-entity | 3 rfc822Name entries: `alpha`, `beta`, `gamma` @example.com |
| `mailbox-dns-only.der` | end-entity | SAN dNSName=`example.com` only — no mailbox entries |
| `mailbox-rfc822-malformed-no-at.der` | end-entity | SAN rfc822Name=`no-at-sign` (valid IA5String, semantically not a mailbox) |
| `mailbox-smtputf8-bad-utf8.der` | end-entity | SAN otherName(SmtpUTF8Mailbox) with malformed UTF-8 value bytes |

Validity 2000-01-01 to 2050-01-01. P-256 ECDSA throughout so the workspace's
default `DefaultVerifier` covers signature checking.

Regenerate with `gen.py`. Uses pyca/cryptography as the external oracle for
DER encoding; the Rust verifier under test never participates in fixture
creation.
