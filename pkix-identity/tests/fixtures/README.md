# pkix-identity test fixtures

DER fixtures for `verify_dns_name` integration tests. Each file is a
self-signed leaf certificate; `pkix-identity` does not validate chains,
so a self-signed cert is sufficient.

| Fixture | SAN contents |
|---|---|
| `san-exact-dns.der` | `DnsName("www.example.com")` |
| `san-wildcard-dns.der` | `DnsName("*.example.com")` |
| `san-multi-dns.der` | `www.example.com`, `api.example.com`, `*.cdn.example.com` |
| `san-ipv4.der` | `IpAddress(192.0.2.5)` |
| `san-ipv6.der` | `IpAddress(2001:db8::1)` |
| `san-mixed.der` | `host.example.com`, `IpAddress(203.0.113.10)` |
| `san-idn-alabel.der` | `DnsName("xn--bcher-kva.example")` |
| `san-mixed-case.der` | `DnsName("Host.Example.COM")` |
| `san-missing.der` | (no SAN extension) |
| `cn-only.der` | (no SAN extension; CN is `leaf`) |
| `cn-hostname.der` | (no SAN; CN is `mx.example.com`) |
| `cn-wildcard.der` | (no SAN; CN is `*.example.com`) |
| `san-dns-plus-cn.der` | `DnsName("www.example.com")`; CN is `mx.example.com` |
| `san-ip-plus-cn.der` | `IpAddress(192.0.2.9)` only; CN is `mx.example.com` |
| `no-san-no-cn.der` | (no SAN; subject is `O=Test Org`, no CN) |
| `san-rfc822.der` | `Rfc822Name("alice@example.com")` |
| `san-rfc822-mixedcase.der` | `Rfc822Name("alice@Example.COM")` |
| `san-smtputf8.der` | `otherName(SmtpUTF8Mailbox, UTF8String "用户@example.com")` |
| `san-smtputf8-u-label-domain.der` | `otherName(SmtpUTF8Mailbox, UTF8String "user@bücher.example")` (ASCII local-part: non-conformant per RFC 8398 §3, never matches) |
| `san-mailbox-mixed.der` | `Rfc822Name("alice@example.com") + otherName(SmtpUTF8Mailbox, "用户@example.com")` |

Validity 2000-01-01 to 2050-01-01. P-256 ECDSA self-signed.

Regenerate with `gen.py` if the fixture set needs to grow. The script
uses pyca/cryptography 48.0.0; new fixtures should not require the
cryptography version to be bumped.

Oracle independence: pyca/cryptography is used to **produce** the
fixtures; `pkix-identity`'s `verify_dns_name` is the **consumer** under
test. The two implementations share no code.

## The RFC 7672 §3.2.3 fixtures

The five fixtures naming a CN exist for `verify_dns_name_with_cn_fallback`,
which implements SMTP DANE's matching rule: DNS-IDs if the certificate
presents any, otherwise the `commonName`.

Three of them encode distinctions the rule turns on, and a test suite without
them would pass against a wrong implementation:

- `san-dns-plus-cn.der` has a DNS-ID *and* a CN naming a different host. The
  CN must be ignored. An implementation that fell back to the CN whenever
  DNS-ID matching failed would let a certificate's CN override its own SAN.
- `san-ip-plus-cn.der` has a SAN carrying no DNS-ID. The rule keys off the
  absence of a *DNS-ID*, not the absence of a SAN extension, so the CN still
  applies here.
- `no-san-no-cn.der` presents no name at all, which must be distinguishable
  from a CN that merely fails to match.

`cn-only.der` predates these and has `CN=leaf`, which is not a hostname; it
tests that the Web PKI path refuses CN fallback rather than that the SMTP path
performs it.
