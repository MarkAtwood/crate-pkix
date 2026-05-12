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
| `san-rfc822.der` | `Rfc822Name("alice@example.com")` |
| `san-rfc822-mixedcase.der` | `Rfc822Name("alice@Example.COM")` |
| `san-smtputf8.der` | `otherName(SmtpUTF8Mailbox, UTF8String "用户@example.com")` |
| `san-smtputf8-u-label-domain.der` | `otherName(SmtpUTF8Mailbox, UTF8String "user@bücher.example")` |
| `san-mailbox-mixed.der` | `Rfc822Name("alice@example.com") + otherName(SmtpUTF8Mailbox, "用户@example.com")` |

Validity 2000-01-01 to 2050-01-01. P-256 ECDSA self-signed.

Regenerate with `gen.py` if the fixture set needs to grow. The script
uses pyca/cryptography 48.0.0; new fixtures should not require the
cryptography version to be bumped.

Oracle independence: pyca/cryptography is used to **produce** the
fixtures; `pkix-identity`'s `verify_dns_name` is the **consumer** under
test. The two implementations share no code.
