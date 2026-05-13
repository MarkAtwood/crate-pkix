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

Validity 2000-01-01 to 2050-01-01. P-256 ECDSA throughout so the workspace's
default `DefaultVerifier` covers signature checking.

Regenerate with `gen.py`. Uses pyca/cryptography as the external oracle for
DER encoding; the Rust verifier under test never participates in fixture
creation.
