# pkix-chain test fixtures

DER fixtures for the use-case wrapper integration tests (`verify_tls_server`
et al.). Each test needs a real two-cert chain because the wrappers run full
RFC 5280 §6.1 path validation before identity binding.

| Fixture | Role | Contents |
|---|---|---|
| `root.der` | trust anchor | P-256 self-signed CA, cA=TRUE, KU=keyCertSign\|cRLSign |
| `leaf-san-www-example.der` | end-entity | EE signed by `root`, EKU=serverAuth, SAN=DNS:www.example.com |
| `leaf-no-san.der` | end-entity | EE signed by `root`, EKU=serverAuth, **no SAN extension** |

Validity 2000-01-01 to 2050-01-01. P-256 ECDSA throughout so the workspace's
default `DefaultVerifier` covers signature checking.

Regenerate with `gen.py`. Uses pyca/cryptography as the external oracle for
DER encoding; the Rust verifier under test never participates in fixture
creation.
