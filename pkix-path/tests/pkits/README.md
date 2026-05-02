# PKITS Test Fixtures

NIST Public Key Interoperability Test Suite (PKITS) certificate fixtures
for integration testing of pkix-path.

## Source

These files were sourced from the Go standard library's copy of the NIST PKITS
test suite, which is itself derived from the original NIST distribution.

Source path (on the machine that generated this copy):
  golang.org/toolchain source tree:
  src/crypto/x509/testdata/nist-pkits/

Original NIST source:
  https://csrc.nist.gov/projects/pki-testing

## Contents

- `certs/` — 405 DER-encoded X.509 certificates (*.crt)
  - `TrustAnchorRootCertificate.crt` — the PKITS trust anchor (root CA)
  - All other certificates are test subjects or intermediate CAs
- `vectors.json` — test vector metadata mapping test names to certificate chains

## Usage in tests

```rust
// Load a cert by name:
let der = include_bytes!("pkits/certs/SomeCertificate.crt");
let cert = Certificate::from_der(der).unwrap();

// Load the trust anchor:
let ta_der = include_bytes!("pkits/certs/TrustAnchorRootCertificate.crt");
```

## License

The PKITS test suite is a work of the US federal government and is in the
public domain. See the NIST PKITS documentation for details.
