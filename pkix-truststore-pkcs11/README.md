# pkix-truststore-pkcs11

**PKCS#11 / HSM / smart card trust store adapter for [`pkix-truststore`](https://docs.rs/pkix-truststore). Stub crate.**

Opens a PKCS#11 session, enumerates trusted certificate objects on the token, and feeds their DER bytes through `pkix_truststore::from_der_iter` to produce `Vec<TrustAnchor>`. Covers HSMs (Yubico HSM, Thales, AWS CloudHSM, Azure Dedicated HSM, SafeNet), OpenSC-backed tokens, PIV / CAC smart cards, and FIPS-mode deployments where trust roots live on a token.

## Status

Stub crate. Substantive content lands when the PKCS#11 session and object enumeration logic is implemented per the workspace roadmap.

## License

Apache-2.0 OR MIT
