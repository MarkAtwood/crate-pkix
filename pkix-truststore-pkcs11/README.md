# pkix-truststore-pkcs11

**PKCS#11 / HSM / smart card trust store adapter for [`pkix-truststore`](https://docs.rs/pkix-truststore). Stub crate.**

Opens a PKCS#11 session, enumerates trusted certificate objects on the token, and feeds their DER bytes through `pkix_truststore::from_der_iter` to produce `Vec<TrustAnchor>`. Planned support: HSMs (Yubico HSM, Thales, AWS CloudHSM, Azure Dedicated HSM, SafeNet), OpenSC-backed tokens, PIV / CAC smart cards, and FIPS-mode deployments where trust roots live on a token.

## Status

Substantive content — session management, object enumeration, `CKA_TRUSTED` filtering, error mapping — lands when it is implemented per the workspace roadmap.

## License

Apache-2.0 OR MIT
