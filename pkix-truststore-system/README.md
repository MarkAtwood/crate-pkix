# pkix-truststore-system

**OS-native trust store adapter for [`pkix-truststore`](https://docs.rs/pkix-truststore). Stub crate.**

Loads trust anchors from platform-native trust stores (macOS Keychain, Windows certificate store, iOS Keychain Services, Android KeyStore) and feeds them through `pkix_truststore::from_der_iter` to produce `Vec<TrustAnchor>`. The `rustls-native-certs` analog for the `pkix-truststore` ecosystem.

Linux is deliberately out of scope: most distributions expose the system trust bundle as a PEM file at a well-known path, which consumers read directly via `pkix_truststore::from_pem`.

## Status

Stub crate. Substantive content lands when the per-platform readers are implemented per the workspace roadmap.

## License

Apache-2.0 OR MIT
