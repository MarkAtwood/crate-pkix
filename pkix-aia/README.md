# pkix-aia

**Authority Information Access (AIA) fetcher trait and types for `pkix-chain`, per [RFC 5280 §4.2.2.1](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.2.1).**

AIA is the certificate extension that carries `caIssuers` URIs pointing at the certificate's issuer. Chain-build code can follow these URIs to fetch missing intermediate certificates when the caller-supplied chain is incomplete.

This crate ships the trait surface only:

- `AiaError` — failure modes for fetcher implementations. `#[non_exhaustive]`, `Clone + Debug + PartialEq + Eq + Send + Sync`, optional `serde` support.
- `AiaFetcher` trait — synchronous `&self` fetch with `Result<Vec<u8>, AiaError>` return; default-impl `batch_fetch` for multi-URI batches.
- `NoAiaFetcher` zero-cost default — *planned* (PKIX-zkjb.4).

Real HTTP fetching lives in a separate adapter crate, `pkix-aia-http`, which is also planned (PKIX-zkjb.5).

## Architectural placement

```text
pkix-chain  ----+------>  pkix-aia          (trait + error + no-op default)
                |
                +------>  pkix-aia-http     (real HTTP fetcher adapter)
```

`pkix-chain`'s `Verifier` struct holds an `A: AiaFetcher` generic parameter that defaults to `NoAiaFetcher`. Callers who do not need AIA fetching see no API change; callers who do can plug in any `AiaFetcher` implementation, including HTTP adapters shipped by separate crates or in-process caching wrappers.

## `no_std` and feature flags

The default build is `no_std + alloc`. Enabling `std` unlocks the `AiaError::IoFailure` variant (whose `kind: std::io::ErrorKind` field requires `std::io`) and the `std::error::Error` impl. Enabling `serde` derives `Serialize` / `Deserialize` on `AiaError`; with `std + serde` together, the `IoFailure` variant round-trips its `kind` field through a stable string label.

## Status

Initial release: `AiaError` + `AiaFetcher` trait. `NoAiaFetcher` zero-cost default lands next under the PKIX-zkjb epic.

## License

Apache-2.0 OR MIT
