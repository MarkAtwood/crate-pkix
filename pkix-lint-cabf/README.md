# pkix-lint-cabf

**Reference CA/Browser Forum lint bundles for [`pkix-lint`](https://docs.rs/pkix-lint). Not authoritative.**

CA/B Forum Baseline Requirements (TLS BR, S/MIME BR) change on a ballot cycle. The lint bundles in this crate are a snapshot of those requirements at the time of the most recent revision. They are intended as a starting point: fork and adapt to your deployment's current interpretation of the BR text, which is the only canonical source.

For the current Baseline Requirements:
- <https://cabforum.org/baseline-requirements/> (TLS)
- <https://cabforum.org/smime-br/> (S/MIME)

Maintained on a best-effort basis. If your deployment depends on bit-exact CA/B Forum conformance, you SHOULD vendor and review the relevant rule definitions yourself.

## Status

Stub crate. Substantive content lands when the OSCAL Profile composition machinery (PKIX-9vnx.7) and `pkix-lint` framework/policy split (PKIX-amgn.5) are in place.

## License

Apache-2.0 OR MIT
