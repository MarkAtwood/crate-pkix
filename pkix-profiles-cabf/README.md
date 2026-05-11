# pkix-profiles-cabf

**Reference implementation of CA/Browser Forum certificate profile requirements (TLS BR, S/MIME BR, Code Signing BR). Not authoritative.**

CA/B Forum Baseline Requirements change on a ballot cycle. The implementations in this crate are a snapshot of those requirements at the time of the most recent revision. They are intended as a starting point: fork and adapt to your deployment's current interpretation of the BR text, which is the only canonical source.

For the current Baseline Requirements:
- <https://cabforum.org/baseline-requirements/> (TLS)
- <https://cabforum.org/smime-br/> (S/MIME)
- <https://cabforum.org/code-signing-baseline-requirements/> (Code Signing)

Maintained on a best-effort basis. If your deployment depends on bit-exact CA/B Forum conformance, you SHOULD vendor and review the relevant rule definitions yourself.

## Status

Stub crate. Substantive content lands when the `pkix-profiles` framework/policy split (PKIX-amgn.4) moves the CA/B Forum-specific profile types into this crate.

## License

Apache-2.0 OR MIT
