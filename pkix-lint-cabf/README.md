# pkix-lint-cabf

**Reference CA/Browser Forum lint bundles for [`pkix-lint`](https://docs.rs/pkix-lint). Not authoritative.**

CA/B Forum Baseline Requirements (TLS BR, S/MIME BR) change on a ballot cycle. The lint bundles in this crate are a snapshot of those requirements at the time of the most recent revision. They are intended as a starting point: fork and adapt to your deployment's current interpretation of the BR text, which is the only canonical source.

For the current Baseline Requirements:
- <https://cabforum.org/baseline-requirements/> (TLS)
- <https://cabforum.org/smime-br/> (S/MIME)

Maintained on a best-effort basis. If your deployment depends on bit-exact CA/B Forum conformance, you SHOULD vendor and review the relevant rule definitions yourself.

## Modules

- `cabf_tls_br` — CA/B Forum TLS Baseline Requirements lint bundle. Migrated
  from `pkix-lint` 0.4.0 (see workspace `CHANGELOG.md` under `pkix-lint
  0.5.0`). Bundles SC-081 phased validity caps, SHA-1 prohibition, RSA
  min-key-size, SAN/EKU presence, and `BasicConstraints` cA-flag checks
  behind `cabf_tls_br::CabfTlsBrProfile`.

Future bundles (`cabf_smime_br`, `cabf_cs_br`) and zlint-derived catalog
content will land via PKIX-amgn.8 and friends. The wire format for the
vendored catalog data is an open design question (OSCAL Catalog JSON is
one candidate); see the bead for current status.

## Usage

```rust,no_run
use pkix_lint::{LintProfile, SubjectKind};
use pkix_lint_cabf::cabf_tls_br::CabfTlsBrProfile;

let profile = CabfTlsBrProfile;
let runner = profile.lint_runner();

let kinds = vec![SubjectKind::Leaf, SubjectKind::AnchorIssued];
let findings = runner.run_chain(&chain, &kinds, now_unix);

for f in findings.iter().filter(|f| f.is_finding()) {
    eprintln!("[{}] {}: {:?}", f.cert_index, f.lint_id, f.result);
}
```

## License

Apache-2.0 OR MIT
