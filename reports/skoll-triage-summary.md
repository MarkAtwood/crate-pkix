# Skoll Security Audit Triage Summary (PKIX-szmo)

Date: 2026-06-04
Tool: Skoll v0.1.292 (wolfSSL/fenrir), `--effort max`
Scope: Full PKIX workspace (`pkix-path`, `pkix-revocation`, `pkix-revocation-http`, `pkix-chain`, `pkix-lint`, `pkix-identity`, `pkix-ct`, `pkix-truststore`, `pkix-profiles`, `pkix-profiles-cabf`, `pkix-lint-cabf`, `pkix-aia`, `pkix-aia-http`, `pkix-zlint-bridge`, `pkix-policy-zlint`, `pkix-path-builder`, `pkix-difftest`)

## Scan Status

| Scan | Status | Findings |
|------|--------|----------|
| Security (CWE-mapped) | Complete | 13 |
| Constant-time | Complete | 6 |
| Bugs (logic errors) | Complete | 6 |
| Review (code quality) | Complete | 21 |
| RFC conformance | Open (PKIX-szmo.2) | Blocked on API credits |
| **Total** | | **46** |

## Triage Classification

### Duplicates of existing beads (3)

| Scan | Finding | Existing Bead | Summary |
|------|---------|---------------|---------|
| SECURITY MEDIUM-1 | SCT u16 timestamp truncation | PKIX-q74z.4 (P2) | pkix-ct hash/sig alg stored as u8, potential truncation on wider TLS alg values |
| REVIEW LOW-5 | UUID v8 seed concatenation without length prefix | PKIX-7f92.53 (P3) | Concatenation of variable-length fields without separator in OSCAL UUID seeds |
| SECURITY MEDIUM-10 | Async anchor revocation check skipped | PKIX-f1j4.5 (P1) | RevocationChecker default method returns Ok(()) for anchors; async wrappers inherit |

### Genuine new findings — fix beads filed (4)

| Scan | Finding | New Bead | Priority | Summary |
|------|---------|----------|----------|---------|
| BUGS MEDIUM-1 | anyPolicy duplicate policy tree nodes | PKIX-6p6p | P2 | `already_covered` Vec snapshot is stale during expansion loop; overlapping `expected_policy_set` after PolicyMappings produces duplicate `PolicyNode` entries |
| REVIEW MEDIUM-6 | Deviation::new validation gap | PKIX-6cp5 | P3 | `id` and `target_lint` not validated for non-emptiness; empty values are silently inert |
| REVIEW MEDIUM-12 | OSCAL profile resolver silent drop | PKIX-cf0b | P3 | `resolve_profile` silently drops include-controls IDs not found in source Catalog; typos go undetected |
| SECURITY MEDIUM-11 | HTTP revocation no-CDP/no-AIA soft-fail | PKIX-hk56 | P3 | `Ok(())` return indistinguishable between "checked-clean" and "could-not-check"; design gap, documented/intentional |

### False positives dismissed (39)

**All 6 CONSTTIME INFO findings**: Compare public certificate data (subject DNs, serial numbers, SAN entries, policy OIDs, CRL issuer names, extension OIDs). No secrets at risk — certificate contents are public by definition.

**BUGS MEDIUM-6** (rfc822Name non-dotted constraint exact-match): The finding claims `.example.com` constraint should match `user@example.com`. Verified against RFC 5280 §4.2.1.10: "If the constraint does not begin with a period, it specifies a host." Non-dotted constraint = exact host match. Code is correct.

**REVIEW MEDIUM-14** (findings_at_or_above threshold logic): The finding claims `>=` comparison is wrong. Verified: `Severity::rank()` assigns Info=10, Notice=20, Warn=30, Error=40, Fatal=50. The `rank() >= threshold.rank()` comparison correctly includes the threshold severity and above. False positive.

**Remaining 30 findings**: LOW/INFO severity across SECURITY and REVIEW scans. Each individually reviewed and classified as either: (a) documented/intentional design choices with code comments explaining the rationale, (b) stylistic suggestions below the engineering threshold for filing, or (c) observations about public-data operations that pose no security risk. None warranted fix beads.

## Cross-reference with prior audits

| Prior Audit | Overlap |
|-------------|---------|
| PKIX-7f92 (pkix-lint crypto-security) | 1 duplicate (UUID seed separator) |
| PKIX-q74z (pkix-ct review) | 1 duplicate (SCT truncation) |
| PKIX-f1j4 (pkix-revocation review) | 1 duplicate (anchor revocation) |
| PKIX-hy2e (pkix-lint review) | 0 (OSCAL recursion finding is distinct from silent-drop) |
| PKIX-ppbr (pkix-path review) | 0 |

## Summary

- **46 total findings** across 4 completed scan modes
- **3 duplicates** of already-tracked issues (P1, P2, P3)
- **4 genuinely new** actionable findings filed (1 P2, 3 P3)
- **39 false positives / non-actionable** dismissed with rationale
- **1 scan mode** (RFC conformance) remains open, blocked on API credits
- **0 P0/P1 new findings** — no emergency fixes required
