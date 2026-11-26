# Hati Security Audit Triage Summary

Date: 2026-06-04
Tool: Hati v0.1.0 (MarkAtwood/hati), 3-stage adversarial pipeline
Scope: Full PKIX workspace (all workspace members under `/home/mark/PROJECT/PKIX/`)

## Pipeline Stages

| Stage | Description | Method |
|-------|-------------|--------|
| Hunt | Parallel vulnerability hunters (9 attack classes) | Sonnet |
| Validate | Adversarial reviewers attempt to disprove findings | Opus |
| Trace | Reachability analysis from external input to vulnerable code | Opus |

## Attack Classes Scanned

deserialization, buffer_overflow, injection, unsafe_code, xss, prototype_pollution, path_traversal, memory_corruption, integer_overflow

## Scan Results

| Stage | Findings In | Findings Out | Notes |
|-------|-------------|--------------|-------|
| Hunt | — | 1 | `f_ptrav7_1` (path_traversal in `limbo-to-pem-tree.py`) |
| Validate | 1 | 1 | Confirmed, confidence 0.92 |
| Trace | 1 | 0 | Unreachable, confidence 0.92 |
| **Final** | | **0 reachable** | **Clean scan** |

## Finding Detail

### f_ptrav7_1 — path traversal in limbo-to-pem-tree.py

- **File**: `pkix-difftest/python/limbo-to-pem-tree.py`
- **Hunt result**: Potential path traversal via user-influenced file paths
- **Validate result**: Confirmed (0.92 confidence) — the script constructs output paths from corpus data
- **Trace result**: Unreachable (0.92 confidence) — developer utility script in pkix-difftest, not production code; no external input path reaches the vulnerable code in a deployed context
- **Disposition**: No action required. The script is a maintainer-only offline tool that converts x509-limbo corpus data into PEM tree fixtures. It is never invoked by library consumers or in production.

## Cross-reference with Prior Audits

| Prior Audit | Overlap |
|-------------|---------|
| PKIX-szmo (Skoll full-workspace scan) | 0 overlap — Skoll found 46 findings (4 genuine, 39 FP, 3 duplicates); Hati's single raw finding was in a different file and attack class |

## Cost

Total: $8.26 across 11 agent invocations.

## Summary

Clean scan. The one raw finding the Hunt stage surfaced did not survive
reachability analysis, so no fixes are required.
