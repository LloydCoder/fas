# ADR 0008 — Security Property Verification Policy

## Status

Accepted.

A remediation declares an expected security property. Verification evaluates that property using
deterministic graph, evidence, permission, control, and optional controlled-test results.

Decision policy:
- persistent or equivalent residual path → REMEDIATION_FAILED
- complete evidence establishing elimination → REMEDIATED
- insufficient evidence → UNKNOWN
- reappearance against a verified baseline → REGRESSED

The property outcome is recorded separately so mitigation is not confused with root-cause
elimination.
