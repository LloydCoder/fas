# FAS residual risk register

This document is the authoritative register for controls that are deliberately outside the local Alpha execution boundary or require external repository/account configuration.

## Repository controls

| Control | State | Enforcement |
|---|---|---|
| CI, CodeQL, secret scan, dependency audit | Implemented | GitHub Actions |
| PR dependency review | Implemented | GitHub Actions |
| Code-owner review paths | Implemented | CODEOWNERS |
| Protected `main` branch | External configuration required | Repository administrator |
| Required status checks on `main` | External configuration required | Repository administrator |
| Signed-commit requirement | External configuration required | Repository administrator |

The source repository cannot encode GitHub branch-protection state in tracked files. These settings must be enabled in repository administration.

## Phase 7 hosted profile

PostgreSQL, S3-compatible objects, tenant membership primitives, lease-aware durable jobs, and structured operational events are implemented for the hosted adapter profile. The deployment still owns TLS termination, external secret management, backup/restore, HA topology, network policy, IAM policy, and centralized metrics/tracing retention.

## Product profiles

The local profile uses SQLite, local content-addressed objects, and bounded in-process workers. The hosted profile provides PostgreSQL/S3 adapters, tenant-scoped roles, lease-aware durable jobs, and structured operational events.

Deployment-owned controls remain external: TLS termination, secret management, IAM policy, backup/restore, HA topology, network policy, centralized metrics/tracing, and operational retention.

## Evidence lifecycle

The local store exposes explicit retention and object-garbage-collection seams. Operators must schedule those maintenance operations according to their retention policy before using FAS for long-lived customer evidence.

## Independent assurance

CI and the FAS-Bench independent benchmark are internal verification layers. An external penetration test or independent source-code assessment remains an assurance activity outside the repository itself.

## Phase 8–12 maturity boundaries

- Phase 8 advanced analysis is bounded, graph-scoped, and cannot directly create findings or verdicts.
- Phase 9 runtime verification is controlled by executable allowlists, deny-all networking, secret denial, and the existing execution limits.
- Phase 10 integrations authenticate/bound transport but provider-specific collectors remain limited to implemented connectors.
- Phase 11 assurance artifacts provide versioned references and integrity-verifiable evidence; they do not assert framework compliance.
- Phase 12 research is budgeted and approval-aware; autonomous output is non-authoritative.

## External assurance

CI and the independent FAS-Bench benchmark are internal engineering verification layers. External penetration testing, independent source review, formal certification, and customer-specific control validation remain external assurance activities.
