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

## Product boundary

FAS local Alpha uses SQLite, a local content-addressed object store, and bounded in-process workers. A hosted multi-tenant deployment additionally requires PostgreSQL/S3 adapters, tenant identity/RBAC, centralized observability, external secret management, HA, and network/TLS termination.

Those are deployment profiles, not hidden guarantees of the local product.

## Evidence lifecycle

The local store exposes explicit retention and object-garbage-collection seams. Operators must schedule those maintenance operations according to their retention policy before using FAS for long-lived customer evidence.

## Independent assurance

CI and the FAS-Bench independent benchmark are internal verification layers. An external penetration test or independent source-code assessment remains an assurance activity outside the repository itself.
