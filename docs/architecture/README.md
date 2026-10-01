# Architecture

FAS is a modular monolith with explicit security-analysis boundaries and isolated execution controls.

## System lifecycle

```
CLI / API
  ↓
Application orchestration
  ↓
Discovery / collectors / adapters
  ↓
Evidence + provenance
  ↓
Evidence graph
  ↓
Investigation
  ↓
Exploitability / verdict analysis
  ↓
Remediation
  ↓
Verification
  ↓
Reporting
```

## Current implementation boundary

Phases 1–12 are implemented. The repository now contains local and hosted product profiles plus bounded advanced analysis, runtime verification, integrations, assurance, and governed research.

Implemented product concerns include the installable package, CLI/API service, local SQLite persistence, hosted PostgreSQL/S3 adapters, tenant-scoped roles, content-addressed objects, deterministic snapshot/discovery/collection, bounded subprocess policy, durable jobs, advanced graph analysis, controlled runtime verification, enterprise integration contracts, assurance bundles, governed research, completeness-aware reporting, diagnostics, health/OpenAPI metadata, and package/CI hardening.

The following remain explicit extension seams rather than implied capabilities:

- unrestricted candidate-code execution outside the controlled runtime policy
- deployment-owned TLS, IAM, backup/restore, HA topology, network controls, and centralized telemetry
- universal scanner/vulnerability coverage
- provider-specific integrations not yet implemented beyond the current connector substrate
- independent external assurance or penetration testing

## Architectural rules

### Evidence boundary

Collectors acquire observations. They do not independently declare exploitability.

### Provenance boundary

Evidence must retain enough provenance to identify its source, artifact state, collection method, and integrity context.

### Snapshot boundary

Original analysis state is immutable. Verification compares explicit before/after snapshots and must not silently mix evidence across them.

### LLM boundary

LLMs can formulate hypotheses, request evidence, and propose interpretations. They cannot create authoritative evidence, mutate immutable history, override deterministic verification, or authorize arbitrary execution.

### Capability boundary

Unsupported functionality must fail explicitly. The product must not simulate PostgreSQL, S3, arbitrary runtime execution, or other future adapters as though they were implemented.

## Layer responsibilities

| Layer | Responsibility | Prohibited shortcut |
|---|---|---|
| API | authentication, transport, request validation | security reasoning |
| CLI | commands and presentation | bypass application/domain rules |
| Application | orchestration and lifecycle | invent evidence |
| Collectors | deterministic observations | declare exploitability |
| Adapters | external-tool integration | erase provenance |
| Evidence | normalization, provenance, integrity | manufacture observations |
| Graph | evidence-backed relationships | invent unsupported edges |
| Analysis | correlation and path reasoning | bypass evidence constraints |
| Verdict | formal conclusions | create unsupported evidence |
| Remediation | before/after comparison | assume a patch worked |
| Reporting | presentation/serialization | alter conclusions |

## Phase map

1. **Foundations** — canonical domain contracts and immutable snapshots.
2. **Evidence Graph** — provenance-aware graph storage and bounded path analysis.
3. **Security Collection** — hostile-input-safe collection and tool adapters.
4. **Investigation** — evidence-grounded deterministic investigation and constrained LLM advisory.
5. **Verification** — remediation verification, semantic graph diff, path revalidation, regression baselines, and deterministic security-test contracts.
6. **Productization** — installable local product boundary, persistence, API/CLI, jobs, reporting, diagnostics, and CI/package hardening.
7. **Production Runtime & Scale** — hosted PostgreSQL/S3 adapters, tenant-scoped authorization, distributed-safe leases, operational telemetry, and production deployment boundaries.
8. **Advanced Security Analysis** — bounded deterministic reachability, privilege, agent/tool, sensitive-resource, and attack-surface analysis.
9. **Trusted Runtime Verification** — controlled sandboxed runtime verification over the bounded execution policy.
10. **Enterprise Integrations** — tenant-scoped event normalization, idempotency, secure outbound connectors, and authenticated webhook processing.
11. **Governance & Assurance** — versioned framework references, evidence-required assessments, and deterministic evidence bundles.
12. **Platform Maturity** — bounded governed research with explicit approval and non-authoritative autonomy boundaries.

Detailed phase decisions are recorded in [Architecture Decision Records](../decisions/README.md).