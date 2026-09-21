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

Phases 1–6 are implemented. Phase 6 is the current bounded local product boundary.

Implemented product concerns include the installable package, CLI/API service, local SQLite persistence, content-addressed objects, deterministic snapshot/discovery/collection, bounded subprocess policy, durable local jobs, completeness-aware reporting, diagnostics, health/OpenAPI metadata, and package/CI hardening.

The following remain explicit extension seams rather than implied capabilities:

- hardened arbitrary candidate-code runtime execution
- PostgreSQL/S3 production adapters
- horizontally scaled workers
- universal scanner/vulnerability coverage
- broader runtime/cloud/environment collectors

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

Detailed phase decisions are recorded in [Architecture Decision Records](../decisions/README.md).