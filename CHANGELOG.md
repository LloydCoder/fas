## Phase 6 — Productization — 2026-09-19

- Added installable product boundary with shared CLI/API application service.
- Added local SQLite persistence, durable job records, idempotency and bounded worker primitives.
- Added content-addressed local object storage abstraction and evidence-linked JSON reports.
- Added `fas analyze`, `status`, `findings`, `report`, `doctor`, `tools`, and `api` product commands.
- Added HTTP health endpoints, OpenAPI metadata, /v1 project/analysis/status/findings/report resources, request IDs, structured errors and explicit capability errors.
- Added configuration precedence, resource limits, secret-safe diagnostics and explicit sandbox policy primitives.
- Added package installation and CLI smoke gates to CI, plus Phase 6 product/security integration tests.
- Added benchmark-compatible machine-readable output schema and Phase 6 architecture/threat-model ADRs.
- Kept unsupported PostgreSQL/S3/runtime-sandbox capabilities explicit rather than simulating them.

## Phase 3 completion — 2026-09-19

- Completed bounded collection lifecycle and explicit collection states.
- Added secure subprocess execution, raw tool artifacts, ToolRun metadata and replay manifests.
- Added agent/MCP, configuration and CI/CD inventory collectors.
- Added parser, filesystem, path, resource, fuzz/property and benchmark hardening.
- Preserved the Phase 3 boundary: collectors produce observations/evidence only; findings, exploitability and verdicts remain later phases.

# Changelog

All notable changes to FAS will be documented here.

The project is currently in early development and has not established a stable release series.

## Unreleased

- Established the public repository foundation.
- Added the initial architecture, evidence-model, threat-model, and contribution documentation.

## Phase 4 — Investigation

- Added immutable-snapshot investigation cases, hypotheses, evidence requests and lifecycle states.
- Added bounded deterministic graph, call/data-flow, endpoint, identity, permission, agent/MCP, control and alternate-path primitives.
- Added evidence-validated attack-path reconstruction and conservative exploitability analysis.
- Added model-agnostic investigator provider, deterministic fake model, structured output validation and external tool authorization boundary.
- Added append-only local persistence seam, PostgreSQL schema, JSON Schema contract and parity checking.
- Added security tests and investigation architecture/threat-model documentation.

## Phase 5 — Verification

- Added explicit remediation, verification-plan, verification-run, graph-diff, attack-path-comparison, residual-path, verification-evidence, regression, baseline, regression-test, security-test, result, and report contracts.
- Added snapshot-to-snapshot deterministic verification with explicit security-property outcomes and no-false-success invariants.
- Added semantic graph differential analysis for permissions, identities, trust boundaries, data-flow, controls, dependencies, agents, tools, credentials, and endpoints.
- Added bounded original/residual/alternate attack-path revalidation using the Phase 4 graph primitives.
- Added append-only JSONL verification persistence seam and deterministic fixture security-test executor.
- Added Phase 5 schema parity, verification fixtures, threat-model coverage, ADRs, and structured `fas verify` CLI support.
- Kept arbitrary candidate-repository execution outside the core Phase 5 runtime boundary.
