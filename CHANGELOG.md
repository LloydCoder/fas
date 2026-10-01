# Changelog

## Phase 8

- Added bounded deterministic advanced graph analysis for reachability, privilege, agent/tool, and sensitive-resource paths.
- Added attack-surface inventory and evidence-scoped analysis signals.
- Preserved explicit limits and incomplete/truncated semantics.
- Reconciled the architecture and README analysis boundaries.


## 0.7.0 — Phase 7

- Added production-selectable PostgreSQL persistence with tenant-scoped rows and membership roles.
- Added S3-compatible content-addressed object storage with read-time SHA-256 verification.
- Made durable worker lifecycle tenant-aware and preserved lease/cancellation semantics.
- Added hosted deployment configuration, structured operational events, migration contract, and production architecture/threat documentation.
- Added Phase 7 regression coverage for tenant authorization, S3 integrity/idempotency, and hosted configuration.


All notable changes to FAS are documented here.

## Documentation and repository experience — 2026-09-21

- Reworked the root README into a contributor-oriented project entry point with quick start, architecture boundaries, capability limits, documentation map, roadmap, and FAS-Bench integration context.
- Reconciled architecture, evidence-model, and threat-model indexes with the implemented Phase 6 product boundary.
- Added a canonical documentation index at `docs/README.md`.
- Added `SUPPORT.md` with clear routing for usage questions, bugs, feature proposals, and private security reports.
- Added repository ownership, pull-request guidance, and structured issue templates to improve contribution quality and maintainer review.
- Removed documentation ambiguity that described Phase 6 as future work after its implementation.

## Phase 6 V2 enforcement — 2026-09-19

- Hardened subprocess execution with canonical executable resolution, sanitized environment, bounded output, timeout/cancellation handling and non-root policy.
- Removed production dependence on target-repository fixture verdict oracles.
- Added deterministic completeness propagation, canonical snapshot manifest metadata and explicit report completeness.
- Strengthened content-addressed storage and tamper-evident audit-chain verification.
- Corrected discovery boundaries and deterministic tool-run identity scoping.
- Added Phase 6 adversarial regression coverage and expanded CI security/reproducibility gates.

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

The project is in alpha; the 0.6.0 Phase 6 product boundary remains bounded and does not claim universal vulnerability coverage or arbitrary runtime sandboxing.

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

## Phase 9

- Added a controlled sandboxed runtime verification adapter over SecureExecutor.
- Enforced explicit executable allowlisting, DENY_ALL networking, secret denial, bounded execution, and output integrity digests.
- Added runtime contract and threat-model documentation plus regression coverage.

## Phase 10

- Added tenant-scoped integration event normalization and idempotency contracts.
- Added HTTPS host-allowlisted outbound connectors and a GitHub REST connector.
- Added bounded GitHub webhook authentication/normalization primitives.
- Added enterprise integration architecture and threat-model documentation.

## Phase 11

- Added machine-readable control assessment and framework reference contracts.
- Added deterministic evidence-bundle manifests with independent integrity verification.
- Added explicit assurance states and evidence requirements.
- Added governance architecture and threat-model documentation.
