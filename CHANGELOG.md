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
