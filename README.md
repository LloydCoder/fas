# FAS

## Forensic Agent Security

**Evidence-first security analysis for AI agents and modern software — reconstructing attack paths, testing exploitability, and verifying remediation without treating scanner output or LLM prose as ground truth.**

[![Status: Alpha](https://img.shields.io/badge/status-alpha-orange)](https://github.com/LloydCoder/fas)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

> **Security conclusions should be traceable to evidence.**

FAS is an open-source security analysis engine for investigating findings across application code, dependencies, identity and authorization, AI agents, tools/MCP interfaces, configuration, CI/CD, and connected service boundaries.

FAS focuses on the questions scanners often leave unresolved:

- Is the reported condition actually reachable?
- Can attacker-controlled data or state reach the sensitive operation?
- Which identity, permission, tool, service, or trust boundary is involved?
- What evidence establishes the claim, and where did it come from?
- Can the relevant attack path be reconstructed?
- Did the remediation actually break the original security property?
- Does a residual or alternate path remain?
- What evidence is missing or contradictory?

FAS is deliberately **complementary to security scanners**, not a replacement for them.

---

## Why evidence-first?

A scanner finding is a signal. A security conclusion requires context.

```
VERDICT
  ↓
FINDING
  ↓
ATTACK PATH
  ↓
GRAPH RELATIONSHIPS
  ↓
EVIDENCE
  ↓
ARTIFACT / CODE LOCATION
  ↓
IMMUTABLE SNAPSHOT
```

The goal is not to maximize the number of findings. It is to make important conclusions inspectable, reproducible, and appropriately uncertain.

### Core principles

1. **Evidence before conclusions** — security claims require supporting observations.
2. **Provenance is first-class** — evidence records origin, method, artifact state, and integrity metadata.
3. **LLMs are advisory** — models may form hypotheses and request evidence; they do not create ground truth.
4. **Snapshots are explicit** — analysis is bound to a defined repository/configuration state.
5. **Attack paths are explicit** — important security relationships should be traceable.
6. **Unknown is valid** — missing evidence is never silently converted into a negative fact.
7. **Remediation is verified** — a changed line or disappearing scanner result is not, by itself, proof of remediation.
8. **Tool truth is preserved** — external observations remain attributable to their source collectors.

---

## Current status

**Version:** `0.6.0`  
**Maturity:** Alpha  
**Current milestone:** Phase 6 productization is implemented as a bounded local product layer.

Phase 6 includes:

- installable Python package and `fas` CLI
- shared CLI/API application service
- local SQLite persistence
- content-addressed local objects
- deterministic repository snapshot/discovery/collection
- bounded subprocess execution policy
- durable local jobs
- completeness-aware reporting
- audit-chain integrity verification
- configuration diagnostics
- HTTP API and OpenAPI metadata
- package/build/install and security/reproducibility CI gates

### Explicit boundaries

FAS does **not** currently claim:

- universal vulnerability coverage
- that an incomplete graph proves absence
- that scanner disappearance proves remediation
- arbitrary candidate-repository code execution in the core product
- horizontally scaled workers
- PostgreSQL/S3 as fully hardened production adapters
- formal compliance with OWASP ASVS, OWASP Top 10, NIST, SLSA, or another framework

These are explicit capability boundaries, not hidden assumptions.

---

## Quick start

### Requirements

- Python **3.11+**
- Git
- Optional external security tools when their collectors are enabled

### Install for development

```bash
git clone https://github.com/LloydCoder/fas.git
cd fas
python -m pip install -e ".[dev]"
```

### Inspect the environment

```bash
fas doctor --format json
fas tools --format json
```

### Analyze a local project

```bash
fas analyze ./example-project --format json
fas status <analysis-id> --format json
fas findings <analysis-id> --format json
fas report <analysis-id> --format json
```

### Run the local API

```bash
fas api
```

The API binds to `127.0.0.1` by default. Non-local exposure requires explicit bearer-token authentication. Read [SECURITY.md](SECURITY.md) before exposing the service beyond a trusted local environment.

### Explore verification

```bash
fas verify --help
```

Verification operates on explicit verification inputs. It is not a generic claim that an entire application is secure.

---

## What FAS analyzes

FAS is designed to correlate evidence across:

- application code and program flow
- dependencies and software supply chain
- authentication and authorization
- identities, principals, and permissions
- APIs and service boundaries
- AI agents and agent tasks
- tools and MCP-style interfaces
- credentials and secret references
- infrastructure and configuration
- CI/CD metadata
- trust boundaries
- runtime observations where supported
- security controls
- remediation changes

A collector produces observations. An observation is not automatically a finding, and a finding is not automatically a proven vulnerability.

---

## Core capabilities

### Security-signal ingestion

FAS can normalize observations from supported deterministic collectors and adapters, including SARIF-compatible output and integrations for tools such as Semgrep, Trivy, and Gitleaks where configured.

### Evidence normalization

Evidence can retain:

- collector
- tool and version
- collection method
- artifact and location
- observed value
- timestamp
- content hash
- provenance metadata

### Evidence graph

FAS represents relationships among repositories, artifacts, files, symbols, endpoints, services, identities, permissions, agents, tasks, tools, data assets, findings, evidence, attack paths, remediations, and runtime observations.

Security-relevant relationships are expected to remain evidence-backed.

### Exploitability analysis

Investigation can ask whether attacker influence, reachability, data flow, effective identity, privileges, trust boundaries, controls, impact, and required evidence are established.

### Attack-path reconstruction

```
Internet
  ↓
Webhook
  ↓
Agent
  ↓
Tool
  ↓
CI Identity
  ↓
Production Resource
```

### Formal verdicts

FAS uses explicit states:

- `EXPLOITABLE`
- `NOT_EXPLOITABLE`
- `CONDITIONALLY_EXPLOITABLE`
- `REMEDIATED`
- `REMEDIATION_FAILED`
- `REGRESSED`
- `UNKNOWN`

A verdict is accompanied by supporting/contradicting evidence and missing-evidence context.

### Remediation verification

```
Original Snapshot
      ↓
Original Evidence Graph
      ↓
Remediation / Patch
      ↓
Patched Snapshot
      ↓
Patched Evidence Graph
      ↓
Semantic Graph Diff
      ↓
Attack-Path Revalidation
      ↓
Remediation Verdict
```

Verification is scoped to the configured finding, security property, evidence graph, paths, and checks. It does not prove that an entire application is secure.

---

## Architecture

FAS is a **modular monolith with isolated execution boundaries**.

```
                         CLI / API
                           │
                           ▼
                  Application Orchestrator
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
      Discovery       Tool Adapters      Collectors
          │                │                │
          └────────────────┼────────────────┘
                           ▼
                 Evidence + Provenance
                           │
                           ▼
                     Evidence Graph
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
          Data Flow    Permissions  Reachability
              │            │            │
              └────────────┼────────────┘
                           ▼
                   Attack-Path Analysis
                           │
                           ▼
                 Exploitability Analysis
                           │
                           ▼
                      Verdict Engine
                           │
                 ┌─────────┴─────────┐
                 ▼                   ▼
             Reporting          Remediation
                                     │
                                     ▼
                                Verification
```

### Boundary rules

| Layer | Owns | Must not |
|---|---|---|
| API | authentication, transport, request validation | perform security reasoning |
| CLI | commands and presentation | bypass application/domain rules |
| Application | orchestration and lifecycle | invent evidence |
| Collectors | deterministic observations | declare exploitability |
| Adapters | external-tool integration | erase provenance |
| Evidence | provenance, integrity, normalization | manufacture observations |
| Graph | evidence-backed relationships | invent unsupported relationships |
| Analysis | correlation and path reasoning | bypass evidence constraints |
| Verdict | formal conclusions | create unsupported evidence |
| Remediation | before/after comparison | assume a patch worked |
| Reporting | presentation/serialization | alter conclusions |

See [Architecture](docs/architecture/README.md) and [ADRs](docs/decisions/README.md).

---

## Evidence and provenance

FAS uses provenance levels to distinguish how an observation was established:

| Level | Meaning |
|---|---|
| T0 | unverified assertion |
| T1 | model inference |
| T2 | tool-generated observation |
| T3 | deterministic artifact verification |
| T4 | reproduced runtime observation |
| T5 | independently reproduced security test |

These are provenance classifications, **not truth probabilities**.

Canonical schemas live under [`schemas/`](schemas/). The detailed evidence model lives under [`docs/evidence-model/`](docs/evidence-model/).

---

## AI-assisted investigation

The intended loop is:

```
Hypothesis
   ↓
Evidence Request
   ↓
Deterministic Collector
   ↓
Verified Evidence
   ↓
Evidence Graph Update
   ↓
Reassessment
   ↓
Verdict Proposal
   ↓
Verification
```

The investigator boundary is intentionally narrow. Model output cannot:

- create authoritative evidence
- mutate immutable evidence history
- override deterministic verification requirements
- authorize arbitrary remediation
- obtain unrestricted database or filesystem access

---

## Security model

FAS may process hostile repositories, source code, configuration, scanner output, and sensitive security evidence. The analyzed repository must therefore be treated as **untrusted input**.

Important security boundaries include:

- hostile source/configuration parsing
- prompt injection in analyzed content
- malicious tool metadata
- subprocess and command execution
- dependency and CI supply-chain compromise
- credential exposure
- sandbox escape
- evidence tampering
- cross-analysis data leakage
- confused-deputy behavior
- unauthorized remediation

Read [SECURITY.md](SECURITY.md) and the [threat model](docs/threat-model/README.md).

---

## Repository layout

```text
fas/
├── .github/                 # CI and community automation
├── docs/                    # architecture, evidence, threat model, ADRs, security
├── schemas/                 # machine-readable contracts
├── src/fas/                 # Python package
├── tests/                   # unit, integration, security, fixtures
├── scripts/                 # repository validation and maintenance
├── CONTRIBUTING.md
├── SECURITY.md
├── CODE_OF_CONDUCT.md
├── SUPPORT.md
├── CHANGELOG.md
├── LICENSE
├── pyproject.toml
└── README.md
```

The source tree is organized around domain boundaries rather than individual vendors.

---

## Development

### Local validation

```bash
python -m pip install -e ".[dev]"
ruff check .
pytest --cov=fas --cov-report=term-missing
pytest tests/security
python -m pip check
python scripts/check_schema_parity.py
python -m build
```

CI also exercises supported Python versions, package installation, CLI/API smoke paths, reproducibility, product integration, and security-focused tests.

**Do not weaken assertions, remove security tests, bypass security gates, or reduce permissions merely to obtain a green build.**

### Security-sensitive changes

A strong contribution normally includes:

1. the smallest coherent implementation change
2. a regression test for the intended security property
3. schema updates when a public contract changes
4. an ADR when architecture or security semantics change
5. documentation updates
6. a changelog entry when the user-visible contract changes

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Documentation map

| Need | Read |
|---|---|
| Understand FAS quickly | This README |
| Learn the architecture | [Architecture](docs/architecture/README.md) |
| Understand evidence/provenance | [Evidence Model](docs/evidence-model/README.md) |
| Understand threats | [Threat Model](docs/threat-model/README.md) |
| Understand design decisions | [ADRs](docs/decisions/README.md) |
| Review Phase 6 controls | [Security Verification Matrix](docs/security/phase6-verification-matrix.md) |
| Contribute | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Report a vulnerability | [SECURITY.md](SECURITY.md) |
| Get help | [SUPPORT.md](SUPPORT.md) |
| Review history | [CHANGELOG.md](CHANGELOG.md) |

The README is intentionally the orientation layer. Deep design rationale belongs in `docs/`.

---

## Roadmap

FAS has completed the foundational phases through Phase 6. Future work should be advertised as explicit milestones, not implied capabilities.

### Completed

- **Phase 1 — Foundations:** domain contracts, evidence/provenance model, immutable snapshots.
- **Phase 2 — Evidence Graph:** provenance-aware graph storage, bounded traversal/path analysis, validation, serialization, and graph comparison primitives.
- **Phase 3 — Security Collection:** repository discovery, tool adapters, hostile-input hardening, raw artifacts, replay metadata, and collection acceptance tests.
- **Phase 4 — Investigation:** immutable cases, evidence requests, deterministic graph/data-flow primitives, attack-path reconstruction, exploitability analysis, and constrained LLM advisory boundary.
- **Phase 5 — Verification:** before/after remediation verification, semantic graph diff, attack-path revalidation, residual/alternate-path analysis, regression baselines, and deterministic security-test contracts.
- **Phase 6 — Productization:** installable package, shared CLI/API service, SQLite persistence, content-addressed objects, deterministic collection, bounded subprocess policy, durable jobs, completeness-aware reporting, diagnostics, API health/OpenAPI metadata, and CI/package hardening.

### Explicit extension seams

- hardened arbitrary runtime execution
- PostgreSQL/S3 production adapters
- horizontally scaled workers
- additional security-tool integrations
- broader runtime/cloud/environment evidence
- deeper agent/MCP security analysis
- additional benchmark/interoperability integrations

A future milestone becomes “implemented” only after code, tests, security controls, schemas, and documentation are reconciled.

---

## Relationship to FAS-Bench

[FAS-Bench](https://github.com/LloydCoder/fas-bench) is a separate repository and benchmark boundary.

FAS exposes versioned machine-readable analysis/report structures so an external benchmark can evaluate findings, evidence, attack paths, verdicts, remediation state, verification state, and provenance without importing private implementation modules.

Keeping the benchmark independent helps keep evaluation separate from product implementation.

---

## Standards and interoperability

FAS supports SARIF-oriented interoperability where implemented.

Security standards and frameworks may be used as engineering references, but references are **not compliance claims**. Formal compliance should only be stated when the relevant versioned requirements have been explicitly mapped, implemented, and verified.

---

## Contributing

Contributions are welcome in:

- application and program analysis
- evidence and provenance modeling
- graph algorithms
- agent and MCP security
- security-tool adapters
- remediation verification
- reproducible security research
- testing and adversarial regression coverage
- documentation and developer experience

Good first contributions should be small, testable, and evidence-oriented.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

---

## Security

Please report vulnerabilities privately rather than through public issues. See [SECURITY.md](SECURITY.md).

---

## License

FAS is licensed under the [Apache License 2.0](LICENSE).

---

## Disclaimer

FAS is security-analysis software. Results depend on configured collectors, tools, evidence, snapshots, and the analysis environment.

A FAS verdict is not a guarantee that a system is secure, nor does it claim to enumerate every possible attack path. Review conclusions in the context of the target system, threat model, and available evidence.
