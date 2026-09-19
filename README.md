# FAS

## Forensic Agent Security

**Evidence-first security analysis for AI agents and modern software — proving exploitability, reconstructing attack paths, and verifying remediation.**

[![Status: Early Development](https://img.shields.io/badge/status-early%20development-orange)](https://github.com/LloydCoder/fas)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> **FAS is being built around a simple rule: security conclusions must be traceable to evidence.**

FAS is an open-source security analysis engine designed to investigate findings across modern software and AI-agent systems. It combines deterministic security tooling, code and configuration analysis, an evidence graph, attack-path reconstruction, exploitability analysis, and remediation verification.

FAS is not intended to replace existing scanners. It is intended to answer the questions scanners often leave unresolved:

- Is the reported condition actually reachable?
- Can an attacker influence the relevant input or state?
- What data and control-flow path connects the entry point to the dangerous operation?
- Which identity, permissions, tools, services, and trust boundaries are involved?
- What security controls are actually present?
- Can the attack path be demonstrated or otherwise verified?
- Does the proposed remediation break the original path?
- Did the remediation introduce a residual or alternate path?
- When the available evidence is insufficient, can the system explicitly return **UNKNOWN** instead of inventing certainty?

---

## Why FAS?

Modern security programs produce large volumes of findings from SAST, SCA, secret scanners, IaC scanners, runtime telemetry, cloud configuration, agent tooling, and other systems.

A finding is not the same thing as a proven vulnerability.

FAS is designed to create a chain of provenance:

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
IMMUTABLE REPOSITORY SNAPSHOT
```

A security conclusion should be reproducible from that chain.

### Core principles

1. **Evidence before conclusions** — findings and verdicts must be supported by observable evidence.
2. **Provenance is first-class** — evidence records where an observation came from, how it was collected, and which artifact state it describes.
3. **LLMs are investigators, not ground truth** — models may formulate hypotheses and request evidence, but deterministic collectors and verification mechanisms establish observations.
4. **Immutable analysis snapshots** — an analysis is tied to a defined repository/configuration/runtime state.
5. **Explicit attack paths** — important security conclusions expose the path from attacker influence to impact.
6. **Uncertainty is a valid result** — missing evidence is represented explicitly; FAS can return `UNKNOWN`.
7. **Remediation must be verified** — changing vulnerable code is not itself proof that the security condition is gone.
8. **Existing security tooling is complementary** — FAS correlates established tools rather than reimplementing every scanner.

---

## What FAS analyzes

FAS is designed to reason across connected security domains:

- Application code
- Data and control flow
- Dependencies and software supply chain
- Authentication and authorization
- Identities and permissions
- AI agents and agent tasks
- Tools and MCP-style tool interfaces
- Credentials and secret references
- APIs and service boundaries
- Infrastructure and configuration
- Trust boundaries
- Runtime observations
- Security controls
- Remediation changes

The initial implementation will prioritize a smaller subset and expand incrementally.

---

## Core capabilities

### Security signal ingestion

FAS can consume observations from security tools and deterministic collectors, including planned adapters for tools such as Semgrep, Trivy, Gitleaks, OSV-compatible dependency intelligence, and MCP/tooling analysis.

A tool observation is **not automatically a FAS finding**. FAS preserves the observation and correlates it with additional evidence.

### Evidence normalization

FAS normalizes observations into a common evidence model containing provenance such as:

- collector
- tool and version
- collection method
- artifact
- file/location
- observed value
- timestamp
- content hash
- provenance metadata

### Evidence graph

FAS builds a graph connecting repositories, artifacts, files, symbols, endpoints, services, identities, principals, permissions, agents, tasks, tools, data assets, findings, evidence, attack paths, remediations, and runtime observations.

Graph relationships are evidence-backed objects.

### Exploitability analysis

A candidate finding can be investigated against questions such as:

- Is attacker influence established?
- Is the relevant capability reachable?
- Does attacker-controlled data reach the security-sensitive operation?
- Which identity executes it?
- What privileges are required?
- Which trust boundaries are crossed?
- Are effective controls present?
- Is the impact path established?
- What evidence remains missing?

### Attack-path reconstruction

FAS represents security paths explicitly:

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

Critical relationships should carry provenance.

### Formal verdicts

FAS uses explicit verdict states:

- `EXPLOITABLE`
- `NOT_EXPLOITABLE`
- `CONDITIONALLY_EXPLOITABLE`
- `REMEDIATED`
- `REMEDIATION_FAILED`
- `REGRESSED`
- `UNKNOWN`

A verdict includes supporting evidence, contradicting evidence, rationale, and missing evidence.

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
Graph Diff
      ↓
Attack-Path Verification
      ↓
Remediation Verdict
```

The goal is to establish whether the original condition was eliminated and whether a residual or alternate path remains.

---

## Architecture

FAS is initially designed as a **modular monolith with isolated execution workers**, rather than a distributed microservice fleet.

```
                         FAS API / CLI
                              │
                              ▼
                    Analysis Orchestrator
                              │
             ┌────────────────┼────────────────┐
             ▼                ▼                ▼
        Discovery        Tool Adapters      Runtime
             │                │             Collectors
             └────────────────┼────────────────┘
                              ▼
                    Evidence Normalizer
                              │
                              ▼
                       Evidence Graph
                              │
              ┌───────────────┼────────────────┐
              ▼               ▼                ▼
          Data Flow       Permissions      Reachability
              │               │                │
              └───────────────┼────────────────┘
                              ▼
                    Attack-Path Analysis
                              │
                              ▼
                   Exploitability Analysis
                              │
                              ▼
                       Verdict Engine
                              │
                ┌─────────────┴─────────────┐
                ▼                           ▼
             Reporting                 Remediation
                                            │
                                            ▼
                                      Verification
```

### Architectural boundaries

| Component | Responsibility | Must not do |
|---|---|---|
| API | Authentication, requests, results | Security reasoning |
| Orchestrator | Workflow and state transitions | Invent evidence |
| Discovery | Build system inventory | Produce final verdicts |
| Collectors | Acquire observations | Declare exploitability |
| Adapters | Integrate external tools | Rewrite tool truth |
| Evidence layer | Normalize, provenance, integrity | Manufacture observations |
| Graph | Store evidence-backed relationships | Invent relationships |
| Analysis | Correlate and reason over graph | Bypass provenance |
| Verdict engine | Produce formal conclusions | Create unsupported evidence |
| Remediation | Compare and verify changes | Assume a patch worked |
| Reporting | Present results | Alter conclusions |

---

## Evidence model

Evidence is a first-class FAS domain object.

A simplified record looks like:

```json
{
  "evidence_id": "evidence_01J...",
  "type": "CODE_LOCATION",
  "claim": "User-controlled input reaches an HTTP client",
  "source": {
    "artifact_id": "artifact_123",
    "path": "src/fetcher.py",
    "line_start": 42,
    "line_end": 48,
    "symbol": "fetch_url"
  },
  "observed_value": "...",
  "provenance": {
    "collector": "static-analysis",
    "tool": "semgrep",
    "tool_version": "...",
    "method": "static_analysis"
  },
  "integrity": {
    "content_hash": "sha256:..."
  }
}
```

Canonical schemas will live under [`schemas/`](schemas/) and evidence documentation under [`docs/evidence-model/`](docs/evidence-model/).

### Provenance levels

FAS can record provenance strength separately from model confidence:

- **T0** — unverified assertion
- **T1** — model inference
- **T2** — tool-generated observation
- **T3** — deterministically verified artifact
- **T4** — reproduced runtime observation
- **T5** — independently reproduced security test

These levels describe how an observation was established. They are not substitutes for evaluating whether evidence actually supports a claim.

---

## AI-assisted investigation

The intended investigation loop is constrained:

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

The model should not have unrestricted database access or the ability to create arbitrary evidence.

Planned investigator capabilities include:

- `get_evidence()`
- `query_graph()`
- `inspect_file()`
- `inspect_symbol()`
- `trace_callers()`
- `trace_callees()`
- `trace_dataflow()`
- `inspect_permissions()`
- `inspect_dependency()`
- `request_runtime_test()`
- `propose_verdict()`

---

## Domain model

The canonical FAS domain is centered around:

```
Analysis
Snapshot
Artifact
Observation
Evidence
GraphNode
GraphEdge
Finding
AttackPath
Verdict
Remediation
Verification
```

Additional node types will be introduced only when justified by an actual analysis requirement.

---

## Repository structure

```
fas/
├── .github/
│   └── workflows/
├── docs/
│   ├── architecture/
│   ├── decisions/
│   ├── evidence-model/
│   └── threat-model/
├── schemas/
├── src/
│   └── fas/
│       ├── api/
│       ├── application/
│       ├── domain/
│       ├── collectors/
│       ├── adapters/
│       ├── analysis/
│       ├── agents/
│       ├── remediation/
│       ├── persistence/
│       └── infrastructure/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── security/
│   └── fixtures/
├── scripts/
├── CONTRIBUTING.md
├── SECURITY.md
├── CODE_OF_CONDUCT.md
├── CHANGELOG.md
├── LICENSE
├── pyproject.toml
└── README.md
```

The structure follows domain boundaries rather than individual vendors.

---

## Development status

FAS is currently in **early development**.

The public repository is being established around the formal domain model and evidence architecture before claiming production readiness.

### Current priorities

- [x] Canonical domain schemas
- [x] Immutable analysis snapshots
- [x] Evidence store and provenance
- [x] Graph node/edge model
- [x] Repository, code, and dependency discovery
- [x] Initial security-tool adapters
- [x] Observation-to-evidence normalization
- [x] Deterministic graph investigation primitives
- [ ] Exploitability analysis
- [ ] Attack-path reconstruction
- [ ] Formal verdict engine
- [ ] Remediation verification
- [ ] CLI
- [ ] API
- [ ] Production hardening

Until these components are implemented and tested, FAS should be considered experimental software.

---

## Relationship to existing security tools

FAS is designed to complement established security tooling.

```
                    Security Signals
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
       Semgrep           Trivy          Gitleaks
          │                │                │
          └────────────────┼────────────────┘
                           ▼
                  FAS Evidence Layer
                           │
                           ▼
                     Evidence Graph
                           │
                           ▼
                    Security Analysis
                           │
                           ▼
                     Attack Path
                           │
                           ▼
                      FAS Verdict
```

The objective is not to claim that one scanner is sufficient. FAS combines evidence sources while preserving their provenance.

---

## Security

FAS itself is security-sensitive software because it may process hostile repositories and execute analysis tooling.

Security engineering is therefore part of the product architecture.

The project will use:

- dependency vulnerability monitoring
- secret detection
- code scanning
- security-focused tests
- least-privilege execution
- sandboxing for potentially dangerous analysis
- provenance and integrity checks
- responsible vulnerability disclosure

See [SECURITY.md](SECURITY.md).

---

## Threat model

FAS may process source code, configuration, dependency metadata, security findings, runtime observations, and potentially sensitive security evidence.

Initial threat areas include:

- malicious repositories
- hostile source code
- prompt injection embedded in analyzed content
- malicious tool metadata
- unsafe command execution
- dependency compromise
- credential exposure
- sandbox escape
- evidence tampering
- cross-analysis data leakage
- confused-deputy behavior
- unauthorized remediation

The analysis execution environment must be treated as a sandbox boundary. Untrusted artifacts must not receive ambient access to production credentials, internal networks, or privileged host resources.

See [docs/threat-model/](docs/threat-model/).

---

## Design goals

### Correctness over coverage

A smaller set of defensible conclusions is preferable to a larger set of unsupported findings.

### Evidence over prose

A persuasive explanation without supporting evidence is not sufficient.

### Deterministic foundations

The security substrate should remain reproducible even when an LLM participates in investigation.

### Human-verifiable results

A security engineer should be able to trace an important conclusion back to the artifacts and observations that support it.

### Incremental architecture

FAS should begin as a modular monolith and introduce distributed infrastructure only when real workload characteristics justify it.

### Extensible tooling

External scanners and collectors should be adapters rather than assumptions spread throughout the analysis engine.

---

## Non-goals

FAS is not intended to:

- replace every SAST, SCA, DAST, IaC, or security tool
- treat LLM output as authoritative security evidence
- provide a universal vulnerability database
- guarantee that every vulnerability can be automatically proven
- silently infer missing environment facts
- execute arbitrary remediation without explicit authorization
- claim production readiness before implementation and security controls justify it

---

## Roadmap

### Phase 1 — Foundations

- Domain contracts
- Evidence schema
- Snapshot model
- Provenance model
- Canonical domain contracts
- Provenance, integrity, and hostile-input tests

### Phase 2 — Evidence Graph

- Canonical graph node/edge scope and identity
- In-memory indexed graph store abstraction
- Provenance-aware relationships and evidence lookup
- Deterministic traversal, shortest paths and bounded path enumeration
- Strongly/weakly connected components and cycle analysis
- Snapshot-isolated subgraph and trust-boundary queries
- Deterministic JSON export/import and cross-snapshot graph diff
- Graph sealing, validation, partial and truncation semantics

### Phase 3 — Security Collection

- Scoped repository, code, and dependency discovery
- Deterministic artifact hashing and immutable collection records
- Observation normalization into provenance-preserving evidence
- SARIF 2.1.x, Semgrep JSON, Trivy JSON, and Gitleaks JSON adapters
- Secret-safe tool-output handling
- Explicit partial-collection semantics and bounded discovery
- Collector/adapter boundary that cannot create findings or verdicts

### Phase 4 — Investigation

- Data-flow tracing
- Reachability analysis
- Permission analysis
- Finding correlation
- Attack-path construction
- Exploitability analysis

### Phase 5 — Verification

- Formal verdict engine
- Runtime/security-test hooks
- Remediation comparison
- Graph diff
- Regression detection

### Phase 6 — Productization

- API
- CLI
- Reports
- Worker execution
- Sandboxed analysis
- Performance and reliability hardening

---

## Documentation

- [Architecture](docs/architecture/README.md)
- [Evidence Model](docs/evidence-model/README.md)
- [Threat Model](docs/threat-model/README.md)
- [Architecture Decision Records](docs/decisions/README.md)
- [Contributing](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

---

## Contributing

Contributions are welcome, particularly around:

- security analysis
- program analysis
- evidence modeling
- graph algorithms
- agent security
- MCP/tool security
- runtime verification
- reproducible security research
- testing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

---

## License

FAS is licensed under the [Apache License 2.0](LICENSE).

---

## Disclaimer

FAS is security analysis software. Results are evidence produced by the configured analysis environment and should be reviewed in the context of the target system, threat model, and available evidence.

FAS does not guarantee that a system is secure or that a reported verdict captures every possible attack path.
