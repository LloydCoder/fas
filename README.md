<div align="center">

# FAS
### Forensic Agent Security

**Evidence-first security analysis for AI agents and modern software — reconstruct attack paths, test exploitability, and verify remediation from traceable evidence.**

[![CI](https://github.com/LloydCoder/fas/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/LloydCoder/fas/actions/workflows/ci.yml)
[![CodeQL](https://github.com/LloydCoder/fas/actions/workflows/codeql.yml/badge.svg)](https://github.com/LloydCoder/fas/actions/workflows/codeql.yml)
[![License](https://img.shields.io/github/license/LloydCoder/fas)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)

</div>

> **A scanner finding is a signal. A FAS security conclusion must be evidence-backed, reproducible, and explicit about uncertainty.**

<pre><code class="language-mermaid">flowchart LR
    A[Code / Config / Tools] --> B[Observations]
    B --> C[Evidence + Provenance]
    C --> D[Evidence Graph]
    D --> E[Attack-Path Analysis]
    E --> F[Verdict]
    F --> G[Remediation Verification]
    G --> C</code></pre>

> [!NOTE]
> A recorded terminal demo is not yet committed. The repository should add a real, short FAS run under docs/media/ rather than presenting a fabricated demo.

## Why FAS

FAS helps security engineers investigate the questions scanners often leave unresolved.

| Security question | FAS approach |
|---|---|
| Is a condition reachable? | Evidence-backed reachability and path analysis |
| Can attacker-controlled state reach a sensitive operation? | Data-flow and relationship analysis |
| Which identity or trust boundary matters? | Identity, permission, service and tool relationships |
| What proves the claim? | Provenance-aware evidence |
| Did remediation work? | Before/after snapshots and semantic graph comparison |
| What remains unknown? | Explicit missing or contradictory evidence |
| Can an AI model decide the result? | No. Models are advisory, not authoritative |

FAS is complementary to deterministic security scanners, not a replacement for them.

## Quick Start

Prerequisites: Python 3.11+ and Git.

<pre><code>git clone https://github.com/LloydCoder/fas.git
cd fas
python -m pip install -e ".[dev]"
fas doctor --format json
fas analyze ./path-to-project --format json</code></pre>

The analysis returns an identifier. Continue with <code>fas status &lt;analysis-id&gt;</code>, <code>fas findings &lt;analysis-id&gt;</code>, or <code>fas report &lt;analysis-id&gt;</code>.

> [!WARNING]
> Only analyze repositories and systems you are authorized to inspect. FAS processes potentially hostile source, configuration and tool output. Read [SECURITY.md](SECURITY.md) before enabling execution or exposing the API.

## Installation

The repository provides a Python package and the <code>fas</code> console command.

<pre><code>python -m pip install -e ".[dev]"</code></pre>

Build and install a wheel when testing a distribution:

<pre><code>python -m build
python -m pip install dist/*.whl</code></pre>

| Requirement | Supported |
|---|---|
| Python | 3.11, 3.12, 3.13, 3.14 |
| Primary hardened runtime | Linux |
| Local persistence | SQLite |
| External security tools | Optional; inspect with <code>fas tools</code> |

## Usage

### Inspect the environment

<pre><code>fas doctor --format json
fas tools --format json</code></pre>

### Analyze a project

<pre><code>fas analyze ./path-to-project --format json
fas status &lt;analysis-id&gt; --format json
fas findings &lt;analysis-id&gt; --format json
fas report &lt;analysis-id&gt; --format json</code></pre>

### Run the local API

<pre><code>fas api</code></pre>

The default API address is <code>127.0.0.1:8765</code>. Any externally reachable deployment must enable bearer-token authentication.

### Verification

<pre><code>fas verify --help</code></pre>

Verification is scoped to explicit inputs and security properties. It is not a generic claim that an application is secure.

## Configuration

Configuration precedence is:

**defaults → JSON configuration file → FAS_* environment variables → CLI/application overrides**

| Setting | Default | Purpose |
|---|---|---|
| database_url | sqlite:///./.fas/fas.db | Local persistence |
| object_store_path | .fas/objects | Content-addressed objects |
| tenant_id | local | Tenant boundary |
| subject_id | local | Request subject |
| role | admin | reader, analyst, or admin |
| api_host | 127.0.0.1 | API bind address |
| api_port | 8765 | API port |
| auth_required | false | Require API authentication |
| max_workers | 2 | Local job concurrency |
| analysis_timeout_seconds | 900 | Analysis time limit |
| subprocess_timeout_seconds | 120 | Process time limit |
| max_artifact_bytes | 50000000 | Artifact size limit |
| max_graph_nodes | 200000 | Graph node bound |
| max_graph_edges | 500000 | Graph edge bound |
| network_policy | DENY_ALL | Runtime network policy |
| retention_days | 90 | Local retention policy |

Environment variables use the <code>FAS_</code> prefix. Never commit bearer tokens or other secrets.

## Features

| Capability | What it provides |
|---|---|
| Evidence ingestion | Normalizes observations while preserving source and provenance |
| Evidence graph | Connects artifacts, identities, permissions, services, findings and paths |
| Exploitability analysis | Tests reachability, influence, privilege and required conditions |
| Formal verdicts | Explicit exploitable, remediated, regression and unknown states |
| Remediation verification | Before/after snapshot and semantic graph comparison |
| AI-assisted investigation | Hypotheses and evidence requests without authoritative model control |
| Tool integration | Deterministic collector and adapter boundaries |
| Security controls | Provenance, bounded execution, redaction and isolation |
| CLI + API | Local human and machine interfaces |
| Reproducibility | Locked dependencies and extensive CI/security gates |

## Documentation

| Need | Documentation |
|---|---|
| First successful run | [Tutorials](docs/tutorials/README.md) |
| Task-specific procedure | [How-to guides](docs/how-to/README.md) |
| Architecture and rationale | [Explanation](docs/explanation/README.md) |
| Commands and configuration | [Reference](docs/reference/README.md) |
| System architecture | [Architecture](docs/architecture/README.md) |
| Evidence and provenance | [Evidence Model](docs/evidence-model/README.md) |
| Threats and controls | [Threat Model](docs/threat-model/README.md) |
| Architecture decisions | [ADRs](docs/decisions/README.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Vulnerability reporting | [SECURITY.md](SECURITY.md) |
| Support | [SUPPORT.md](SUPPORT.md) |
| History | [CHANGELOG.md](CHANGELOG.md) |

Machine-oriented navigation is available through [llms.txt](llms.txt).

## Development

<pre><code>python -m pip install -e ".[dev]"
ruff check .
pytest --cov=fas --cov-report=term-missing
pytest tests/security
python -m pip check
python scripts/check_schema_parity.py
python -m build</code></pre>

Security-sensitive changes should include regression coverage, preserve evidence/provenance semantics, update contracts and documentation where applicable, and never weaken a security gate merely to obtain a green build.

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security model

FAS treats analyzed repositories and external tool output as untrusted input. Important boundaries include hostile parsing, prompt injection, subprocess/runtime execution, dependency and CI supply-chain compromise, credential exposure, evidence tampering, cross-analysis isolation, agent/tool authorization, and verification bypass.

> [!NOTE]
> LLM output is advisory. Models cannot create authoritative evidence, mutate immutable evidence history, bypass deterministic verification, or authorize arbitrary remediation/runtime commands.

Read the [threat model](docs/threat-model/README.md) and [security policy](SECURITY.md).

## Project status

**Package version:** 0.6.0  
**Maturity:** Alpha.

The current main branch contains the Phase 1–16 implementation described by the repository architecture. Version 0.6.0 remains the latest version recorded in package metadata and the changelog; Phases 13–16 are implemented on main but unreleased until a corresponding versioned release is published.

> [!WARNING]
> FAS does not claim universal vulnerability coverage, complete attack-path enumeration, arbitrary candidate-repository execution, hardened horizontal scale, or formal compliance with OWASP ASVS, OWASP Top 10, NIST, SLSA, or another framework without a specific verified mapping.

## Relationship to FAS-Bench

[FAS-Bench](https://github.com/LloydCoder/fas-bench) is a separate benchmark boundary. Keeping evaluation independent from product implementation lets external benchmark data evaluate findings, evidence, attack paths, verdicts, remediation state and provenance without importing private FAS implementation modules.

## Contributing

Contributions are welcome in program analysis, evidence/provenance, graph algorithms, agent/MCP security, security-tool adapters, remediation verification, adversarial testing, reproducible security research, and documentation.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## License and acknowledgements

FAS is licensed under the [Apache License 2.0](LICENSE).

FAS builds on the Python ecosystem and interoperates with established security tooling and machine-readable security formats. External tools remain attributable sources; FAS does not convert their output into authoritative conclusions without evidence-backed analysis.

<details>
<summary>Roadmap</summary>

Future work is versioned capability development rather than another numbered phase system. Priorities include deeper language-aware analysis, additional integrations, stronger hosted operations, benchmark expansion, independently assessed assurance, and controlled model-assisted research.

</details>

<details>
<summary>Troubleshooting</summary>

Start with <code>fas doctor --format json</code> and <code>fas tools --format json</code>. Then use the [How-to guides](docs/how-to/README.md) or [SUPPORT.md](SUPPORT.md). Never use a public issue for a vulnerability.

</details>
