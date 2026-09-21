# Contributing to FAS

Thank you for contributing to FAS. The project is security-analysis software, so correctness, reproducibility, provenance, immutable history, and safe execution matter more than feature volume.

## Start here

1. Read the [README](README.md).
2. Read the relevant [architecture documentation](docs/architecture/README.md).
3. Check the [ADRs](docs/decisions/README.md) before changing security semantics.
4. For security vulnerabilities, follow [SECURITY.md](SECURITY.md) rather than opening a public issue.
5. If you are unsure whether a proposed change fits the architecture, open a design discussion/issue before implementing a large change.

## What makes a good contribution?

Prefer changes that are:

- narrowly scoped
- reproducible
- testable
- evidence-backed
- explicit about capability boundaries
- documented at the same time as the implementation

High-value contribution areas include program analysis, evidence/provenance, graph algorithms, agent/MCP security, security-tool adapters, remediation verification, adversarial testing, reproducible security research, and documentation.

## Domain and evidence rules

- Observation, evidence, finding, investigation, verdict, remediation, and verification are distinct.
- Security-relevant relationships must be provenance/evidence backed.
- Original snapshot/evidence history is immutable.
- Candidate verification data must not silently cross snapshot boundaries.
- Missing evidence is explicit; absence is not negative evidence.
- LLM output is advisory and never the source of truth.

## Verification rules

- A remediation declares an expected security property and root cause.
- Verification compares explicit before/after snapshots.
- Semantic graph diff distinguishes security-relevant changes from identifier churn.
- Original attack paths are accounted for.
- Residual/alternate-path analysis is used where technically applicable.
- `REMEDIATED` requires completed required checks, verification evidence, and no blocking contradiction or missing evidence.
- `UNKNOWN` is the correct outcome when required evidence is unavailable.
- Candidate repositories are untrusted and must not receive ambient credentials or arbitrary execution privileges.

## Development setup

```bash
git clone https://github.com/LloydCoder/fas.git
cd fas
python -m pip install -e ".[dev]"
```

Run the local product smoke path:

```bash
fas doctor --format json
fas tools --format json
fas analyze ./path-to-fixture --format json
fas status <analysis-id> --format json
fas report <analysis-id> --format json
```

## Validation baseline

```bash
ruff check .
pytest --cov=fas --cov-report=term-missing
pytest tests/security
python -m pip check
python scripts/check_schema_parity.py
python -m build
```

CI also exercises supported Python versions, clean package installation, API/CLI smoke paths, reproducibility, product integration, and security gates.

**Never weaken assertions, remove security tests, skip workflows, or reduce permissions simply to obtain a green build.**

## Documentation synchronization

When a change affects public behavior or security semantics, update the relevant combination of:

- README
- CLI/API documentation
- schemas
- architecture documentation
- ADR
- threat model
- security verification matrix
- changelog

New domain objects normally require corresponding schema, persistence, API/CLI, tests, and documentation work where applicable.

## Security research

Use FAS only against systems you are authorized to analyze. Prefer controlled fixtures for demonstrations and regression tests.