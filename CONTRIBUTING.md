# Contributing to FAS

FAS is security-analysis software. Contributions should prioritize correctness, reproducibility,
provenance, immutable history, and safe execution.

## Before contributing

1. Read the README and the applicable architecture/ADR documentation.
2. Keep changes within one architectural phase where practical.
3. Do not commit secrets, credentials, customer data, or production artifacts.
4. Add security-focused regression tests for security-sensitive changes.
5. Keep schemas and documentation synchronized with domain contracts.

## Domain and evidence rules

- Observation, evidence, finding, investigation, verdict, remediation, and verification are distinct.
- Every security-relevant relationship must be provenance/evidence backed.
- Original snapshot/evidence history is immutable.
- Candidate verification data must never silently cross snapshot boundaries.
- Missing evidence is explicit; do not turn absence into a negative fact.
- LLM output is advisory and never the source of truth.

## Verification rules

- A remediation declares an expected security property and root cause.
- Verification compares explicit before/after snapshots.
- Semantic graph diff must distinguish security-relevant changes from identifier churn.
- Original attack paths must be accounted for.
- Bounded residual/alternate-path analysis is required where technically applicable.
- `REMEDIATED` requires completed required checks, verification evidence, and no blocking
  contradiction or missing evidence.
- `UNKNOWN` is the correct outcome when required evidence is unavailable.
- Candidate repositories are untrusted and must not receive ambient credentials or arbitrary
  execution privileges.

## CI requirements

Run:

```bash
python -m pip install -e ".[dev]"
ruff check .
pytest
python scripts/check_schema_parity.py
python -m build
```

Do not weaken assertions, remove security tests, skip workflows, or reduce permissions merely to
obtain a green build.

## Documentation

Update the relevant ADR, schema, README, threat model, CLI documentation, and changelog whenever
the public architecture or security semantics change.

## Security research

Use FAS only against systems you are authorized to analyze. Demonstrations should use controlled
fixtures or authorized environments.


## Phase 6 product development

Install with `python -m pip install -e ".[dev]"`. The local product backend creates SQLite state
under `.fas/` by default. Use `fas doctor --format json` before integration work.

Run the local product smoke path:

```bash
fas analyze ./path-to-fixture --format json
fas status <analysis-id> --format json
fas report <analysis-id> --format json
fas tools --format json
fas doctor --format json
```

The HTTP API is started with `fas api` and binds to localhost by default. Production exposure must
set `FAS_AUTH_REQUIRED=true` and provide `FAS_API_TOKEN`; do not expose the development mode on
a public interface.

Product changes must preserve explicit unsupported-capability errors rather than introducing fake
endpoints. New domain objects require schema, persistence, API/CLI, tests, and documentation
reconciliation as applicable.
