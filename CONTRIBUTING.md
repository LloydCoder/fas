# Contributing to FAS

Thank you for contributing to FAS. Correctness, reproducibility, provenance, safe execution, and explicit uncertainty take priority over feature volume.

## Before you start

1. Read [README.md](README.md).
2. Read the relevant [architecture documentation](docs/architecture/README.md).
3. Check [ADRs](docs/decisions/README.md) before changing security semantics.
4. For vulnerabilities, follow [SECURITY.md](SECURITY.md), not the public issue tracker.
5. For normal bugs and feature proposals, use the GitHub issue forms.

## Development workflow

Fork the repository, create a focused branch, make the smallest coherent change, validate locally, then open a pull request.

    git clone https://github.com/LloydCoder/fas.git
    cd fas
    python -m pip install -e ".[dev]"
    git checkout -b feat/short-description

## Validation baseline

    ruff check .
    pytest --cov=fas --cov-report=term-missing
    pytest tests/security
    python -m pip check
    python scripts/check_schema_parity.py
    python -m build

CI additionally tests supported Python versions, clean installation, API/CLI smoke paths, reproducibility, product integration, dependency security, CodeQL and secret scanning.

> [!WARNING]
> Do not weaken assertions, remove security tests, bypass CI, or reduce permissions merely to obtain a green build.

## Security and evidence rules

- Observation, evidence, finding, investigation, verdict, remediation, and verification are distinct.
- Security-relevant relationships must remain provenance/evidence backed.
- Original snapshot and evidence history are immutable.
- Missing evidence remains explicit; absence is not negative evidence.
- LLM output is advisory and never the source of truth.
- Candidate repositories are untrusted and must not receive ambient credentials or arbitrary execution privileges.
- Remediation verification must compare explicit before/after snapshots.
- UNKNOWN is correct when required evidence is unavailable.

## Change requirements

| Change | Expected updates |
|---|---|
| Public CLI/API behavior | Tests + reference docs + changelog |
| Security semantics | Regression tests + threat model/ADR + docs |
| Schema/contract | Schema + parity tests + consumers + docs |
| New collector/adapter | Deterministic tests + provenance coverage + docs |
| Persistence change | Storage tests + compatibility notes |
| User-visible behavior | Changelog and relevant docs |
| Architecture/security boundary | ADR and threat-model review |

## Pull requests

Explain what changed, why, validation performed, security/evidence impact, contract impact, and documentation impact. CODEOWNERS identifies security-sensitive areas requiring maintainer review.

## Commits

Use clear, imperative commit subjects. Conventional prefixes such as feat:, fix:, docs:, test:, refactor:, ci:, and security: are recommended when accurate.

## Security research

Use FAS only against systems you are authorized to analyze. Prefer controlled fixtures. Never commit real credentials, customer data, private source code, or sensitive vulnerability evidence.

## Documentation

Documentation is part of the implementation contract. Update the canonical source when behavior or security semantics change rather than duplicating deep explanations.

## License

Contributions are provided under the repository's [Apache License 2.0](LICENSE).
