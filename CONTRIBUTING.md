# Contributing to FAS

Thank you for contributing to FAS.

FAS is security-analysis software. Contributions should prioritize correctness, reproducibility, provenance, and safe execution.

## Before contributing

1. Read the README and relevant architecture documentation.
2. Check existing issues before starting substantial work.
3. Keep changes scoped to one architectural concern where practical.
4. Do not commit secrets, customer data, private repositories, credentials, or production artifacts.
5. Add or update tests for security-sensitive behavior.

## Engineering principles

- Evidence must have provenance.
- Do not manufacture security evidence.
- Keep deterministic collection separate from model inference.
- Preserve immutable analysis state.
- Prefer explicit domain contracts over implicit dictionaries.
- Treat analyzed repositories and tool output as untrusted input.
- Prefer small, reviewable changes.
- Avoid introducing dependencies without a clear architectural reason.
- Keep documented public interfaces stable.

## Pull requests

A pull request should explain:

- what changed
- why it changed
- security implications
- tests performed
- schema/API compatibility impact
- new dependencies or execution capabilities

Security-sensitive changes should include focused regression tests.

## Security research

Do not use FAS to test systems without authorization. Demonstrations should use controlled fixtures or authorized environments.

See [SECURITY.md](SECURITY.md) for vulnerability reporting.
