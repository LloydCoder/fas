# FAS Documentation

This directory contains the durable technical documentation for FAS.

## Documentation map

| Area | Purpose |
|---|---|
| [Architecture](architecture/README.md) | System lifecycle, boundaries, implementation phases, and architectural invariants |
| [Evidence Model](evidence-model/README.md) | Observation/evidence separation, provenance, snapshot integrity, and completeness semantics |
| [Threat Model](threat-model/README.md) | Trust boundaries, threats, security invariants, and runtime limits |
| [ADRs](decisions/README.md) | Recorded architecture and security decisions |
| [Security](security/phase6-verification-matrix.md) | Phase 6 security verification map and standards-reference boundaries |

## Documentation ownership model

The repository uses a simple rule:

> **Implementation, contracts, tests, and documentation must describe the same system.**

When a public behavior or security invariant changes, update the relevant documentation in the same change.

### Where information belongs

- **README.md** — project orientation, quick start, capability boundaries, contributor entry points.
- **CONTRIBUTING.md** — development workflow and contribution expectations.
- **SECURITY.md** — vulnerability reporting and security policy.
- **Architecture docs** — system structure and boundaries.
- **ADRs** — why an architectural decision was made.
- **Threat model** — what can go wrong and which controls matter.
- **Schemas** — machine-readable contracts.
- **CHANGELOG.md** — user-visible historical changes.

Avoid duplicating deep design explanations across multiple documents. Link to one canonical source instead.

## Documentation quality bar

Documentation changes should be:

- technically accurate against the current implementation
- explicit about supported and unsupported capabilities
- reproducible where commands are shown
- clear about security boundaries
- free of unsupported compliance or production-readiness claims
- linked using repository-relative paths where possible

The root [README](../README.md) is the starting point for new users and contributors.