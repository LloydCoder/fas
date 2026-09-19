# ADR 0004 — Constrained Investigation Boundary

## Decision

Phase 4 uses deterministic, read-only investigation primitives behind a strict tool policy and a
model-agnostic provider interface. The investigator model can propose hypotheses, evidence
requests, attack paths, and verdicts, but trusted FAS code validates all structured output.

## Rationale

Security conclusions must remain reproducible without a paid model and must not depend on model
authorization decisions. Immutable snapshot scope and evidence provenance remain enforced by the
domain and graph layers.

## Consequences

The first implementation is a modular monolith with an in-memory graph and append-only local
persistence seam. PostgreSQL integration can implement the same repository contract without
changing the investigation domain.
