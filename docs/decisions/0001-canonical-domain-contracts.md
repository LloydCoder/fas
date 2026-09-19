# ADR 0001 — Canonical Domain Contracts

- **Status:** Accepted
- **Date:** 2026-09-19

## Context

FAS needs a stable semantic foundation that can be consumed by collectors,
graph construction, investigation, verification, persistence, APIs, and future
agent tooling without allowing infrastructure concerns to redefine security
semantics.

The initial repository contained partial JSON schemas and package placeholders,
but no authoritative implementation layer.

## Decision

Pydantic v2 models under `src/fas/domain/` are the canonical implementation
contracts for Phase 1.

The models are immutable, reject unknown fields, use explicit enums and typed
identifiers, and expose deterministic JSON serialization.

Observations remain distinct from evidence, findings, and verdicts. Evidence
requires provenance. Security-relevant graph relationships require evidence
references. UNKNOWN is a first-class verdict and requires explicit missing
evidence.

Snapshot identity is part of the domain so historical evidence cannot be
silently mixed across repository states.

## Why Pydantic

Pydantic provides typed validation, JSON-compatible serialization, JSON Schema
generation, and a small dependency footprint without coupling the domain to
persistence or transport frameworks.

## Why evidence is append-oriented

Changing an existing evidence record would destroy the historical statement
of what was observed. Contradictory information is therefore represented by a
new record with its own provenance.

## Why LLM inference is separate

An LLM can generate a hypothesis or request additional evidence, but a model
output does not become a verified observation merely because it is plausible.
The provenance category and level preserve that distinction.

## Why graph algorithms are deferred

Phase 1 defines the semantic objects needed by the future evidence graph.
Storage, traversal, path discovery, and graph query optimization belong to
Phase 2 and would otherwise create premature infrastructure coupling.

## Consequences

The Phase 2 graph can consume stable nodes and edges. Collectors can normalize
tool output into observations without declaring exploitability. Verification
can produce evidence without directly forcing a verdict. Historical records
remain reconstructable from serialized contracts.

The checked-in JSON Schemas are interoperability artifacts and include an
explicit contract version. Future breaking semantic changes require a new
schema/contract version rather than silently changing historical meaning.
