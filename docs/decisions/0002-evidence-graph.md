# ADR 0002 — Evidence Graph Architecture

- Status: Accepted
- Date: 2026-09-19

## Context

FAS needs a deterministic relationship substrate for code, identities,
permissions, agents, tools, MCP components, runtime observations, findings and
security evidence. The graph must remain an evidence substrate rather than a
generic inference engine.

Phase 1 already defines GraphNode and GraphEdge domain contracts. Phase 2
must add storage and algorithms without duplicating those semantic contracts.

## Decision

FAS Phase 2 uses a directed, typed provenance-aware multigraph implemented
behind a GraphStore protocol and exercised by a backend-independent
GraphEngine.

The default implementation is InMemoryGraphStore. PostgreSQL is the intended
future durable system of record, but no PostgreSQL dependency is required for
Phase 2 algorithms.

NetworkX is not a dependency and is not the canonical FAS graph model.
Required algorithms are small enough to implement directly while preserving
FAS-specific scope, evidence and truncation semantics.

## Directed multigraph

Relationship type is part of the semantic edge identity. Therefore the same
source and target can have CALLS and FLOWS_TO relationships simultaneously.

Edges have one canonical direction. Reverse traversal is calculated at query
time and does not create synthetic reverse edges.

## Provenance and evidence

Security-relevant nodes and edges must reference evidence. Evidence and
provenance are accumulated during semantic merges. A graph relationship never
becomes authoritative merely because it exists in the adjacency structure.

Missing evidence is an invalid reference, not an inferred placeholder.

## Snapshot isolation

Nodes and edges carry analysis and snapshot scope. Ordinary traversal is
snapshot-isolated even when a graph is scoped to an entire analysis. Cross
snapshot state is compared with GraphDiff rather than merged into a
traversable graph.

This prevents false attack paths produced by combining historical states.

## Partial graphs and truncation

Graphs explicitly declare completeness. Query results explicitly report
TRUNCATED when a configured traversal or path limit is reached.

No-path in a partial graph is not proof of real-world non-reachability.

## Identity resolution

Canonical identity is explicit and exact. Stable identifiers are derived from
canonical identity material. No fuzzy or LLM-based entity resolution is used.

When deterministic identity cannot be established, entities remain distinct.

## Backend boundary

GraphStore isolates persistence. GraphEngine owns FAS graph semantics and
algorithms. A future PostgreSQL implementation must satisfy the same
observable semantics and must not become the source of security meaning.

## Why Phase 2 does not determine exploitability

A graph path establishes structural connectivity only. It does not establish
attacker influence, effective authorization, runtime configuration, controls,
impact or exploitability.

Those questions belong to later investigation and verdict phases.

## Consequences

The graph is reproducible, inspectable and suitable for future benchmark
execution. It can be built and queried without infrastructure services.

The in-memory implementation is not intended to be the final large-scale
persistence system. Future persistence work must preserve these semantics.
