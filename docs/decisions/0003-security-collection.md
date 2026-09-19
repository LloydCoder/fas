# ADR 0003 — Deterministic Security Collection Boundary

## Status

Accepted

## Decision

Phase 3 separates acquisition from reasoning:

1. collectors and adapters emit Observation;
2. ObservationNormalizer converts observations to Evidence;
3. GraphBuilder and GraphEngine persist evidence and graph relationships;
4. later phases correlate evidence, reconstruct attack paths, and produce formal verdicts.

All collection records are analysis/snapshot scoped. Tool output is untrusted input. Scanner output never becomes a FAS finding merely because an adapter parsed it.

## Consequences

Adapters remain replaceable, provenance remains inspectable, deterministic replay is possible from stored observations, and future subprocess execution can be sandboxed without changing the evidence contract.

No external scanner executable is required for Phase 3 tests.
