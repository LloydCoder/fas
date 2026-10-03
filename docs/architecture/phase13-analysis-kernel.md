# Phase 13 — Analysis Query Kernel

Phase 13 adds a deterministic, read-only query facade over the existing evidence graph.

## Contract

The kernel:
- delegates graph matching and traversal to GraphEngine;
- sorts output by canonical identifiers;
- applies explicit bounded result limits;
- reports COMPLETE, EMPTY, or TRUNCATED rather than silently dropping data;
- derives evidence identifiers only from existing graph nodes, edges, and paths.

It does not create evidence, findings, attack paths, verdicts, or authority; execute tools; mutate the graph; or replace Agent Platform orchestration.

## Security invariants

1. Limits are positive and bounded by configured defaults.
2. Truncation is explicit and never represented as complete.
3. Reachability is constrained by caller-supplied relationship types and GraphEngine limits.
4. Evidence correlation is deterministic set union.
5. The kernel exposes no mutating graph operation.

AdvancedAnalysisEngine remains the domain-specific security analysis layer. The kernel is a reusable primitive for later supply-chain, identity, API, cloud, and agent/MCP analyzers.
