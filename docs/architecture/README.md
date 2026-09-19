# FAS Architecture

FAS is initially designed as a modular monolith with isolated execution workers.

## Logical flow

```
API / CLI
  -> Analysis Orchestrator
  -> Discovery and Collectors
  -> Evidence Normalization
  -> Evidence Graph
  -> Security Analysis
  -> Exploitability Analysis
  -> Verdict
  -> Remediation Verification
```

## Architectural rule

Every material security conclusion must be traceable to evidence and to the immutable snapshot in which that evidence was observed.

Detailed architecture decision records belong in [../decisions/](../decisions/).


## Phase 2 Evidence Graph

See [evidence-graph.md](evidence-graph.md) for the graph store, deterministic traversal, snapshot isolation, provenance, graph sealing, partial-graph semantics, and graph diff architecture.

- [Security Collection](security-collection.md) — Phase 3 repository discovery, dependency discovery, tool adapters, normalization, and collection completeness.
