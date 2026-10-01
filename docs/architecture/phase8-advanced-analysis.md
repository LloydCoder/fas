# FAS Phase 8 — Advanced Security Analysis

Phase 8 expands deterministic graph reasoning without changing the evidence boundary.

## Analysis families

- data-flow and reachability signals
- privilege reachability
- agent-to-tool and MCP reachability
- sensitive-resource reachability
- bounded attack-surface inventory

Every signal is scoped to the graph snapshot, carries the evidence IDs available on its path, and preserves PARTIAL/TRUNCATED status. The analyzer cannot create findings or verdicts.

## Safety rules

1. Analysis operates only on the supplied graph scope.
2. Traversal is bounded by explicit pair limits and graph limits.
3. Missing or incomplete graph state remains incomplete.
4. LLM output is not consulted to establish an analysis signal.
5. A signal is not a vulnerability finding until a higher-level investigation establishes the required security property.

Future Phase 8 increments can add language-aware data-flow, cloud/IAM, IaC, dependency reachability, and richer agent/MCP semantics behind the same deterministic contracts.
