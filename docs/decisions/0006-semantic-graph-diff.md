# ADR 0006 — Semantic Graph Diff

## Status

Accepted.

Graph diffs use canonical node identities and semantic edge endpoints rather than serialized
IDs. The diff also classifies security-relevant changes such as permission widening/narrowing,
identity, trust-boundary, data-flow, control, agent/tool, MCP, credential, and dependency changes.

This prevents an implementation that merely renames nodes from being mistaken for a security
change.
