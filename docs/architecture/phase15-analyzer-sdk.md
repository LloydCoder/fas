# Phase 15 — Analyzer SDK

FAS now exposes a minimal extension contract for deterministic security analyzers.

The SDK only defines analyzer identity, collection context input, observation output,
completion state, and a registry. It does not grant tool execution authority, mutate evidence,
create findings or verdicts, or bypass Agent Platform governance.

Extensions remain responsible for producing properly attributed observations. FAS core remains
responsible for normalization, evidence formation, graph semantics, analysis, and verdict rules.
