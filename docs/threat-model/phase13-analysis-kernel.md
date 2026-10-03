# Phase 13 Threat Model — Analysis Query Kernel

| Threat | Control |
|---|---|
| Truncation mistaken for completeness | Explicit TRUNCATED status and complete == False |
| Unbounded traversal | GraphEngine traversal limits plus pair/result caps |
| Cross-domain authority | Read-only facade with no verdict/finding mutation |
| Evidence manufacture | Evidence IDs derive only from existing graph objects |
| Non-deterministic output | Canonical identifier sorting |
| Query mutation | No mutating operations exposed |

Residual risk: the kernel cannot establish correctness of upstream graph contents; collectors, adapters, graph construction, and evidence validation remain responsible for provenance and correctness.
