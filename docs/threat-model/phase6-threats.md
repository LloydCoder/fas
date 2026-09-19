# Phase 6 Threat Model

| Threat | Control |
|---|---|
| Malicious repository | hostile-input parsing, path/symlink checks, bounded collection |
| Tool/SARIF poisoning | deterministic parsing and evidence provenance |
| Prompt injection | repository content remains data, not investigator instructions |
| Evidence mutation | frozen/append-oriented domain records |
| Cross-snapshot contamination | snapshot-bound graph and verification checks |
| Command injection | structured argv; no shell construction in product execution boundary |
| Secret leakage | redaction, explicit environment allowlists, secret-safe diagnostics |
| API abuse | bounded request body, authentication boundary for non-local binding |
| Authorization bypass | bearer-token gate in externally bound local product mode |
| Resource exhaustion | bounded artifact size, graph budgets, worker concurrency and subprocess limits |
| Job duplication | operation-key idempotency |
| Worker crash | durable job state and startup recovery |
| CI compromise | read-only workflow permissions and full-SHA action pinning |
| Artifact tampering | SHA-256 content addressing |
| Unsafe remediation | Phase 5 verification requires explicit before/after snapshots and proof checks |

Residual risk remains for future runtime sandbox backends and horizontally scaled persistence; those capabilities are not claimed by the current local product profile.
