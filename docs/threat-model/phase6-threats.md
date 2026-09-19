# Phase 6 Threat Model

| Threat | Control |
|---|---|
| Malicious repository | hostile-input parsing, path/symlink checks, bounded collection |
| Tool/SARIF poisoning | deterministic parsing and evidence provenance |
| Prompt injection | repository content remains data, not investigator instructions |
| Evidence mutation | immutable domain records, content hashes, snapshot binding, audit-chain verification |
| Cross-snapshot contamination | snapshot-bound graph and verification checks |
| Command injection | structured argv; no shell construction in product execution boundary |
| Secret leakage | redaction, explicit environment allowlists, secret-safe diagnostics |
| API abuse | bounded request body, authentication boundary for non-local binding |
| Authorization bypass | bearer-token gate in externally bound local product mode |
| Resource exhaustion | bounded artifact size, graph budgets, worker concurrency, request limits and subprocess limits |
| Job duplication | operation-key idempotency |
| Worker crash | durable job state and startup recovery |
| CI compromise | read-only workflow permissions and full-SHA action pinning |
| Artifact tampering | SHA-256 content addressing, pre-commit hash verification, read-time hash verification |
| Unsafe remediation | Phase 5 verification requires explicit before/after snapshots and proof checks |

Residual risk remains for future runtime sandbox backends and horizontally scaled persistence; those capabilities are not claimed by the current local product profile.


## Residual risks

The local executor is a controlled subprocess boundary, not a general-purpose OS sandbox. Arbitrary candidate-code runtime execution remains unsupported until a platform-specific sandbox backend provides filesystem, network, credential, process, memory, CPU, timeout and privilege isolation. Horizontal/distributed persistence is likewise outside the current Phase 6 product profile.
