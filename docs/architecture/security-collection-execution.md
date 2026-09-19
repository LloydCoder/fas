# Phase 3 Collection and Execution Security

Phase 3 treats the repository and all tool output as hostile input. Collection is bounded, deterministic, provenance-preserving, and incapable of creating findings or verdicts.

## Lifecycle

CollectionPlan -> bounded collectors -> CollectorOutcome -> CollectionSummary -> ObservationNormalizer -> Evidence Graph.

Every external tool invocation crosses SecureExecutor. Arguments are argv-only; shell interpolation is forbidden; executables are allowlisted; environment is minimized; stdin is closed; cwd is explicit; execution has time and output bounds; process groups are terminated on timeout/cancellation.

Raw tool output is an artifact and is never interpreted as a verdict. ToolRun records command identity, revision, environment fingerprint, hashes, status and raw-artifact linkage for replay.

## Failure semantics

SUCCESS means the collector completed without skipped work. PARTIAL means useful output exists but collection was incomplete. TIMEOUT, CANCELLED, TOOL_ERROR and RESOURCE_LIMIT are explicit failures. Missing evidence is never converted to negative evidence.

## Parser hardening

JSON ingestion enforces byte, nesting and item limits. Malformed data is an explicit parse failure. Secrets are excluded from normalized observations and logs.

## Offline mode

Collectors that inspect repository files are deterministic and offline. External tools are opt-in and execute only through SecureExecutor.
