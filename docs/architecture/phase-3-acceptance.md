# Phase 3 Acceptance Contract

Phase 3 is complete only when all of the following are true:

- Phase 1 and Phase 2 invariants remain green.
- CollectionPlan, CollectionResult and CollectionSummary are explicit.
- Repository, code, dependency, agent/MCP, configuration and CI/CD collectors are deterministic and scoped.
- SARIF, Semgrep, Trivy and Gitleaks output is normalized without producing findings or verdicts.
- Raw tool output and ToolRun metadata are retained with integrity hashes.
- External execution is argv-only, allowlisted, environment-minimized, time/output bounded and process-group terminated on timeout.
- Parser input is bounded for bytes, depth and item count.
- Path traversal, symlink escape and resource limits are tested.
- Failure states and retry policy are explicit.
- Replay manifests are deterministic and snapshot-scoped.
- Security/fuzz/property tests and collection benchmarks are present.
- CI compiles, lints, tests and runs the Phase 2/3 benchmarks on supported Python versions.

No Phase 4 investigation semantics, exploitability verdicts, attack-path conclusions, or remediation verification are introduced here.
