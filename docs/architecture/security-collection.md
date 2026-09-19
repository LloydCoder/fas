# Phase 3 — Security Collection Architecture

Phase 3 establishes the deterministic ingestion boundary between security collectors/tool outputs and the Phase 2 evidence graph.

## Pipeline

repository or tool output -> Collector/Adapter -> Observation -> ObservationNormalizer -> Evidence -> GraphBuilder -> sealed graph

Collectors and adapters do not create findings, attack paths, exploitability verdicts, or remediation conclusions.

## Collection scope

Every collection operation is scoped to an analysis and immutable snapshot. Repository discovery is read-only, does not execute repository code, does not follow symlinks, excludes common cache/vendor/build directories, and applies file-count and file-size limits.

Artifacts carry SHA-256 hashes calculated from bytes actually read. Observations carry the same analysis/snapshot scope and retain their raw output reference, source location, observed value, and provenance.

## Normalization

ObservationNormalizer converts one Observation into one Evidence record. The conversion preserves the claim, observed value, source location, observation identity, provenance, and artifact linkage. It does not raise confidence or provenance level.

Evidence identifiers are deterministic for observation content plus analysis/snapshot scope.

## Tool adapters

Initial adapters parse SARIF 2.1.x, Semgrep JSON, Trivy JSON, and Gitleaks JSON. They preserve scanner observations and do not translate scanner output into exploitability.

Gitleaks secret material is deliberately omitted from normalized observed values. Rule metadata, fingerprints, locations, and safe metadata remain available.

## Dependency discovery

Dependency discovery parses Python pyproject/requirements, npm manifests, and Go modules without executing package managers. Unsupported manifests are inventoried with parsed=false rather than treated as dependency absence.

## Completeness

CollectionBatch exposes complete, skipped, and warnings. A partial or bounded inventory must remain partial. The graph must only be sealed as complete when the required collection set is known to be complete.

## Security boundary

Tool output is parsed as untrusted data. No shell execution, dynamic import, expression evaluation, or repository-defined code is performed. Future external tool execution belongs behind a sandboxed worker boundary.
