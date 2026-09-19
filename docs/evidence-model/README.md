# FAS Evidence Model

Phase 1 establishes the canonical evidence contract used by every later FAS
component.

## Semantic chain

```
Analysis
  ↓
immutable Snapshot
  ↓
Artifact
  ↓
Observation
  ↓
Evidence
  ↓
GraphNode / GraphEdge
  ↓
Finding
  ↓
AttackPath
  ↓
Verdict
  ↓
Remediation
  ↓
Verification
```

The reverse direction is used for audit: a verdict must be traceable back to
the evidence and immutable snapshot from which it was established.

## Observation vs Evidence vs Finding vs Verdict

- **Observation** is something a collector, scanner, runtime, or other source
  observed. It is not a vulnerability conclusion.
- **Evidence** is a structured piece of information used to support or
  contradict a security claim, with provenance and optional integrity metadata.
- **Finding** is a correlated security condition assembled from observations
  and evidence.
- **Verdict** is a formal conclusion governed by deterministic domain
  invariants.

A scanner observation therefore cannot silently become an exploitable finding.

## Provenance

Provenance is first-class and records category, strength level, collector,
method, source, timestamp, actor, parent evidence, and optional integrity.

T0–T5 describe how information was established. They are not a truth score.
In particular, LLM inference remains distinct from tool observations and
verification evidence.

## Append-oriented evidence

Evidence models are frozen and contain no update operation. New or
contradictory information is represented by additional evidence records.
Later phases may persist these immutable records, but persistence is outside
the Phase 1 domain boundary.

## Snapshot boundary

Artifacts reference exactly one snapshot. Findings reference the snapshot
against which they were correlated. Later phases must not mix evidence from
different snapshots without explicitly representing the comparison.

## UNKNOWN

`UNKNOWN` is a valid verdict when required evidence is missing. Missing
evidence is represented explicitly and must not be converted into
`NOT_EXPLOITABLE`.

## Canonical implementation

Pydantic v2 models under `src/fas/domain/` are the implementation contracts.
JSON Schema documents under `schemas/` are interoperability artifacts and
carry an explicit schema version.
