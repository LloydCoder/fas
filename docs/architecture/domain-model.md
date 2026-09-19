# FAS Phase 1 Domain Model

## Boundary

The domain layer is pure semantic infrastructure. It has no dependency on
FastAPI, an ORM, a database, Redis, Kafka, scanner SDKs, cloud SDKs, or an LLM
framework.

Adapters, persistence, APIs, and execution workers translate into these
contracts later.

## Canonical objects

| Object | Meaning |
|---|---|
| Analysis | One analysis execution and its lifecycle |
| Snapshot | Immutable analyzable state |
| Artifact | Content or external analysis artifact associated with a snapshot |
| Observation | Raw/normalized observation from a source |
| Evidence | Structured claim-supporting information with provenance |
| GraphNode | Evidence-backed entity in the future graph |
| GraphEdge | Provenance-bearing relationship between graph nodes |
| Finding | Correlated security condition |
| AttackPath | Structured node/edge chain from entry toward impact |
| Verdict | Formal conclusion with evidence requirements |
| Remediation | Proposed/applied change against a finding |
| Verification | Verification activity and before/after evidence |

## Identity

Domain identities use prefixed, sortable ULID-style identifiers such as
`evidence_01...`. IDs are immutable and validated against their canonical
prefix.

## Integrity

`ContentHash` currently supports SHA-256 using the explicit
`sha256:<64-hex>` representation. The domain does not implement storage.

## Provenance

Every evidence-bearing object requires provenance. Security-relevant graph
nodes and edges require evidence references in addition to provenance.

Provenance strength T0–T5 describes establishment method, not truth.

## Immutability

Canonical models are frozen Pydantic models. Evidence is append-oriented:
contradictory evidence is another record, never a mutation of the original
observation.

## Verdict semantics

The verdict taxonomy is deliberately small:

- EXPLOITABLE
- NOT_EXPLOITABLE
- CONDITIONALLY_EXPLOITABLE
- REMEDIATED
- REMEDIATION_FAILED
- REGRESSED
- UNKNOWN

Ambiguous labels such as "probably exploitable" are intentionally absent.
Uncertainty belongs in confidence, conditions, and missing evidence.

Deterministic invariants include:

- EXPLOITABLE requires supporting evidence and an attack path and cannot have
  unresolved mandatory missing evidence.
- NOT_EXPLOITABLE requires evidence for the blocking condition.
- CONDITIONALLY_EXPLOITABLE requires explicit conditions and evidence.
- UNKNOWN requires explicit missing evidence.
- REMEDIATED requires verification evidence.
- REMEDIATION_FAILED requires residual/alternate evidence.
- REGRESSED requires a prior verdict and regression evidence.

## Phase boundary

Phase 1 defines the graph node/edge contracts but not graph storage, traversal,
path discovery, subgraph queries, or attack-path discovery. Those are Phase 2.

Similarly, Phase 1 defines remediation and verification records but does not
implement remediation execution, scanner adapters, runtime collectors, an LLM
investigator, or a verdict engine.
