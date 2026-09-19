# FAS Evidence Graph

Phase 2 implements the deterministic relationship substrate between Phase 1
evidence and later security analysis.

## Architecture

Phase 1 domain contracts
  |
  v
GraphBuilder
  |
  v
InMemoryGraphStore  <---- GraphStore protocol
  |
  v
GraphEngine
  |
  v
GraphView

The graph is a directed, typed multigraph. Two nodes may have multiple
relationships because relationship type is part of the semantic edge key.

The graph engine is backend-independent. PostgreSQL is the intended future
system of record, but Phase 2 keeps algorithms independent from any database
or graph-specific service.

## Scope and snapshot isolation

Every GraphNode and GraphEdge carries both analysis_id and snapshot_id.
A graph engine can be scoped to an entire analysis or to one snapshot.

An analysis-scoped engine may contain multiple snapshots, but ordinary
traversal always follows the snapshot of its starting node. Edges whose
endpoints belong to different snapshots are rejected.

Cross-snapshot comparison is implemented by GraphEngine.diff; it does not
construct a traversable union graph.

## Node identity

GraphNode.canonical_identity is the explainable identity key. The
NodeIdentityResolver normalizes exact identity strings and derives a stable
node identifier from SHA-256 material encoded in the FAS identifier alphabet.

No fuzzy or LLM-based entity resolution is performed.

A canonical identity should omit snapshot information when the entity is
intended to remain the same logical entity across snapshots (for example a
repository-relative file), and include snapshot-specific identity when that
distinction is semantically required.

## Edge identity and direction

The semantic edge key is:

analysis + snapshot + source + target + relationship_type

The edge identifier is stable for that semantic relationship.

Direction is canonical and never materialized as an automatic reverse edge.
incoming_edges, outgoing_edges, predecessors, and successors expose both
directions as query operations.

Duplicate semantic relationships are merged through
merge_edge_evidence(). Evidence and provenance are accumulated rather than
replaced.

Contradictory relationships use different relationship semantics or evidence
records; the graph does not resolve the security meaning of the contradiction.

## Provenance and evidence

Security-relevant nodes and edges require evidence references. The in-memory
store resolves those references before accepting the relationship.

The graph can answer:

- which evidence supports an edge;
- which provenance records produced an edge;
- which evidence supports a node;
- which artifacts and observations are linked by those evidence records.

A missing evidence reference is an insertion/validation error, not an invented
placeholder.

## Construction and sealing

GraphBuilder is the intended boundary for Phase 3 collectors. Collectors
will eventually normalize observations into Phase 1 evidence and then add
canonical graph objects.

Build-time operations are mutable. seal() validates the graph and returns a
GraphView. The view exposes queries but no mutation methods.

Malformed edges are rejected rather than silently quarantined.

## Traversal and path semantics

Traversal supports:

- outbound, inbound, and bidirectional direction;
- maximum depth;
- maximum visited nodes;
- maximum visited edges;
- relationship and node-type filters.

Shortest paths minimize edge count. Tie-breaking uses deterministic edge and
node ordering.

Bounded path enumeration always has a maximum depth and path count. When a
limit is reached the result status is TRUNCATED; incomplete enumeration is
never presented as exhaustive.

GraphPath contains nodes, edges, snapshot scope, relationship sequence,
supporting evidence identifiers, and trust-boundary nodes.

A path is structural graph information. It does not establish attacker
capability or exploitability.

## Partial graphs

A graph has an explicit complete flag. The default is False.

A structural query returning no path from a partial graph is only a statement
about represented relationships. It is not proof that the real system has no
path.

A complete graph is still not a security verdict; completeness does not add
attacker semantics that are not represented by the graph.

## Trust boundaries

Trust boundaries are ordinary TRUST_BOUNDARY nodes. boundary_crossings()
returns the boundary nodes occurring on a validated path.

Phase 2 does not classify a crossing as dangerous.

## Diff semantics

GraphEngine.diff(left, right) compares compatible analysis graphs and uses
canonical node identity and relationship semantics to identify:

- added, removed, unchanged and changed nodes;
- added, removed, unchanged and changed edges.

Diff is a comparison operation, not a merge operation. It does not conclude
that remediation succeeded.

## Validation

Validation checks endpoint existence, snapshot scope, evidence resolution,
and evidence scope. The store also indexes adjacency and semantic identity so
ordinary lookup and adjacency queries do not require full graph scans.

## Security boundaries

The graph APIs deliberately avoid LLMs, scanner adapters, databases, message
queues and microservices. Metadata is treated as untrusted input and core
domain objects retain Pydantic extra-forbid behavior.

Secret and credential nodes should contain identifiers, references, hashes or
other non-secret metadata. Phase 2 never requires plaintext secret material.

## Future PostgreSQL implementation

GraphStore is the persistence seam. A future PostgreSQL implementation must
preserve the same scope, evidence, provenance, deterministic ordering and
validation semantics. The graph algorithms must not need to know whether
records came from memory or PostgreSQL.

## Phase boundary

Phase 2 intentionally does not implement:

- Semgrep, Trivy, Gitleaks, OSV or other scanner adapters;
- runtime collectors;
- LLM investigation;
- exploitability reasoning;
- verdict generation;
- remediation decisions;
- a PostgreSQL persistence implementation;
- a graph microservice.

Those concerns consume this substrate in later phases.
