"""Deterministic graph construction and entity identity helpers."""

from __future__ import annotations

import hashlib

from fas.domain.common import (
    AnalysisId,
    Confidence,
    GraphNodeType,
    NodeId,
    Provenance,
    RelationshipType,
    SnapshotId,
    utc_now,
)
from fas.domain.graph import GraphEdge, GraphNode
from fas.domain.evidence import Evidence
from fas.domain.analysis import Artifact, Observation

from .engine import GraphEngine
from .errors import GraphInvariantViolation


_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def stable_id(prefix: str, canonical_identity: str) -> str:
    digest = hashlib.sha256(canonical_identity.encode("utf-8")).digest()[:16]
    value = int.from_bytes(digest, "big")
    chars = []
    for _ in range(26):
        chars.append(_CROCKFORD[value & 31])
        value >>= 5
    return f"{prefix}_{''.join(reversed(chars))}"


class NodeIdentityResolver:
    """Exact identity normalization; intentionally contains no fuzzy matching."""

    @staticmethod
    def canonical(kind: GraphNodeType, identity: str) -> str:
        value = " ".join(identity.strip().split())
        if not value:
            raise ValueError("canonical identity cannot be empty")
        return f"{kind.value.lower()}:{value}"

    @classmethod
    def node_id(cls, kind: GraphNodeType, identity: str) -> NodeId:
        return stable_id("node", cls.canonical(kind, identity))  # type: ignore[return-value]


class GraphBuilder:
    """Deterministic boundary from Phase 1 records into the graph engine."""

    def __init__(self, engine: GraphEngine) -> None:
        self.engine = engine

    def add_artifact(self, artifact: Artifact) -> None:
        self.engine.add_artifact(artifact)

    def add_observation(self, observation: Observation) -> None:
        self.engine.add_observation(observation)

    def add_evidence(self, evidence: Evidence) -> None:
        self.engine.add_evidence(evidence)

    def add_node(self, node: GraphNode) -> GraphNode:
        return self.engine.upsert_node(node)

    def add_edge(self, edge: GraphEdge) -> GraphEdge:
        return self.engine.merge_edge_evidence(edge)

    def build(self, *, complete: bool = False):
        validation = self.engine.validate()
        if not validation.valid:
            raise GraphInvariantViolation(
                "; ".join(issue.message for issue in validation.issues)
            )
        return self.engine.seal(complete=complete)

    @staticmethod
    def make_node(
        *,
        analysis_id: AnalysisId,
        snapshot_id: SnapshotId,
        node_type: GraphNodeType,
        canonical_identity: str,
        label: str,
        provenance: tuple[Provenance, ...],
        evidence_ids: tuple[str, ...] = (),
        security_relevant: bool = False,
        metadata: dict[str, str] | None = None,
    ) -> GraphNode:
        canonical = NodeIdentityResolver.canonical(node_type, canonical_identity)
        return GraphNode(
            id=NodeIdentityResolver.node_id(node_type, canonical_identity),
            type=node_type,
            label=label,
            analysis_id=analysis_id,
            snapshot_id=snapshot_id,
            canonical_identity=canonical,
            evidence_ids=evidence_ids,
            provenance=provenance,
            security_relevant=security_relevant,
            metadata=metadata or {},
        )

    @staticmethod
    def make_edge(
        *,
        analysis_id: AnalysisId,
        snapshot_id: SnapshotId,
        source_node_id: NodeId,
        target_node_id: NodeId,
        relationship_type: RelationshipType,
        provenance: tuple[Provenance, ...],
        evidence_ids: tuple[str, ...] = (),
        confidence: Confidence | None = None,
        security_relevant: bool = False,
        metadata: dict[str, str] | None = None,
    ) -> GraphEdge:
        semantic = "|".join((
            analysis_id,
            snapshot_id,
            source_node_id,
            target_node_id,
            relationship_type.value,
        ))
        return GraphEdge(
            id=stable_id("edge", semantic),  # type: ignore[arg-type]
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            relationship_type=relationship_type,
            analysis_id=analysis_id,
            snapshot_id=snapshot_id,
            provenance=provenance,
            evidence_ids=evidence_ids,
            confidence=confidence,
            observed_at=utc_now(),
            security_relevant=security_relevant,
            metadata=metadata or {},
        )
