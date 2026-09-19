"""Phase 2 graph query, path, validation, and diff contracts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import FrozenSet

from fas.domain.common import (
    AnalysisId,
    EvidenceId,
    GraphNodeType,
    NodeId,
    RelationshipType,
    SnapshotId,
)
from fas.domain.evidence import Evidence
from fas.domain.graph import GraphEdge, GraphNode


class TraversalDirection(StrEnum):
    OUTBOUND = "OUTBOUND"
    INBOUND = "INBOUND"
    BOTH = "BOTH"


class ResultStatus(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    TRUNCATED = "TRUNCATED"
    INVALID = "INVALID"
    EMPTY = "EMPTY"


class GraphScopeKind(StrEnum):
    ANALYSIS = "ANALYSIS"
    SNAPSHOT = "SNAPSHOT"


@dataclass(frozen=True, slots=True)
class GraphScope:
    kind: GraphScopeKind
    analysis_id: AnalysisId
    snapshot_id: SnapshotId | None = None

    def accepts(self, analysis_id: AnalysisId, snapshot_id: SnapshotId) -> bool:
        if analysis_id != self.analysis_id:
            return False
        return self.snapshot_id is None or snapshot_id == self.snapshot_id


@dataclass(frozen=True, slots=True)
class GraphLimits:
    max_traversal_depth: int = 12
    max_nodes_visited: int = 10_000
    max_edges_visited: int = 25_000
    max_paths: int = 100
    max_path_depth: int = 12
    max_result_size: int = 10_000

    def __post_init__(self) -> None:
        if any(value < 0 for value in (
            self.max_traversal_depth,
            self.max_nodes_visited,
            self.max_edges_visited,
            self.max_paths,
            self.max_path_depth,
            self.max_result_size,
        )):
            raise ValueError("graph limits must be non-negative")


@dataclass(frozen=True, slots=True)
class GraphQuery:
    node_types: FrozenSet[GraphNodeType] | None = None
    relationship_types: FrozenSet[RelationshipType] | None = None
    evidence_ids: FrozenSet[EvidenceId] | None = None
    provenance_categories: FrozenSet[str] | None = None
    min_confidence: float | None = None
    max_confidence: float | None = None

    def __post_init__(self) -> None:
        if self.min_confidence is not None and not 0 <= self.min_confidence <= 1:
            raise ValueError("min_confidence must be between 0 and 1")
        if self.max_confidence is not None and not 0 <= self.max_confidence <= 1:
            raise ValueError("max_confidence must be between 0 and 1")
        if (
            self.min_confidence is not None
            and self.max_confidence is not None
            and self.min_confidence > self.max_confidence
        ):
            raise ValueError("min_confidence cannot exceed max_confidence")


class GraphQueryResult:
    """Typed result wrapper used by query APIs."""

    def __init__(
        self,
        *,
        nodes: tuple[GraphNode, ...] = (),
        edges: tuple[GraphEdge, ...] = (),
        status: ResultStatus = ResultStatus.COMPLETE,
        reason: str | None = None,
    ) -> None:
        self.nodes = nodes
        self.edges = edges
        self.status = status
        self.reason = reason

    @property
    def complete(self) -> bool:
        return self.status == ResultStatus.COMPLETE


class TraversalResult:
    def __init__(
        self,
        *,
        node_ids: tuple[NodeId, ...] = (),
        edge_ids: tuple[str, ...] = (),
        depths: tuple[tuple[NodeId, int], ...] = (),
        status: ResultStatus = ResultStatus.COMPLETE,
        reason: str | None = None,
    ) -> None:
        self.node_ids = node_ids
        self.edge_ids = edge_ids
        self.depths = depths
        self.status = status
        self.reason = reason

    @property
    def complete(self) -> bool:
        return self.status == ResultStatus.COMPLETE


class GraphPath:
    """Evidence-backed structural path."""

    def __init__(
        self,
        *,
        path_id: str,
        nodes: tuple[GraphNode, ...],
        edges: tuple[GraphEdge, ...],
        analysis_id: AnalysisId,
        snapshot_id: SnapshotId,
        status: ResultStatus = ResultStatus.COMPLETE,
        trust_boundary_node_ids: tuple[NodeId, ...] = (),
        evidence_ids: tuple[EvidenceId, ...] = (),
    ) -> None:
        self.path_id = path_id
        self.nodes = nodes
        self.edges = edges
        self.analysis_id = analysis_id
        self.snapshot_id = snapshot_id
        self.status = status
        self.trust_boundary_node_ids = trust_boundary_node_ids
        self.evidence_ids = evidence_ids
        self.validate()

    @property
    def depth(self) -> int:
        return len(self.edges)

    @property
    def relationship_types(self) -> tuple[RelationshipType, ...]:
        return tuple(edge.relationship_type for edge in self.edges)

    def validate(self) -> None:
        if not self.nodes:
            if self.edges:
                raise ValueError("a path cannot contain edges without nodes")
            return
        if len(self.edges) != len(self.nodes) - 1:
            raise ValueError("path edge/node cardinality is invalid")
        if self.nodes[0].snapshot_id != self.snapshot_id:
            raise ValueError("path starts outside its snapshot")
        for index, edge in enumerate(self.edges):
            if edge.snapshot_id != self.snapshot_id:
                raise ValueError("path contains a cross-snapshot edge")
            if edge.source_node_id != self.nodes[index].id:
                raise ValueError("path edge source does not match node sequence")
            if edge.target_node_id != self.nodes[index + 1].id:
                raise ValueError("path edge target does not match node sequence")
        if self.nodes[-1].snapshot_id != self.snapshot_id:
            raise ValueError("path ends outside its snapshot")


class PathResult:
    def __init__(
        self,
        *,
        paths: tuple[GraphPath, ...] = (),
        status: ResultStatus = ResultStatus.EMPTY,
        reason: str | None = None,
    ) -> None:
        self.paths = paths
        self.status = status
        self.reason = reason

    @property
    def complete(self) -> bool:
        return self.status == ResultStatus.COMPLETE


class ValidationIssue:
    def __init__(self, code: str, message: str, subject_id: str | None = None) -> None:
        self.code = code
        self.message = message
        self.subject_id = subject_id


class ValidationResult:
    def __init__(self, issues: tuple[ValidationIssue, ...] = ()) -> None:
        self.issues = issues

    @property
    def valid(self) -> bool:
        return not self.issues


class GraphDiff:
    def __init__(
        self,
        *,
        added_nodes: tuple[GraphNode, ...] = (),
        removed_nodes: tuple[GraphNode, ...] = (),
        unchanged_nodes: tuple[GraphNode, ...] = (),
        changed_nodes: tuple[tuple[GraphNode, GraphNode], ...] = (),
        added_edges: tuple[GraphEdge, ...] = (),
        removed_edges: tuple[GraphEdge, ...] = (),
        unchanged_edges: tuple[GraphEdge, ...] = (),
        changed_edges: tuple[tuple[GraphEdge, GraphEdge], ...] = (),
    ) -> None:
        self.added_nodes = added_nodes
        self.removed_nodes = removed_nodes
        self.unchanged_nodes = unchanged_nodes
        self.changed_nodes = changed_nodes
        self.added_edges = added_edges
        self.removed_edges = removed_edges
        self.unchanged_edges = unchanged_edges
        self.changed_edges = changed_edges


class GraphExport:
    schema_version: str = "1.0"

    def __init__(
        self,
        *,
        analysis_id: AnalysisId,
        nodes: tuple[GraphNode, ...],
        edges: tuple[GraphEdge, ...],
        evidence: tuple[Evidence, ...],
        artifacts: tuple[object, ...] = (),
        observations: tuple[object, ...] = (),
        metadata: dict[str, str] | None = None,
    ) -> None:
        self.analysis_id = analysis_id
        self.nodes = nodes
        self.edges = edges
        self.evidence = evidence
        self.artifacts = artifacts
        self.observations = observations
        self.metadata = metadata or {}
