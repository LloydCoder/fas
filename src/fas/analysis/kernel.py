"""Deterministic evidence-backed analysis query kernel."""
from __future__ import annotations
from dataclasses import dataclass
from fas.domain.common import EvidenceId, GraphNodeType, ProvenanceCategory, RelationshipType
from fas.domain.graph import GraphEdge, GraphNode
from fas.graph import GraphEngine, GraphPath, GraphQuery, ResultStatus

@dataclass(frozen=True, slots=True)
class QueryLimits:
    max_nodes: int = 10_000
    max_edges: int = 25_000
    max_paths: int = 100
    def __post_init__(self) -> None:
        if any(v < 1 for v in (self.max_nodes, self.max_edges, self.max_paths)):
            raise ValueError("query limits must be positive")

@dataclass(frozen=True, slots=True)
class NodeSelection:
    nodes: tuple[GraphNode, ...]
    status: ResultStatus
    reason: str | None = None
    @property
    def complete(self) -> bool:
        return self.status == ResultStatus.COMPLETE

@dataclass(frozen=True, slots=True)
class EdgeSelection:
    edges: tuple[GraphEdge, ...]
    status: ResultStatus
    reason: str | None = None
    @property
    def complete(self) -> bool:
        return self.status == ResultStatus.COMPLETE

@dataclass(frozen=True, slots=True)
class PathSelection:
    paths: tuple[GraphPath, ...]
    status: ResultStatus
    reason: str | None = None
    @property
    def complete(self) -> bool:
        return self.status == ResultStatus.COMPLETE

class AnalysisQueryEngine:
    """Read-only deterministic query facade over GraphEngine."""

    def __init__(self, graph: GraphEngine, *, limits: QueryLimits | None = None) -> None:
        self.graph = graph
        self.limits = limits or QueryLimits()

    def nodes(self, *, node_types: frozenset[GraphNodeType] | None = None,
              evidence_ids: frozenset[EvidenceId] | None = None,
              provenance_categories: frozenset[ProvenanceCategory] | None = None,
              limit: int | None = None) -> NodeSelection:
        cap = self._cap(limit, self.limits.max_nodes)
        query = GraphQuery(node_types=node_types, evidence_ids=evidence_ids,
                           provenance_categories=provenance_categories)
        values = tuple(sorted(self.graph.nodes(query), key=lambda item: item.id))
        if not values:
            return NodeSelection((), ResultStatus.EMPTY, "no matching nodes")
        if len(values) > cap:
            return NodeSelection(values[:cap], ResultStatus.TRUNCATED, "node result limit exceeded")
        return NodeSelection(values, ResultStatus.COMPLETE)

    def edges(self, *, relationship_types: frozenset[RelationshipType] | None = None,
              evidence_ids: frozenset[EvidenceId] | None = None,
              provenance_categories: frozenset[ProvenanceCategory] | None = None,
              min_confidence: float | None = None, max_confidence: float | None = None,
              limit: int | None = None) -> EdgeSelection:
        cap = self._cap(limit, self.limits.max_edges)
        query = GraphQuery(relationship_types=relationship_types, evidence_ids=evidence_ids,
                           provenance_categories=provenance_categories,
                           min_confidence=min_confidence, max_confidence=max_confidence)
        values = tuple(sorted(self.graph.edges(query), key=lambda item: item.id))
        if not values:
            return EdgeSelection((), ResultStatus.EMPTY, "no matching edges")
        if len(values) > cap:
            return EdgeSelection(values[:cap], ResultStatus.TRUNCATED, "edge result limit exceeded")
        return EdgeSelection(values, ResultStatus.COMPLETE)

    def reachable(self, *, source_types: frozenset[GraphNodeType],
                  target_types: frozenset[GraphNodeType],
                  relationships: frozenset[RelationshipType],
                  max_depth: int | None = None, max_pairs: int | None = None) -> PathSelection:
        if not source_types or not target_types or not relationships:
            raise ValueError("source_types, target_types, and relationships must not be empty")
        pair_cap = self._cap(max_pairs, self.limits.max_paths)
        sources = tuple(sorted((n for n in self.graph.nodes() if n.type in source_types), key=lambda n: n.id))
        targets = tuple(sorted((n for n in self.graph.nodes() if n.type in target_types), key=lambda n: n.id))
        paths: list[GraphPath] = []
        pairs = 0
        for source in sources:
            for target in targets:
                if source.id == target.id:
                    continue
                pairs += 1
                if pairs > pair_cap:
                    return PathSelection(tuple(paths), ResultStatus.TRUNCATED, "path pair limit exceeded")
                result = self.graph.shortest_path(source.id, target.id,
                    allowed_relationship_types=relationships, max_depth=max_depth)
                paths.extend(sorted(result.paths, key=lambda p: p.path_id))
                if len(paths) >= pair_cap:
                    return PathSelection(tuple(paths[:pair_cap]), ResultStatus.TRUNCATED, "path result limit exceeded")
        if not paths:
            return PathSelection((), ResultStatus.EMPTY, "no reachable path")
        status = next((p.status for p in paths if p.status != ResultStatus.COMPLETE), ResultStatus.COMPLETE)
        return PathSelection(tuple(paths), status)

    @staticmethod
    def evidence_ids(*, nodes: tuple[GraphNode, ...] = (),
                     edges: tuple[GraphEdge, ...] = (),
                     paths: tuple[GraphPath, ...] = ()) -> tuple[EvidenceId, ...]:
        values: set[EvidenceId] = set()
        for node in nodes:
            values.update(node.evidence_ids)
        for edge in edges:
            values.update(edge.evidence_ids)
        for path in paths:
            values.update(path.evidence_ids)
            for node in path.nodes:
                values.update(node.evidence_ids)
            for edge in path.edges:
                values.update(edge.evidence_ids)
        return tuple(sorted(values))

    @staticmethod
    def _cap(requested: int | None, default: int) -> int:
        cap = default if requested is None else requested
        if cap < 1:
            raise ValueError("query limits must be positive")
        return min(cap, default)
