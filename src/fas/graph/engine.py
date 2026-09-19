"""Deterministic evidence graph engine and read-only graph view."""

from __future__ import annotations

from collections import deque
from hashlib import sha256
import json
from collections.abc import Iterable

from fas.domain.analysis import Artifact, Observation
from fas.domain.common import EvidenceId, GraphNodeType, NodeId, RelationshipType
from fas.domain.evidence import Evidence
from fas.domain.graph import GraphEdge, GraphNode

from .contracts import (
    GraphDiff,
    GraphLimits,
    GraphQuery,
    GraphQueryResult,
    GraphScope,
    GraphScopeKind,
    GraphPath,
    PathResult,
    ResultStatus,
    TraversalDirection,
    TraversalResult,
    ValidationIssue,
    ValidationResult,
)
from .errors import (
    EdgeNotFound,
    GraphDeserializationError,
    GraphInvariantViolation,
    GraphSealedError,
    NodeNotFound,
    SnapshotMismatch,
)
from .store import GraphStore, InMemoryGraphStore


def _stable_path_id(node_ids: tuple[NodeId, ...], edge_ids: tuple[str, ...]) -> str:
    digest = sha256(("|".join((*node_ids, *edge_ids))).encode()).hexdigest()[:26]
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    value = int(digest, 16)
    chars = []
    for _ in range(26):
        chars.append(alphabet[value & 31])
        value >>= 5
    return "path_" + "".join(reversed(chars))


class GraphEngine:
    """FAS graph semantics independent of storage implementation."""

    def __init__(
        self,
        store: GraphStore | None = None,
        *,
        analysis_id: str,
        snapshot_id: str | None = None,
        limits: GraphLimits | None = None,
        complete: bool = False,
    ) -> None:
        self.store = store or InMemoryGraphStore()
        self.scope = GraphScope(
            GraphScopeKind.SNAPSHOT if snapshot_id is not None else GraphScopeKind.ANALYSIS,
            analysis_id,
            snapshot_id,
        )
        self.limits = limits or GraphLimits()
        self.complete = complete
        self._sealed = False

    @property
    def sealed(self) -> bool:
        return self._sealed

    def _ensure_mutable(self) -> None:
        if self._sealed:
            raise GraphSealedError("graph is sealed")

    def _ensure_scope(self, analysis_id: str, snapshot_id: str) -> None:
        if not self.scope.accepts(analysis_id, snapshot_id):
            raise SnapshotMismatch("object lies outside graph scope")

    def add_evidence(self, evidence: Evidence) -> None:
        self._ensure_mutable()
        self._ensure_scope(evidence.analysis_id, evidence.snapshot_id)
        self.store.register_evidence(evidence)

    def add_artifact(self, artifact: Artifact) -> None:
        self._ensure_mutable()
        self.store.register_artifact(artifact)

    def add_observation(self, observation: Observation) -> None:
        self._ensure_mutable()
        self.store.register_observation(observation)

    def add_node(self, node: GraphNode) -> None:
        self._ensure_mutable()
        self._ensure_scope(node.analysis_id, node.snapshot_id)
        self.store.add_node(node)

    def upsert_node(self, node: GraphNode) -> GraphNode:
        self._ensure_mutable()
        self._ensure_scope(node.analysis_id, node.snapshot_id)
        return self.store.merge_node(node)

    def add_nodes(self, nodes: Iterable[GraphNode]) -> None:
        for node in nodes:
            self.add_node(node)

    def add_edges(self, edges: Iterable[GraphEdge]) -> None:
        for edge in edges:
            self.add_edge(edge)

    def add_edge(self, edge: GraphEdge) -> None:
        self._ensure_mutable()
        self._ensure_scope(edge.analysis_id, edge.snapshot_id)
        self.store.add_edge(edge)

    def merge_edge_evidence(self, edge: GraphEdge) -> GraphEdge:
        self._ensure_mutable()
        self._ensure_scope(edge.analysis_id, edge.snapshot_id)
        return self.store.merge_edge(edge)

    def remove_node(self, node_id: NodeId) -> None:
        self._ensure_mutable()
        node = self.get_node(node_id)
        self.store.remove_node(node.id)

    def remove_edge(self, edge_id: str) -> None:
        self._ensure_mutable()
        edge = self.get_edge(edge_id)
        self._ensure_scope(edge.analysis_id, edge.snapshot_id)
        self.store.remove_edge(edge.id)

    def seal(self, *, complete: bool | None = None) -> "GraphView":
        if complete is not None:
            self.complete = complete
        self._sealed = True
        validation = self.validate()
        if not validation.valid:
            raise GraphInvariantViolation(
                "; ".join(issue.message for issue in validation.issues)
            )
        return GraphView(self)

    def get_node(self, node_id: NodeId) -> GraphNode:
        node = self.store.get_node(node_id)
        self._ensure_scope(node.analysis_id, node.snapshot_id)
        return node

    def get_edge(self, edge_id: str) -> GraphEdge:
        edge = self.store.get_edge(edge_id)
        self._ensure_scope(edge.analysis_id, edge.snapshot_id)
        return edge

    def node_exists(self, node_id: NodeId) -> bool:
        try:
            self.get_node(node_id)
            return True
        except NodeNotFound:
            return False

    def edge_exists(self, edge_id: str) -> bool:
        try:
            self.get_edge(edge_id)
            return True
        except EdgeNotFound:
            return False

    def nodes(self, query: GraphQuery | None = None) -> tuple[GraphNode, ...]:
        values = self.store.nodes(self.scope)
        if query is None:
            return values
        return tuple(node for node in values if self._node_matches(node, query))

    def edges(self, query: GraphQuery | None = None) -> tuple[GraphEdge, ...]:
        values = self.store.edges(self.scope)
        if query is None:
            return values
        return tuple(edge for edge in values if self._edge_matches(edge, query))

    @staticmethod
    def _node_matches(node: GraphNode, query: GraphQuery) -> bool:
        if query.node_types and node.type not in query.node_types:
            return False
        if query.evidence_ids and not query.evidence_ids.intersection(node.evidence_ids):
            return False
        if query.provenance_categories:
            categories = {item.category.value for item in node.provenance}
            if not categories.intersection(query.provenance_categories):
                return False
        return True

    @staticmethod
    def _edge_matches(edge: GraphEdge, query: GraphQuery) -> bool:
        if query.relationship_types and edge.relationship_type not in query.relationship_types:
            return False
        if query.evidence_ids and not query.evidence_ids.intersection(edge.evidence_ids):
            return False
        if query.provenance_categories:
            categories = {item.category.value for item in edge.provenance}
            if not categories.intersection(query.provenance_categories):
                return False
        if edge.confidence is not None:
            value = edge.confidence.value
            if query.min_confidence is not None and value < query.min_confidence:
                return False
            if query.max_confidence is not None and value > query.max_confidence:
                return False
        return True

    def incoming_edges(self, node_id: NodeId) -> tuple[GraphEdge, ...]:
        node = self.get_node(node_id)
        return self.store.incoming_edges(node.id, self.scope)

    def outgoing_edges(self, node_id: NodeId) -> tuple[GraphEdge, ...]:
        node = self.get_node(node_id)
        return self.store.outgoing_edges(node.id, self.scope)

    def predecessors(self, node_id: NodeId) -> tuple[GraphNode, ...]:
        return tuple(self.get_node(edge.source_node_id) for edge in self.incoming_edges(node_id))

    def successors(self, node_id: NodeId) -> tuple[GraphNode, ...]:
        return tuple(self.get_node(edge.target_node_id) for edge in self.outgoing_edges(node_id))

    def neighbors(self, node_id: NodeId, direction: TraversalDirection = TraversalDirection.BOTH) -> tuple[GraphNode, ...]:
        edges = ()
        if direction in {TraversalDirection.OUTBOUND, TraversalDirection.BOTH}:
            edges += self.outgoing_edges(node_id)
        if direction in {TraversalDirection.INBOUND, TraversalDirection.BOTH}:
            edges += self.incoming_edges(node_id)
        ids = sorted({edge.target_node_id if edge.source_node_id == node_id else edge.source_node_id for edge in edges})
        return tuple(self.get_node(node) for node in ids)

    def get_edges_between(self, source_node_id: NodeId, target_node_id: NodeId) -> tuple[GraphEdge, ...]:
        return tuple(
            edge for edge in self.outgoing_edges(source_node_id)
            if edge.target_node_id == target_node_id
        )

    def get_edge_evidence(self, edge_id: str) -> tuple[Evidence, ...]:
        edge = self.get_edge(edge_id)
        return tuple(sorted((self.store.evidence(item) for item in edge.evidence_ids), key=lambda e: e.id))

    def get_node_evidence(self, node_id: NodeId) -> tuple[Evidence, ...]:
        node = self.get_node(node_id)
        return tuple(sorted((self.store.evidence(item) for item in node.evidence_ids), key=lambda e: e.id))

    def get_edge_provenance(self, edge_id: str):
        return self.get_edge(edge_id).provenance

    def get_node_provenance(self, node_id: NodeId):
        return self.get_node(node_id).provenance

    def get_provenance(self, subject_id: str, *, subject_type: str) -> tuple:
        if subject_type == "node":
            return self.get_node_provenance(subject_id)  # type: ignore[arg-type]
        if subject_type == "edge":
            return self.get_edge_provenance(subject_id)
        raise ValueError("subject_type must be node or edge")

    def evidence_subgraph(self, evidence_ids: Iterable[EvidenceId]) -> GraphQueryResult:
        ids = frozenset(evidence_ids)
        nodes = tuple(node for node in self.nodes() if ids.intersection(node.evidence_ids))
        edges = tuple(edge for edge in self.edges() if ids.intersection(edge.evidence_ids))
        return GraphQueryResult(nodes=nodes, edges=edges, status=ResultStatus.COMPLETE)

    def subgraph(self, node_ids: Iterable[NodeId], *, query: GraphQuery | None = None) -> GraphQueryResult:
        ids = frozenset(node_ids)
        nodes = tuple(node for node in self.nodes(query) if node.id in ids)
        edges = tuple(
            edge for edge in self.edges(query)
            if edge.source_node_id in ids and edge.target_node_id in ids
        )
        return GraphQueryResult(nodes=nodes, edges=edges, status=ResultStatus.COMPLETE if nodes else ResultStatus.EMPTY)

    def neighborhood(
        self,
        node_id: NodeId,
        *,
        depth: int = 1,
        direction: TraversalDirection = TraversalDirection.BOTH,
        relationship_types: frozenset[RelationshipType] | None = None,
        allowed_node_types: frozenset[GraphNodeType] | None = None,
        max_nodes: int | None = None,
        max_edges: int | None = None,
    ) -> GraphQueryResult:
        result = self.traverse(
            node_id,
            direction=direction,
            max_depth=depth,
            allowed_relationship_types=relationship_types,
            allowed_node_types=allowed_node_types,
            max_nodes=max_nodes,
            max_edges=max_edges,
        )
        ids = frozenset(result.node_ids)
        nodes = tuple(self.get_node(item) for item in result.node_ids)
        edges = tuple(
            edge for edge in self.edges()
            if edge.source_node_id in ids and edge.target_node_id in ids
        )
        if max_edges is not None:
            edges = edges[:max_edges]
        return GraphQueryResult(nodes=nodes, edges=edges, status=result.status, reason=result.reason)

    def traverse(
        self,
        start_node_id: NodeId,
        *,
        direction: TraversalDirection = TraversalDirection.OUTBOUND,
        max_depth: int | None = None,
        allowed_relationship_types: frozenset[RelationshipType] | None = None,
        excluded_relationship_types: frozenset[RelationshipType] | None = None,
        allowed_node_types: frozenset[GraphNodeType] | None = None,
        excluded_node_types: frozenset[GraphNodeType] | None = None,
        max_nodes: int | None = None,
        max_edges: int | None = None,
    ) -> TraversalResult:
        start = self.get_node(start_node_id)
        depth_limit = self.limits.max_traversal_depth if max_depth is None else min(max_depth, self.limits.max_traversal_depth)
        node_limit = self.limits.max_nodes_visited if max_nodes is None else min(max_nodes, self.limits.max_nodes_visited)
        edge_limit = self.limits.max_edges_visited if max_edges is None else min(max_edges, self.limits.max_edges_visited)
        queue: deque[tuple[NodeId, int]] = deque([(start.id, 0)])
        seen = {start.id}
        visited_edges: set[str] = set()
        depths: dict[NodeId, int] = {start.id: 0}
        truncated = False

        while queue:
            current, depth = queue.popleft()
            if depth >= depth_limit:
                continue
            edges = []
            if direction in {TraversalDirection.OUTBOUND, TraversalDirection.BOTH}:
                edges.extend(self.outgoing_edges(current))
            if direction in {TraversalDirection.INBOUND, TraversalDirection.BOTH}:
                edges.extend(self.incoming_edges(current))
            for edge in sorted(edges, key=lambda item: item.id):
                if allowed_relationship_types and edge.relationship_type not in allowed_relationship_types:
                    continue
                if excluded_relationship_types and edge.relationship_type in excluded_relationship_types:
                    continue
                visited_edges.add(edge.id)
                if len(visited_edges) > edge_limit:
                    truncated = True
                    break
                neighbor = edge.target_node_id if edge.source_node_id == current else edge.source_node_id
                candidate = self.get_node(neighbor)
                if allowed_node_types and candidate.type not in allowed_node_types:
                    continue
                if excluded_node_types and candidate.type in excluded_node_types:
                    continue
                if candidate.snapshot_id != start.snapshot_id:
                    raise SnapshotMismatch("traversal attempted to cross snapshot boundary")
                if neighbor not in seen:
                    seen.add(neighbor)
                    depths[neighbor] = depth + 1
                    if len(seen) > node_limit:
                        truncated = True
                        break
                    queue.append((neighbor, depth + 1))
            if truncated:
                break

        status = ResultStatus.TRUNCATED if truncated else ResultStatus.COMPLETE
        return TraversalResult(
            node_ids=tuple(sorted(seen)),
            edge_ids=tuple(sorted(visited_edges)),
            depths=tuple(sorted(depths.items())),
            status=status,
            reason="configured traversal limit reached" if truncated else None,
        )

    def reachable_nodes(self, start_node_id: NodeId, **kwargs) -> TraversalResult:
        return self.traverse(start_node_id, **kwargs)

    def has_path(self, source_node_id: NodeId, target_node_id: NodeId, **kwargs) -> bool:
        result = self.shortest_path(source_node_id, target_node_id, **kwargs)
        return bool(result.paths)

    def shortest_path(self, source_node_id: NodeId, target_node_id: NodeId, **kwargs) -> PathResult:
        source = self.get_node(source_node_id)
        target = self.get_node(target_node_id)
        if source.snapshot_id != target.snapshot_id:
            return PathResult(status=ResultStatus.EMPTY, reason="cross-snapshot paths are forbidden")
        allowed_relationship_types = kwargs.get("allowed_relationship_types")
        direction = kwargs.get("direction", TraversalDirection.OUTBOUND)
        max_depth = min(kwargs.get("max_depth", self.limits.max_path_depth), self.limits.max_path_depth)
        queue = deque([source.id])
        distance = {source.id: 0}
        predecessor: dict[NodeId, tuple[NodeId, str] | None] = {source.id: None}
        while queue:
            current = queue.popleft()
            if current == target.id:
                break
            if distance[current] >= max_depth:
                continue
            edges = []
            if direction in {TraversalDirection.OUTBOUND, TraversalDirection.BOTH}:
                edges.extend(self.outgoing_edges(current))
            if direction in {TraversalDirection.INBOUND, TraversalDirection.BOTH}:
                edges.extend(self.incoming_edges(current))
            for edge in sorted(edges, key=lambda item: item.id):
                if allowed_relationship_types and edge.relationship_type not in allowed_relationship_types:
                    continue
                neighbor = edge.target_node_id if edge.source_node_id == current else edge.source_node_id
                if neighbor in distance:
                    continue
                distance[neighbor] = distance[current] + 1
                predecessor[neighbor] = (current, edge.id)
                queue.append(neighbor)
        if target.id not in predecessor:
            return PathResult(status=ResultStatus.EMPTY)
        node_ids = []
        edge_ids = []
        current = target.id
        while current != source.id:
            node_ids.append(current)
            previous, edge_id = predecessor[current]
            edge_ids.append(edge_id)
            current = previous
        node_ids.append(source.id)
        node_ids.reverse()
        edge_ids.reverse()
        return PathResult(paths=(self._build_path(tuple(node_ids), tuple(edge_ids)),), status=ResultStatus.COMPLETE)

    def all_shortest_paths(self, source_node_id: NodeId, target_node_id: NodeId, **kwargs) -> PathResult:
        source = self.get_node(source_node_id)
        target = self.get_node(target_node_id)
        if source.snapshot_id != target.snapshot_id:
            return PathResult(status=ResultStatus.EMPTY, reason="cross-snapshot paths are forbidden")
        allowed = kwargs.get("allowed_relationship_types")
        direction = kwargs.get("direction", TraversalDirection.OUTBOUND)
        max_depth = min(kwargs.get("max_depth", self.limits.max_path_depth), self.limits.max_path_depth)
        distance = {source.id: 0}
        predecessors: dict[NodeId, list[tuple[NodeId, str]]] = {source.id: []}
        queue = deque([source.id])
        while queue:
            current = queue.popleft()
            if distance[current] >= max_depth:
                continue
            edges = self._traversal_edges(current, direction)
            for edge in edges:
                if allowed and edge.relationship_type not in allowed:
                    continue
                neighbor = edge.target_node_id if edge.source_node_id == current else edge.source_node_id
                candidate_distance = distance[current] + 1
                if neighbor not in distance:
                    distance[neighbor] = candidate_distance
                    predecessors[neighbor] = [(current, edge.id)]
                    queue.append(neighbor)
                elif distance[neighbor] == candidate_distance:
                    predecessors[neighbor].append((current, edge.id))
        if target.id not in distance:
            return PathResult(status=ResultStatus.EMPTY)
        paths: list[GraphPath] = []
        truncated = False

        def backtrack(node: NodeId, nodes: list[NodeId], edges: list[str]) -> None:
            nonlocal truncated
            if len(paths) >= self.limits.max_paths:
                truncated = True
                return
            if node == source.id:
                paths.append(self._build_path(tuple(reversed(nodes)), tuple(reversed(edges))))
                return
            for previous, edge_id in sorted(predecessors[node], key=lambda item: (item[0], item[1])):
                backtrack(previous, [*nodes, previous], [*edges, edge_id])
                if truncated:
                    return

        backtrack(target.id, [target.id], [])
        return PathResult(
            paths=tuple(paths),
            status=ResultStatus.TRUNCATED if truncated else ResultStatus.COMPLETE,
            reason="max_paths reached" if truncated else None,
        )

    def enumerate_paths(self, source_node_id: NodeId, target_node_id: NodeId, **kwargs) -> PathResult:
        return self.bounded_paths(source_node_id, target_node_id, **kwargs)

    def paths_between(self, source_node_id: NodeId, target_node_id: NodeId, **kwargs) -> PathResult:
        return self.bounded_paths(source_node_id, target_node_id, **kwargs)

    def reachable_targets(self, source_node_id: NodeId, target_node_ids: Iterable[NodeId], **kwargs) -> tuple[NodeId, ...]:
        reachable = set(self.reachable_nodes(source_node_id, **kwargs).node_ids)
        return tuple(sorted(set(target_node_ids) & reachable))

    def bounded_paths(self, source_node_id: NodeId, target_node_id: NodeId, **kwargs) -> PathResult:
        source = self.get_node(source_node_id)
        target = self.get_node(target_node_id)
        if source.snapshot_id != target.snapshot_id:
            return PathResult(status=ResultStatus.EMPTY, reason="cross-snapshot paths are forbidden")
        max_depth = min(kwargs.get("max_depth", self.limits.max_path_depth), self.limits.max_path_depth)
        max_paths = min(kwargs.get("max_paths", self.limits.max_paths), self.limits.max_paths)
        allowed = kwargs.get("allowed_relationship_types")
        direction = kwargs.get("direction", TraversalDirection.OUTBOUND)
        paths: list[GraphPath] = []
        truncated = False

        def walk(current: NodeId, nodes: list[NodeId], edges: list[str]) -> None:
            nonlocal truncated
            if len(paths) >= max_paths:
                truncated = True
                return
            if current == target.id:
                paths.append(self._build_path(tuple(nodes), tuple(edges)))
                return
            if len(edges) >= max_depth:
                return
            for edge in self._traversal_edges(current, direction):
                if allowed and edge.relationship_type not in allowed:
                    continue
                neighbor = edge.target_node_id if edge.source_node_id == current else edge.source_node_id
                if neighbor in nodes:
                    continue
                walk(neighbor, [*nodes, neighbor], [*edges, edge.id])
                if truncated:
                    return

        walk(source.id, [source.id], [])
        return PathResult(
            paths=tuple(paths),
            status=ResultStatus.TRUNCATED if truncated else (ResultStatus.COMPLETE if paths else ResultStatus.EMPTY),
            reason="max_paths reached" if truncated else None,
        )

    def _traversal_edges(self, node_id: NodeId, direction: TraversalDirection) -> tuple[GraphEdge, ...]:
        edges: list[GraphEdge] = []
        if direction in {TraversalDirection.OUTBOUND, TraversalDirection.BOTH}:
            edges.extend(self.outgoing_edges(node_id))
        if direction in {TraversalDirection.INBOUND, TraversalDirection.BOTH}:
            edges.extend(self.incoming_edges(node_id))
        return tuple(sorted(edges, key=lambda edge: edge.id))

    def _build_path(self, node_ids: tuple[NodeId, ...], edge_ids: tuple[str, ...]) -> GraphPath:
        nodes = tuple(self.get_node(item) for item in node_ids)
        edges = tuple(self.get_edge(item) for item in edge_ids)
        evidence = tuple(sorted({item for edge in edges for item in edge.evidence_ids}))
        boundaries = tuple(
            node.id for node in nodes if node.type == GraphNodeType.TRUST_BOUNDARY
        )
        return GraphPath(
            path_id=_stable_path_id(node_ids, edge_ids),
            nodes=nodes,
            edges=edges,
            analysis_id=self.scope.analysis_id,
            snapshot_id=nodes[0].snapshot_id,
            trust_boundary_node_ids=boundaries,
            evidence_ids=evidence,
        )

    def strongly_connected_components(self) -> tuple[tuple[NodeId, ...], ...]:
        index = 0
        indices: dict[NodeId, int] = {}
        lowlinks: dict[NodeId, int] = {}
        stack: list[NodeId] = []
        on_stack: set[NodeId] = set()
        components: list[tuple[NodeId, ...]] = []

        def visit(node_id: NodeId) -> None:
            nonlocal index
            indices[node_id] = index
            lowlinks[node_id] = index
            index += 1
            stack.append(node_id)
            on_stack.add(node_id)
            for edge in self.outgoing_edges(node_id):
                target = edge.target_node_id
                if target not in indices:
                    visit(target)
                    lowlinks[node_id] = min(lowlinks[node_id], lowlinks[target])
                elif target in on_stack:
                    lowlinks[node_id] = min(lowlinks[node_id], indices[target])
            if lowlinks[node_id] == indices[node_id]:
                component = []
                while True:
                    member = stack.pop()
                    on_stack.remove(member)
                    component.append(member)
                    if member == node_id:
                        break
                components.append(tuple(sorted(component)))

        for node in self.nodes():
            if node.id not in indices:
                visit(node.id)
        return tuple(sorted(components, key=lambda component: component))

    def detect_cycles(self) -> tuple[tuple[NodeId, ...], ...]:
        return tuple(component for component in self.strongly_connected_components() if len(component) > 1)

    def connected_components(self) -> tuple[tuple[NodeId, ...], ...]:
        unseen = {node.id for node in self.nodes()}
        components = []
        while unseen:
            start = min(unseen)
            queue = [start]
            component = set()
            while queue:
                current = queue.pop()
                if current in component:
                    continue
                component.add(current)
                unseen.discard(current)
                queue.extend(node.id for node in self.neighbors(current))
            components.append(tuple(sorted(component)))
        return tuple(sorted(components))

    def boundary_crossings(self, path: GraphPath) -> tuple[NodeId, ...]:
        return path.trust_boundary_node_ids

    def validate(self) -> ValidationResult:
        issues: list[ValidationIssue] = []
        nodes = self.nodes()
        node_ids = {node.id for node in nodes}
        for node in nodes:
            try:
                for evidence_id in node.evidence_ids:
                    evidence = self.store.evidence(evidence_id)
                    if evidence.analysis_id != node.analysis_id or evidence.snapshot_id != node.snapshot_id:
                        issues.append(ValidationIssue("EVIDENCE_SCOPE", "node evidence scope mismatch", node.id))
            except NodeNotFound as exc:
                issues.append(ValidationIssue("EVIDENCE_REFERENCE", str(exc), node.id))
        for edge in self.edges():
            if edge.source_node_id not in node_ids or edge.target_node_id not in node_ids:
                issues.append(ValidationIssue("EDGE_ENDPOINT", "edge endpoint missing", edge.id))
            else:
                source = self.get_node(edge.source_node_id)
                target = self.get_node(edge.target_node_id)
                if source.snapshot_id != edge.snapshot_id or target.snapshot_id != edge.snapshot_id:
                    issues.append(ValidationIssue("SNAPSHOT_MISMATCH", "edge crosses snapshot scope", edge.id))
            for evidence_id in edge.evidence_ids:
                try:
                    evidence = self.store.evidence(evidence_id)
                    if evidence.analysis_id != edge.analysis_id or evidence.snapshot_id != edge.snapshot_id:
                        issues.append(ValidationIssue("EVIDENCE_SCOPE", "edge evidence scope mismatch", edge.id))
                except NodeNotFound as exc:
                    issues.append(ValidationIssue("EVIDENCE_REFERENCE", str(exc), edge.id))
        return ValidationResult(tuple(issues))

    def to_json(self) -> str:
        export = {
            "schema_version": "1.0",
            "analysis_id": self.scope.analysis_id,
            "snapshot_id": self.scope.snapshot_id,
            "complete": self.complete,
            "metadata": {},
            "nodes": [node.model_dump(mode="json") for node in self.nodes()],
            "edges": [edge.model_dump(mode="json") for edge in self.edges()],
            "evidence": [item.model_dump(mode="json") for item in self.store.evidence_records()],
            "artifacts": [item.model_dump(mode="json") for item in self.store.artifact_records()],
            "observations": [item.model_dump(mode="json") for item in self.store.observation_records()],
        }
        return json.dumps(export, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    @classmethod
    def from_json(cls, payload: str, *, store: GraphStore | None = None) -> "GraphEngine":
        try:
            raw = json.loads(payload)
            engine = cls(
                store,
                analysis_id=raw["analysis_id"],
                snapshot_id=raw.get("snapshot_id"),
                complete=bool(raw.get("complete", False)),
            )
            for item in raw.get("artifacts", []):
                engine.add_artifact(Artifact.model_validate(item))
            for item in raw.get("observations", []):
                engine.add_observation(Observation.model_validate(item))
            for item in raw.get("evidence", []):
                engine.add_evidence(Evidence.model_validate(item))
            for item in raw["nodes"]:
                engine.add_node(GraphNode.model_validate(item))
            for item in raw["edges"]:
                engine.add_edge(GraphEdge.model_validate(item))
            return engine
        except Exception as exc:
            if isinstance(exc, (GraphSealedError, SnapshotMismatch)):
                raise
            raise GraphDeserializationError(str(exc)) from exc

    @staticmethod
    def diff(left: "GraphEngine", right: "GraphEngine") -> GraphDiff:
        if left.scope.analysis_id != right.scope.analysis_id:
            raise SnapshotMismatch("graph diff requires the same analysis")
        left_nodes = {node.canonical_identity: node for node in left.nodes()}
        right_nodes = {node.canonical_identity: node for node in right.nodes()}
        unchanged_nodes = []
        changed_nodes = []
        for identity in sorted(left_nodes.keys() & right_nodes.keys()):
            if left_nodes[identity].model_dump(mode="json") == right_nodes[identity].model_dump(mode="json"):
                unchanged_nodes.append(right_nodes[identity])
            else:
                changed_nodes.append((left_nodes[identity], right_nodes[identity]))
        def edge_key(edge: GraphEdge) -> tuple[str, str, str]:
            source = left.get_node(edge.source_node_id).canonical_identity if left.node_exists(edge.source_node_id) else edge.source_node_id
            target = left.get_node(edge.target_node_id).canonical_identity if left.node_exists(edge.target_node_id) else edge.target_node_id
            return source, target, edge.relationship_type.value

        def edge_key_right(edge: GraphEdge) -> tuple[str, str, str]:
            source = right.get_node(edge.source_node_id).canonical_identity if right.node_exists(edge.source_node_id) else edge.source_node_id
            target = right.get_node(edge.target_node_id).canonical_identity if right.node_exists(edge.target_node_id) else edge.target_node_id
            return source, target, edge.relationship_type.value

        left_edges = {edge_key(edge): edge for edge in left.edges()}
        right_edges = {edge_key_right(edge): edge for edge in right.edges()}
        unchanged_edges = []
        changed_edges = []
        for key in sorted(left_edges.keys() & right_edges.keys()):
            if left_edges[key].model_dump(mode="json") == right_edges[key].model_dump(mode="json"):
                unchanged_edges.append(right_edges[key])
            else:
                changed_edges.append((left_edges[key], right_edges[key]))
        return GraphDiff(
            added_nodes=tuple(right_nodes[key] for key in sorted(right_nodes.keys() - left_nodes.keys())),
            removed_nodes=tuple(left_nodes[key] for key in sorted(left_nodes.keys() - right_nodes.keys())),
            unchanged_nodes=tuple(unchanged_nodes),
            changed_nodes=tuple(changed_nodes),
            added_edges=tuple(right_edges[key] for key in sorted(right_edges.keys() - left_edges.keys())),
            removed_edges=tuple(left_edges[key] for key in sorted(left_edges.keys() - right_edges.keys())),
            unchanged_edges=tuple(unchanged_edges),
            changed_edges=tuple(changed_edges),
        )


class GraphView:
    """Immutable read-only facade over a sealed graph."""

    def __init__(self, engine: GraphEngine) -> None:
        if not engine.sealed:
            raise GraphSealedError("GraphView requires a sealed graph")
        self._engine = engine

    @property
    def scope(self) -> GraphScope:
        return self._engine.scope

    @property
    def complete(self) -> bool:
        return self._engine.complete

    def nodes(self, query: GraphQuery | None = None) -> tuple[GraphNode, ...]:
        return self._engine.nodes(query)

    def edges(self, query: GraphQuery | None = None) -> tuple[GraphEdge, ...]:
        return self._engine.edges(query)

    def get_node(self, node_id: NodeId) -> GraphNode:
        return self._engine.get_node(node_id)

    def get_edge(self, edge_id: str) -> GraphEdge:
        return self._engine.get_edge(edge_id)

    def neighbors(self, *args, **kwargs):
        return self._engine.neighbors(*args, **kwargs)

    def predecessors(self, *args, **kwargs):
        return self._engine.predecessors(*args, **kwargs)

    def successors(self, *args, **kwargs):
        return self._engine.successors(*args, **kwargs)

    def incoming_edges(self, *args, **kwargs):
        return self._engine.incoming_edges(*args, **kwargs)

    def outgoing_edges(self, *args, **kwargs):
        return self._engine.outgoing_edges(*args, **kwargs)

    def get_edges_between(self, *args, **kwargs):
        return self._engine.get_edges_between(*args, **kwargs)

    def get_provenance(self, *args, **kwargs):
        return self._engine.get_provenance(*args, **kwargs)

    def paths_between(self, *args, **kwargs):
        return self._engine.paths_between(*args, **kwargs)

    def enumerate_paths(self, *args, **kwargs):
        return self._engine.enumerate_paths(*args, **kwargs)

    def neighborhood(self, *args, **kwargs):
        return self._engine.neighborhood(*args, **kwargs)

    def evidence_subgraph(self, *args, **kwargs):
        return self._engine.evidence_subgraph(*args, **kwargs)

    def traverse(self, *args, **kwargs):
        return self._engine.traverse(*args, **kwargs)

    def reachable_nodes(self, *args, **kwargs):
        return self._engine.reachable_nodes(*args, **kwargs)

    def has_path(self, *args, **kwargs):
        return self._engine.has_path(*args, **kwargs)

    def shortest_path(self, *args, **kwargs):
        return self._engine.shortest_path(*args, **kwargs)

    def all_shortest_paths(self, *args, **kwargs):
        return self._engine.all_shortest_paths(*args, **kwargs)

    def bounded_paths(self, *args, **kwargs):
        return self._engine.bounded_paths(*args, **kwargs)

    def reachable_targets(self, *args, **kwargs):
        return self._engine.reachable_targets(*args, **kwargs)

    def strongly_connected_components(self):
        return self._engine.strongly_connected_components()

    def detect_cycles(self):
        return self._engine.detect_cycles()

    def connected_components(self):
        return self._engine.connected_components()

    def boundary_crossings(self, *args, **kwargs):
        return self._engine.boundary_crossings(*args, **kwargs)

    def get_edge_evidence(self, *args, **kwargs):
        return self._engine.get_edge_evidence(*args, **kwargs)

    def get_node_evidence(self, *args, **kwargs):
        return self._engine.get_node_evidence(*args, **kwargs)

    def get_edge_provenance(self, *args, **kwargs):
        return self._engine.get_edge_provenance(*args, **kwargs)

    def get_node_provenance(self, *args, **kwargs):
        return self._engine.get_node_provenance(*args, **kwargs)

    def validate(self):
        return self._engine.validate()

    def to_json(self) -> str:
        return self._engine.to_json()
