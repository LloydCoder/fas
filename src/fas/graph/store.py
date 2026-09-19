"""Backend-independent graph storage contracts and in-memory implementation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from fas.domain.analysis import Artifact, Observation
from fas.domain.evidence import Evidence
from fas.domain.graph import GraphEdge, GraphNode
from fas.domain.common import EvidenceId, NodeId

from .contracts import GraphScope
from .errors import DuplicateEdge, DuplicateNode, EdgeNotFound, NodeNotFound, SnapshotMismatch


@dataclass(frozen=True, slots=True)
class MutationEvent:
    kind: str
    subject_id: str
    analysis_id: str
    snapshot_id: str


class GraphStore(Protocol):
    def register_evidence(self, evidence: Evidence) -> None: ...
    def register_artifact(self, artifact: Artifact) -> None: ...
    def register_observation(self, observation: Observation) -> None: ...
    def add_node(self, node: GraphNode) -> None: ...
    def add_edge(self, edge: GraphEdge) -> None: ...
    def merge_node(self, node: GraphNode) -> GraphNode: ...
    def merge_edge(self, edge: GraphEdge) -> GraphEdge: ...
    def get_node(self, node_id: NodeId) -> GraphNode: ...
    def get_edge(self, edge_id: str) -> GraphEdge: ...
    def remove_node(self, node_id: NodeId) -> None: ...
    def remove_edge(self, edge_id: str) -> None: ...
    def nodes(self, scope: GraphScope | None = None) -> tuple[GraphNode, ...]: ...
    def edges(self, scope: GraphScope | None = None) -> tuple[GraphEdge, ...]: ...
    def outgoing_edges(self, node_id: NodeId, scope: GraphScope | None = None) -> tuple[GraphEdge, ...]: ...
    def incoming_edges(self, node_id: NodeId, scope: GraphScope | None = None) -> tuple[GraphEdge, ...]: ...
    def events(self) -> tuple[MutationEvent, ...]: ...
    def evidence_records(self) -> tuple[Evidence, ...]: ...
    def artifact_records(self) -> tuple[Artifact, ...]: ...
    def observation_records(self) -> tuple[Observation, ...]: ...
    def evidence(self, evidence_id: EvidenceId) -> Evidence: ...
    def artifacts(self, artifact_id: str) -> Artifact: ...
    def observations(self, observation_id: str) -> Observation: ...


class InMemoryGraphStore:
    """Deterministic indexed store; no graph algorithm is coupled to it."""

    def __init__(self) -> None:
        self._nodes: dict[NodeId, GraphNode] = {}
        self._edges: dict[str, GraphEdge] = {}
        self._node_identity: dict[tuple[str, str, str, str], NodeId] = {}
        self._edge_semantics: dict[tuple[str, str, str, str, str], str] = {}
        self._outgoing: dict[NodeId, set[str]] = {}
        self._incoming: dict[NodeId, set[str]] = {}
        self._evidence: dict[EvidenceId, Evidence] = {}
        self._artifacts: dict[str, Artifact] = {}
        self._observations: dict[str, Observation] = {}
        self._events: list[MutationEvent] = []

    @staticmethod
    def node_key(node: GraphNode) -> tuple[str, str, str, str]:
        return (node.analysis_id, node.snapshot_id, node.type.value, node.canonical_identity)

    @staticmethod
    def edge_key(edge: GraphEdge) -> tuple[str, str, str, str, str]:
        return (
            edge.analysis_id,
            edge.snapshot_id,
            edge.source_node_id,
            edge.target_node_id,
            edge.relationship_type.value,
        )

    def register_evidence(self, evidence: Evidence) -> None:
        if evidence.id in self._evidence and self._evidence[evidence.id] != evidence:
            raise DuplicateNode(f"evidence {evidence.id} already exists with different content")
        for artifact_id in evidence.related_artifact_ids:
            artifact = self._artifacts.get(artifact_id)
            if artifact is None:
                raise SnapshotMismatch(f"unknown artifact {artifact_id}")
            if artifact.snapshot_id != evidence.snapshot_id:
                raise SnapshotMismatch(f"artifact {artifact_id} is outside evidence scope")
        for observation_id in evidence.related_observation_ids:
            observation = self._observations.get(observation_id)
            if observation is None:
                raise SnapshotMismatch(f"unknown observation {observation_id}")
        for provenance in evidence.provenance:
            for parent_id in provenance.parent_evidence_ids:
                if parent_id not in self._evidence:
                    raise SnapshotMismatch(f"unknown parent evidence {parent_id}")
        self._evidence[evidence.id] = evidence

    def register_artifact(self, artifact: Artifact) -> None:
        if artifact.id in self._artifacts and self._artifacts[artifact.id] != artifact:
            raise DuplicateNode(f"artifact {artifact.id} already exists with different content")
        self._artifacts[artifact.id] = artifact

    def register_observation(self, observation: Observation) -> None:
        if observation.id in self._observations and self._observations[observation.id] != observation:
            raise DuplicateNode(f"observation {observation.id} already exists with different content")
        self._observations[observation.id] = observation

    def add_node(self, node: GraphNode) -> None:
        if node.id in self._nodes:
            raise DuplicateNode(f"node {node.id} already exists")
        key = self.node_key(node)
        if key in self._node_identity:
            raise DuplicateNode(f"semantic node already exists for {key}")
        self._validate_node_evidence(node)
        self._validate_provenance(node.provenance, node.snapshot_id)
        self._nodes[node.id] = node
        self._node_identity[key] = node.id
        self._outgoing.setdefault(node.id, set())
        self._incoming.setdefault(node.id, set())
        self._events.append(MutationEvent("NodeAdded", node.id, node.analysis_id, node.snapshot_id))

    def add_edge(self, edge: GraphEdge) -> None:
        if edge.id in self._edges:
            raise DuplicateEdge(f"edge {edge.id} already exists")
        if edge.source_node_id not in self._nodes or edge.target_node_id not in self._nodes:
            raise NodeNotFound("edge endpoints must exist before edge insertion")
        source = self._nodes[edge.source_node_id]
        target = self._nodes[edge.target_node_id]
        if source.analysis_id != edge.analysis_id or target.analysis_id != edge.analysis_id:
            raise SnapshotMismatch("edge and endpoint analysis scopes differ")
        if source.snapshot_id != edge.snapshot_id or target.snapshot_id != edge.snapshot_id:
            raise SnapshotMismatch("edge and endpoint snapshots differ")
        key = self.edge_key(edge)
        if key in self._edge_semantics:
            raise DuplicateEdge(f"semantic edge already exists for {key}")
        self._validate_edge_evidence(edge)
        self._validate_provenance(edge.provenance, edge.snapshot_id)
        self._edges[edge.id] = edge
        self._edge_semantics[key] = edge.id
        self._outgoing[edge.source_node_id].add(edge.id)
        self._incoming[edge.target_node_id].add(edge.id)
        self._events.append(MutationEvent("EdgeAdded", edge.id, edge.analysis_id, edge.snapshot_id))

    def merge_node(self, node: GraphNode) -> GraphNode:
        existing_id = self._node_identity.get(self.node_key(node))
        if existing_id is None:
            self.add_node(node)
            return node
        existing = self._nodes[existing_id]
        if existing.id != node.id:
            raise DuplicateNode("same semantic node has conflicting stable IDs")
        merged = existing.model_copy(
            update={
                "evidence_ids": tuple(sorted(set(existing.evidence_ids) | set(node.evidence_ids))),
                "provenance": self._merge_provenance(existing.provenance, node.provenance),
                "metadata": {**existing.metadata, **node.metadata},
                "security_relevant": existing.security_relevant or node.security_relevant,
            }
        )
        self._nodes[existing_id] = merged
        self._events.append(MutationEvent("NodeMerged", existing_id, merged.analysis_id, merged.snapshot_id))
        return merged

    def merge_edge(self, edge: GraphEdge) -> GraphEdge:
        existing_id = self._edge_semantics.get(self.edge_key(edge))
        if existing_id is None:
            self.add_edge(edge)
            return edge
        existing = self._edges[existing_id]
        merged = existing.model_copy(
            update={
                "evidence_ids": tuple(sorted(set(existing.evidence_ids) | set(edge.evidence_ids))),
                "provenance": self._merge_provenance(existing.provenance, edge.provenance),
                "metadata": {**existing.metadata, **edge.metadata},
                "confidence": edge.confidence if edge.confidence is not None else existing.confidence,
                "security_relevant": existing.security_relevant or edge.security_relevant,
                "observed_at": max(existing.observed_at, edge.observed_at),
            }
        )
        self._edges[existing_id] = merged
        self._events.append(MutationEvent("EdgeMerged", existing_id, merged.analysis_id, merged.snapshot_id))
        return merged

    @staticmethod
    def _merge_provenance(left, right):
        unique = {
            item.canonical_json(): item
            for item in (*left, *right)
        }
        return tuple(unique[key] for key in sorted(unique))

    def _validate_node_evidence(self, node: GraphNode) -> None:
        for evidence_id in node.evidence_ids:
            evidence = self._evidence.get(evidence_id)
            if evidence is None:
                raise SnapshotMismatch(f"unknown evidence {evidence_id}")
            if evidence.analysis_id != node.analysis_id or evidence.snapshot_id != node.snapshot_id:
                raise SnapshotMismatch(f"evidence {evidence_id} is outside node scope")

    def _validate_provenance(self, provenance_records, snapshot_id: str) -> None:
        for provenance in provenance_records:
            for parent_id in provenance.parent_evidence_ids:
                parent = self._evidence.get(parent_id)
                if parent is None:
                    raise SnapshotMismatch(f"unknown parent evidence {parent_id}")
                if parent.snapshot_id != snapshot_id:
                    raise SnapshotMismatch(f"parent evidence {parent_id} is outside scope")

    def _validate_edge_evidence(self, edge: GraphEdge) -> None:
        for evidence_id in edge.evidence_ids:
            evidence = self._evidence.get(evidence_id)
            if evidence is None:
                raise SnapshotMismatch(f"unknown evidence {evidence_id}")
            if evidence.analysis_id != edge.analysis_id or evidence.snapshot_id != edge.snapshot_id:
                raise SnapshotMismatch(f"evidence {evidence_id} is outside edge scope")

    def get_node(self, node_id: NodeId) -> GraphNode:
        try:
            return self._nodes[node_id]
        except KeyError as exc:
            raise NodeNotFound(node_id) from exc

    def get_edge(self, edge_id: str) -> GraphEdge:
        try:
            return self._edges[edge_id]
        except KeyError as exc:
            raise EdgeNotFound(edge_id) from exc

    def remove_node(self, node_id: NodeId) -> None:
        node = self.get_node(node_id)
        for edge_id in tuple(self._outgoing.get(node_id, ()) | self._incoming.get(node_id, ())):
            self.remove_edge(edge_id)
        del self._nodes[node_id]
        self._node_identity.pop(self.node_key(node), None)
        self._outgoing.pop(node_id, None)
        self._incoming.pop(node_id, None)
        self._events.append(MutationEvent("NodeRemoved", node_id, node.analysis_id, node.snapshot_id))

    def remove_edge(self, edge_id: str) -> None:
        edge = self.get_edge(edge_id)
        del self._edges[edge_id]
        self._edge_semantics.pop(self.edge_key(edge), None)
        self._outgoing[edge.source_node_id].discard(edge_id)
        self._incoming[edge.target_node_id].discard(edge_id)
        self._events.append(MutationEvent("EdgeRemoved", edge_id, edge.analysis_id, edge.snapshot_id))

    def nodes(self, scope: GraphScope | None = None) -> tuple[GraphNode, ...]:
        values = (node for node in self._nodes.values() if scope is None or scope.accepts(node.analysis_id, node.snapshot_id))
        return tuple(sorted(values, key=lambda node: node.id))

    def edges(self, scope: GraphScope | None = None) -> tuple[GraphEdge, ...]:
        values = (edge for edge in self._edges.values() if scope is None or scope.accepts(edge.analysis_id, edge.snapshot_id))
        return tuple(sorted(values, key=lambda edge: edge.id))

    def outgoing_edges(self, node_id: NodeId, scope: GraphScope | None = None) -> tuple[GraphEdge, ...]:
        self.get_node(node_id)
        edges = (
            self._edges[edge_id]
            for edge_id in self._outgoing.get(node_id, ())
            if scope is None or scope.accepts(self._edges[edge_id].analysis_id, self._edges[edge_id].snapshot_id)
        )
        return tuple(sorted(edges, key=lambda edge: edge.id))

    def incoming_edges(self, node_id: NodeId, scope: GraphScope | None = None) -> tuple[GraphEdge, ...]:
        self.get_node(node_id)
        edges = (
            self._edges[edge_id]
            for edge_id in self._incoming.get(node_id, ())
            if scope is None or scope.accepts(self._edges[edge_id].analysis_id, self._edges[edge_id].snapshot_id)
        )
        return tuple(sorted(edges, key=lambda edge: edge.id))

    def evidence(self, evidence_id: EvidenceId) -> Evidence:
        try:
            return self._evidence[evidence_id]
        except KeyError as exc:
            raise NodeNotFound(f"evidence {evidence_id}") from exc

    def artifacts(self, artifact_id: str) -> Artifact:
        try:
            return self._artifacts[artifact_id]
        except KeyError as exc:
            raise NodeNotFound(f"artifact {artifact_id}") from exc

    def observations(self, observation_id: str) -> Observation:
        try:
            return self._observations[observation_id]
        except KeyError as exc:
            raise NodeNotFound(f"observation {observation_id}") from exc

    def events(self) -> tuple[MutationEvent, ...]:
        return tuple(self._events)

    def evidence_records(self) -> tuple[Evidence, ...]:
        return tuple(sorted(self._evidence.values(), key=lambda item: item.id))

    def artifact_records(self) -> tuple[Artifact, ...]:
        return tuple(sorted(self._artifacts.values(), key=lambda item: item.id))

    def observation_records(self) -> tuple[Observation, ...]:
        return tuple(sorted(self._observations.values(), key=lambda item: item.id))
