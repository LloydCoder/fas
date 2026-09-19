"""Semantic before/after graph comparison for Phase 5."""
from __future__ import annotations

from collections import defaultdict
from hashlib import sha256

from fas.domain.common import GraphNodeType, RelationshipType, new_id
from fas.domain.graph import GraphNode
from fas.domain.verification import GraphDiff
from fas.graph import GraphEngine, GraphScopeKind


def _node_key(node: GraphNode) -> str:
    return f"{node.type.value}:{node.canonical_identity}"


def _security_signature(node: GraphNode) -> tuple[str, ...]:
    m = node.metadata
    keys = ("principal","action","resource","capability","sink","source","impact","security_property","permission","identity","authorization","effective")
    values = tuple(f"{key}={m[key]}" for key in keys if key in m)
    return (node.type.value, node.canonical_identity, *values)


def _permission_signature(node: GraphNode) -> str:
    m = node.metadata
    return "|".join([m.get("principal", node.label), m.get("action", "UNKNOWN"), m.get("resource", node.label)])


def _edge_key(graph: GraphEngine, edge) -> tuple[str, str, str]:
    source = graph.get_node(edge.source_node_id)
    target = graph.get_node(edge.target_node_id)
    return (_node_key(source), _node_key(target), edge.relationship_type.value)


def _fingerprint(values: tuple[str, ...]) -> str:
    return sha256("|".join(values).encode("utf-8")).hexdigest()


class SemanticGraphDiffEngine:
    """Compare two snapshot graphs by semantic identity, not serialized IDs."""

    def compare(self, original: GraphEngine, candidate: GraphEngine) -> GraphDiff:
        if original.scope.kind != GraphScopeKind.SNAPSHOT or candidate.scope.kind != GraphScopeKind.SNAPSHOT:
            raise ValueError("Phase 5 graph diff requires snapshot-scoped graphs")
        if original.scope.analysis_id != candidate.scope.analysis_id:
            raise ValueError("graphs must belong to the same analysis")
        if original.scope.snapshot_id == candidate.scope.snapshot_id:
            raise ValueError("graph diff requires distinct snapshots")

        before_nodes = {_node_key(n): n for n in original.nodes()}
        after_nodes = {_node_key(n): n for n in candidate.nodes()}
        modified_nodes = [
            (before_nodes[k], after_nodes[k])
            for k in sorted(before_nodes.keys() & after_nodes.keys())
            if _security_signature(before_nodes[k]) != _security_signature(after_nodes[k])
            or before_nodes[k].metadata != after_nodes[k].metadata
            or before_nodes[k].label != after_nodes[k].label
        ]

        before_edges = {_edge_key(original, e): e for e in original.edges()}
        after_edges = {_edge_key(candidate, e): e for e in candidate.edges()}
        modified_edges = [
            (before_edges[k], after_edges[k])
            for k in sorted(before_edges.keys() & after_edges.keys())
            if before_edges[k].metadata != after_edges[k].metadata
            or before_edges[k].evidence_ids != after_edges[k].evidence_ids
            or before_edges[k].provenance != after_edges[k].provenance
        ]

        before_permissions = {
            _permission_signature(n): n
            for n in original.nodes()
            if n.type in {GraphNodeType.PERMISSION, GraphNodeType.ROLE, GraphNodeType.PRINCIPAL}
        }
        after_permissions = {
            _permission_signature(n): n
            for n in candidate.nodes()
            if n.type in {GraphNodeType.PERMISSION, GraphNodeType.ROLE, GraphNodeType.PRINCIPAL}
        }

        permission_removed = tuple(sorted(set(before_permissions) - set(after_permissions)))
        permission_added = tuple(sorted(set(after_permissions) - set(before_permissions)))

        before_by_principal = defaultdict(set)
        after_by_principal = defaultdict(set)
        for n in original.nodes():
            if n.type in {GraphNodeType.PERMISSION, GraphNodeType.ROLE, GraphNodeType.PRINCIPAL}:
                before_by_principal[n.metadata.get("principal", n.label)].add(_permission_signature(n))
        for n in candidate.nodes():
            if n.type in {GraphNodeType.PERMISSION, GraphNodeType.ROLE, GraphNodeType.PRINCIPAL}:
                after_by_principal[n.metadata.get("principal", n.label)].add(_permission_signature(n))

        widened, narrowed = [], []
        for principal in sorted(set(before_by_principal) & set(after_by_principal)):
            before = before_by_principal[principal]
            after = after_by_principal[principal]
            if after > before:
                widened.append(principal)
            elif before > after:
                narrowed.append(principal)

        def changed_types(node_type: GraphNodeType) -> tuple[str, ...]:
            out=[]
            for key in sorted(before_nodes.keys() & after_nodes.keys()):
                b,a=before_nodes[key],after_nodes[key]
                if b.type == node_type and (b.metadata != a.metadata or b.label != a.label):
                    out.append(key)
            out.extend(sorted(k for k in set(before_nodes)-set(after_nodes)
                              if k.startswith(node_type.value+":")))
            out.extend(sorted(k for k in set(after_nodes)-set(before_nodes)
                              if k.startswith(node_type.value+":")))
            return tuple(sorted(set(out)))

        return GraphDiff(
            id=new_id("graph_diff"),
            analysis_id=original.scope.analysis_id,
            original_snapshot_id=original.scope.snapshot_id,
            candidate_snapshot_id=candidate.scope.snapshot_id,
            added_node_ids=tuple(sorted(after_nodes[k].id for k in set(after_nodes)-set(before_nodes))),
            removed_node_ids=tuple(sorted(before_nodes[k].id for k in set(before_nodes)-set(after_nodes))),
            modified_node_ids=tuple(sorted(a.id for _,a in modified_nodes)),
            added_edge_ids=tuple(sorted(after_edges[k].id for k in set(after_edges)-set(before_edges))),
            removed_edge_ids=tuple(sorted(before_edges[k].id for k in set(before_edges)-set(after_edges))),
            modified_edge_ids=tuple(sorted(a.id for _,a in modified_edges)),
            unchanged_node_count=len(set(before_nodes) & set(after_nodes)) - len(modified_nodes),
            unchanged_edge_count=len(set(before_edges) & set(after_edges)) - len(modified_edges),
            permission_added=permission_added,
            permission_removed=permission_removed,
            permission_widened=tuple(widened),
            permission_narrowed=tuple(narrowed),
            identity_changed=changed_types(GraphNodeType.IDENTITY),
            trust_boundary_changed=changed_types(GraphNodeType.TRUST_BOUNDARY),
            endpoint_changed=changed_types(GraphNodeType.ENDPOINT),
            tool_capability_changed=changed_types(GraphNodeType.TOOL),
            agent_capability_changed=changed_types(GraphNodeType.AGENT),
            credential_changed=changed_types(GraphNodeType.CREDENTIAL),
            dataflow_changed=tuple(sorted({
                *(_edge_key(original,e)[2]+":"+_edge_key(original,e)[0]+"->"+_edge_key(original,e)[1]
                  for e in original.edges() if e.relationship_type == RelationshipType.FLOWS_TO),
            } ^ {
                *(_edge_key(candidate,e)[2]+":"+_edge_key(candidate,e)[0]+"->"+_edge_key(candidate,e)[1]
                  for e in candidate.edges() if e.relationship_type == RelationshipType.FLOWS_TO),
            })),
            control_changed=changed_types(GraphNodeType.CONTROL),
            dependency_changed=changed_types(GraphNodeType.DEPENDENCY),
        )
