from tests.fixtures.graph.conftest import add_evidence, add_node

from fas.domain.common import GraphNodeType, RelationshipType
from fas.graph import (
    GraphBuilder,
    GraphEngine,
    GraphLimits,
    ResultStatus,
    stable_id,
    TraversalDirection,
)
from fas.graph.errors import (
    DuplicateNode,
    GraphSealedError,
    SnapshotMismatch,
)


def test_insert_lookup_and_direction(engine, context, provenance):
    evidence = add_evidence(engine, context, provenance)
    source = add_node(
        engine, context, provenance, node_type=GraphNodeType.ENDPOINT, identity="/fetch", evidence=evidence
    )
    target = __import__("conftest").add_node(
        engine, context, provenance, node_type=GraphNodeType.SYMBOL, identity="fetch", evidence=evidence
    )
    engine.add_node(source)
    engine.add_node(target)
    edge = GraphBuilder.make_edge(
        analysis_id=context["analysis"],
        snapshot_id=context["snapshot"],
        source_node_id=source.id,
        target_node_id=target.id,
        relationship_type=RelationshipType.INVOKES,
        provenance=(provenance,),
        evidence_ids=(evidence.id,),
        security_relevant=True,
    )
    engine.add_edge(edge)
    assert engine.get_node(source.id) == source
    assert engine.get_edge(edge.id) == edge
    assert engine.successors(source.id) == (target,)
    assert engine.predecessors(target.id) == (source,)
    assert engine.incoming_edges(target.id) == (edge,)
    assert engine.outgoing_edges(source.id) == (edge,)
    assert engine.neighbors(source.id, TraversalDirection.OUTBOUND) == (target,)


def test_multigraph_and_merge_preserve_evidence(engine, context, provenance):
    evidence_a = __import__("conftest").add_evidence(engine, context, provenance, claim="collector A")
    evidence_b = __import__("conftest").add_evidence(engine, context, provenance, claim="collector B")
    source = __import__("conftest").add_node(
        engine, context, provenance, node_type=GraphNodeType.SYMBOL, identity="a", evidence=evidence_a
    )
    target = __import__("conftest").add_node(
        engine, context, provenance, node_type=GraphNodeType.SYMBOL, identity="b", evidence=evidence_a
    )
    engine.add_node(source)
    engine.add_node(target)
    first = GraphBuilder.make_edge(
        analysis_id=context["analysis"], snapshot_id=context["snapshot"],
        source_node_id=source.id, target_node_id=target.id,
        relationship_type=RelationshipType.CALLS, provenance=(provenance,),
        evidence_ids=(evidence_a.id,), security_relevant=True,
    )
    second = first.model_copy(update={"id": stable_id("edge", "alternate"), "evidence_ids": (evidence_b.id,)})
    engine.add_edge(first)
    merged = engine.merge_edge_evidence(second)
    assert set(merged.evidence_ids) == {evidence_a.id, evidence_b.id}
    assert len(engine.get_edges_between(source.id, target.id)) == 1
    other = GraphBuilder.make_edge(
        analysis_id=context["analysis"], snapshot_id=context["snapshot"],
        source_node_id=source.id, target_node_id=target.id,
        relationship_type=RelationshipType.FLOWS_TO, provenance=(provenance,),
        evidence_ids=(evidence_b.id,), security_relevant=True,
    )
    engine.add_edge(other)
    assert len(engine.get_edges_between(source.id, target.id)) == 2


def test_bounded_traversal_and_deterministic_shortest_path(engine, context, provenance):
    evidence = __import__("conftest").add_evidence(engine, context, provenance)
    nodes = []
    for identity in ("a", "b", "c", "d"):
        node = __import__("conftest").add_node(
            engine, context, provenance, node_type=GraphNodeType.SYMBOL, identity=identity, evidence=evidence
        )
        engine.add_node(node)
        nodes.append(node)
    for left, right in __import__("itertools").pairwise(nodes):
        engine.add_edge(GraphBuilder.make_edge(
            analysis_id=context["analysis"], snapshot_id=context["snapshot"],
            source_node_id=left.id, target_node_id=right.id,
            relationship_type=RelationshipType.CALLS, provenance=(provenance,),
            evidence_ids=(evidence.id,),
        ))
    traversal = engine.traverse(nodes[0].id, max_depth=2)
    assert traversal.node_ids == tuple(sorted(node.id for node in nodes[:3]))
    assert traversal.status == ResultStatus.PARTIAL
    path = engine.shortest_path(nodes[0].id, nodes[3].id)
    assert len(path.paths) == 1
    assert [node.label for node in path.paths[0].nodes] == ["a", "b", "c", "d"]


def test_path_enumeration_reports_truncation(engine, context, provenance):
    evidence = __import__("conftest").add_evidence(engine, context, provenance)
    nodes = []
    for identity in ("s", "a", "b", "t"):
        node = __import__("conftest").add_node(
            engine, context, provenance, node_type=GraphNodeType.SYMBOL, identity=identity, evidence=evidence
        )
        engine.add_node(node)
        nodes.append(node)
    for middle in nodes[1:3]:
        engine.add_edge(GraphBuilder.make_edge(
            analysis_id=context["analysis"], snapshot_id=context["snapshot"],
            source_node_id=nodes[0].id, target_node_id=middle.id,
            relationship_type=RelationshipType.FLOWS_TO, provenance=(provenance,),
            evidence_ids=(evidence.id,),
        ))
        engine.add_edge(GraphBuilder.make_edge(
            analysis_id=context["analysis"], snapshot_id=context["snapshot"],
            source_node_id=middle.id, target_node_id=nodes[-1].id,
            relationship_type=RelationshipType.FLOWS_TO, provenance=(provenance,),
            evidence_ids=(evidence.id,),
        ))
    result = engine.bounded_paths(nodes[0].id, nodes[-1].id, max_paths=1, max_depth=3)
    assert result.status == ResultStatus.TRUNCATED
    assert len(result.paths) == 1


def test_scc_cycle_and_components(engine, context, provenance):
    evidence = __import__("conftest").add_evidence(engine, context, provenance)
    nodes = []
    for identity in ("a", "b", "isolated"):
        node = __import__("conftest").add_node(
            engine, context, provenance, node_type=GraphNodeType.SYMBOL, identity=identity, evidence=evidence
        )
        engine.add_node(node)
        nodes.append(node)
    a, b, _ = nodes
    for source, target in ((a, b), (b, a)):
        engine.add_edge(GraphBuilder.make_edge(
            analysis_id=context["analysis"], snapshot_id=context["snapshot"],
            source_node_id=source.id, target_node_id=target.id,
            relationship_type=RelationshipType.CALLS, provenance=(provenance,),
            evidence_ids=(evidence.id,),
        ))
    assert engine.detect_cycles() == (tuple(sorted((a.id, b.id))),)
    assert len(engine.connected_components()) == 2


def test_snapshot_isolation(engine, context, provenance):
    evidence = __import__("conftest").add_evidence(engine, context, provenance)
    node = __import__("conftest").add_node(
        engine, context, provenance, node_type=GraphNodeType.SYMBOL, identity="a", evidence=evidence
    )
    engine.add_node(node)
    other = node.model_copy(update={"snapshot_id": context["other_snapshot"]})
    with __import__("pytest").raises(SnapshotMismatch):
        engine.add_node(other)


def test_sealed_graph_is_read_only(engine, context, provenance):
    evidence = __import__("conftest").add_evidence(engine, context, provenance)
    node = __import__("conftest").add_node(
        engine, context, provenance, node_type=GraphNodeType.SYMBOL, identity="a", evidence=evidence
    )
    engine.add_node(node)
    view = engine.seal()
    assert view.get_node(node.id) == node
    with __import__("pytest").raises(GraphSealedError):
        engine.add_node(node.model_copy(update={"id": stable_id("node", "new")}))


def test_duplicate_semantic_nodes_are_rejected(engine, context, provenance):
    evidence = __import__("conftest").add_evidence(engine, context, provenance)
    node = __import__("conftest").add_node(
        engine, context, provenance, node_type=GraphNodeType.SYMBOL, identity="a", evidence=evidence
    )
    engine.add_node(node)
    with __import__("pytest").raises(DuplicateNode):
        engine.add_node(node.model_copy(update={"id": stable_id("node", "different")}))


def test_security_edge_evidence_is_queryable(engine, context, provenance):
    evidence = __import__("conftest").add_evidence(engine, context, provenance)
    source = __import__("conftest").add_node(
        engine, context, provenance, node_type=GraphNodeType.AGENT, identity="agent", evidence=evidence
    )
    target = __import__("conftest").add_node(
        engine, context, provenance, node_type=GraphNodeType.TOOL, identity="tool", evidence=evidence
    )
    engine.add_nodes((source, target))
    edge = GraphBuilder.make_edge(
        analysis_id=context["analysis"], snapshot_id=context["snapshot"],
        source_node_id=source.id, target_node_id=target.id,
        relationship_type=RelationshipType.CAN_USE, provenance=(provenance,),
        evidence_ids=(evidence.id,), security_relevant=True,
    )
    engine.add_edge(edge)
    assert engine.get_edge_evidence(edge.id)[0].id == evidence.id
    assert engine.get_edge_provenance(edge.id)[0] == provenance


def test_recursive_self_loop_is_representable(engine, context, provenance):
    from tests.fixtures.graph.conftest import add_evidence, add_node

    evidence = add_evidence(engine, context, provenance, claim="recursive call")
    node = add_node(engine, context, provenance, node_type=GraphNodeType.SYMBOL, identity="recursive", evidence=evidence)
    engine.add_node(node)
    edge = GraphBuilder.make_edge(
        analysis_id=context["analysis"], snapshot_id=context["snapshot"],
        source_node_id=node.id, target_node_id=node.id,
        relationship_type=RelationshipType.CALLS, provenance=(provenance,),
        evidence_ids=(evidence.id,),
    )
    engine.add_edge(edge)
    assert engine.get_edge(edge.id).source_node_id == engine.get_edge(edge.id).target_node_id
    assert engine.detect_cycles() == ((node.id,),)


def test_result_size_and_cancellation_limits(context, provenance):
    from tests.fixtures.graph.conftest import add_evidence, add_node

    engine = GraphEngine(
        analysis_id=context["analysis"], snapshot_id=context["snapshot"],
        limits=GraphLimits(max_result_size=2, max_traversal_depth=8, max_nodes_visited=10, max_edges_visited=10, max_paths=5, max_path_depth=8),
    )
    evidence = add_evidence(engine, context, provenance)
    nodes = [add_node(engine, context, provenance, node_type=GraphNodeType.SYMBOL, identity=str(i), evidence=evidence) for i in range(3)]
    engine.add_nodes(nodes)
    result = engine.subgraph([node.id for node in nodes])
    assert result.status == ResultStatus.TRUNCATED
    cancelled = engine.traverse(nodes[0].id, cancellation_check=lambda: True)
    assert cancelled.status == ResultStatus.TRUNCATED


def test_same_snapshot_graph_merge_accumulates_relationship_evidence(context, provenance):
    engine_a = GraphEngine(analysis_id=context["analysis"], snapshot_id=context["snapshot"])
    engine_b = GraphEngine(analysis_id=context["analysis"], snapshot_id=context["snapshot"])
    evidence_a = add_evidence(engine_a, context, provenance, claim="source A")
    evidence_b = add_evidence(engine_b, context, provenance, claim="source B")
    source = add_node(engine_a, context, provenance, node_type=GraphNodeType.SYMBOL, identity="source", evidence=evidence_a)
    target = add_node(engine_a, context, provenance, node_type=GraphNodeType.SYMBOL, identity="target", evidence=evidence_a)
    engine_a.add_nodes((source, target))
    edge_a = GraphBuilder.make_edge(
        analysis_id=context["analysis"], snapshot_id=context["snapshot"],
        source_node_id=source.id, target_node_id=target.id,
        relationship_type=RelationshipType.CALLS, provenance=(provenance,),
        evidence_ids=(evidence_a.id,), observed_at=provenance.observed_at,
    )
    engine_a.add_edge(edge_a)
    source_b = source.model_copy(update={"evidence_ids": (evidence_b.id,)})
    target_b = target.model_copy(update={"evidence_ids": (evidence_b.id,)})
    engine_b.add_nodes((source_b, target_b))
    edge = GraphBuilder.make_edge(
        analysis_id=context["analysis"], snapshot_id=context["snapshot"],
        source_node_id=source.id, target_node_id=target.id,
        relationship_type=RelationshipType.CALLS, provenance=(provenance,),
        evidence_ids=(evidence_b.id,), observed_at=provenance.observed_at,
    )
    engine_b.add_edge(edge)
    engine_a.merge_graph(engine_b)
    assert set(engine_a.get_edge_evidence(edge.id)) == {evidence_a, evidence_b}
