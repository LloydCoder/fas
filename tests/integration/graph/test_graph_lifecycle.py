from fas.domain.common import GraphNodeType, RelationshipType
from fas.graph import GraphBuilder, GraphEngine, ResultStatus


def test_phase1_to_graph_to_sealed_view_to_round_trip(engine, context, provenance):
    from tests.fixtures.graph.conftest import add_evidence, add_node

    evidence = add_evidence(engine, context, provenance, claim="endpoint calls function")
    endpoint = add_node(
        engine, context, provenance, node_type=GraphNodeType.ENDPOINT, identity="/fetch", evidence=evidence
    )
    function = add_node(
        engine, context, provenance, node_type=GraphNodeType.SYMBOL, identity="fetch_url", evidence=evidence
    )
    engine.add_nodes((endpoint, function))
    engine.add_edge(GraphBuilder.make_edge(
        analysis_id=context["analysis"], snapshot_id=context["snapshot"],
        source_node_id=endpoint.id, target_node_id=function.id,
        relationship_type=RelationshipType.INVOKES, provenance=(provenance,),
        evidence_ids=(evidence.id,), security_relevant=True,
    ))
    view = engine.seal(complete=True)
    assert view.complete is True
    assert view.shortest_path(endpoint.id, function.id).status == ResultStatus.COMPLETE
    restored = GraphEngine.from_json(view.to_json())
    assert restored.to_json() == view.to_json()


def test_graph_diff_tracks_structural_changes(engine, context, provenance):
    from tests.fixtures.graph.conftest import add_evidence, add_node

    evidence = add_evidence(engine, context, provenance)
    source = add_node(
        engine, context, provenance, node_type=GraphNodeType.SYMBOL, identity="source", evidence=evidence
    )
    target = add_node(
        engine, context, provenance, node_type=GraphNodeType.SYMBOL, identity="target", evidence=evidence
    )
    engine.add_nodes((source, target))
    edge = GraphBuilder.make_edge(
        analysis_id=context["analysis"], snapshot_id=context["snapshot"],
        source_node_id=source.id, target_node_id=target.id,
        relationship_type=RelationshipType.CALLS, provenance=(provenance,),
        evidence_ids=(evidence.id,),
    )
    engine.add_edge(edge)

    patched = GraphEngine.from_json(engine.to_json())
    patched.remove_edge(edge.id)
    diff = GraphEngine.diff(engine, patched)
    assert diff.removed_edges[0].id == edge.id
    assert not diff.added_edges
    assert not diff.added_nodes


def test_diff_does_not_create_cross_snapshot_traversal(engine, context, provenance):
    from tests.fixtures.graph.conftest import add_evidence, add_node

    evidence = add_evidence(engine, context, provenance)
    source = add_node(
        engine, context, provenance, node_type=GraphNodeType.SYMBOL, identity="source", evidence=evidence
    )
    engine.add_node(source)
    patched = GraphEngine(
        analysis_id=context["analysis"],
        snapshot_id=context["other_snapshot"],
    )
    other = source.model_copy(update={"snapshot_id": context["other_snapshot"]})
    patched.add_evidence(evidence.model_copy(update={"snapshot_id": context["other_snapshot"]}))
    patched.add_node(other)
    diff = GraphEngine.diff(engine, patched)
    assert diff.unchanged_nodes == ()
    assert diff.added_nodes and diff.removed_nodes
