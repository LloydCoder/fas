import json

import pytest

from fas.domain.common import GraphNodeType, RelationshipType
from fas.graph import GraphBuilder, GraphEngine, ResultStatus
from fas.graph.errors import GraphInvariantViolation, SnapshotMismatch


def test_cross_snapshot_edge_injection_is_rejected(engine, context, provenance):
    from tests.fixtures.graph.conftest import add_evidence, add_node

    evidence = add_evidence(engine, context, provenance)
    first = add_node(
        engine, context, provenance, node_type=GraphNodeType.SYMBOL, identity="a", evidence=evidence
    )
    second = add_node(
        engine, context, provenance, node_type=GraphNodeType.SYMBOL, identity="b", evidence=evidence
    )
    engine.add_nodes((first, second))
    foreign = second.model_copy(update={"snapshot_id": context["other_snapshot"]})
    with pytest.raises(SnapshotMismatch):
        engine.add_node(foreign)


def test_fake_evidence_reference_cannot_enter_graph(engine, context, provenance):
    from tests.fixtures.graph.conftest import add_node

    fake = type("FakeEvidence", (), {"id": "evidence_01J00000000000000000000000"})()
    node = GraphBuilder.make_node(
        analysis_id=context["analysis"],
        snapshot_id=context["snapshot"],
        node_type=GraphNodeType.SECRET,
        canonical_identity="secret:test",
        label="secret",
        provenance=(provenance,),
        evidence_ids=(fake.id,),
        security_relevant=True,
    )
    with pytest.raises(SnapshotMismatch):
        engine.add_node(node)


def test_path_explosion_is_bounded(engine, context, provenance):
    from tests.fixtures.graph.conftest import add_evidence, add_node

    evidence = add_evidence(engine, context, provenance)
    nodes = [
        add_node(
            engine, context, provenance, node_type=GraphNodeType.SYMBOL,
            identity=f"n{i}", evidence=evidence
        )
        for i in range(8)
    ]
    engine.add_nodes(nodes)
    for index in range(1, len(nodes)):
        engine.add_edge(GraphBuilder.make_edge(
            analysis_id=context["analysis"], snapshot_id=context["snapshot"],
            source_node_id=nodes[0].id, target_node_id=nodes[index].id,
            relationship_type=RelationshipType.FLOWS_TO, provenance=(provenance,),
            evidence_ids=(evidence.id,),
        ))
        engine.add_edge(GraphBuilder.make_edge(
            analysis_id=context["analysis"], snapshot_id=context["snapshot"],
            source_node_id=nodes[index].id, target_node_id=nodes[-1].id,
            relationship_type=RelationshipType.FLOWS_TO, provenance=(provenance,),
            evidence_ids=(evidence.id,),
        ))
    result = engine.bounded_paths(nodes[0].id, nodes[-1].id, max_paths=2, max_depth=3)
    assert result.status == ResultStatus.TRUNCATED
    assert len(result.paths) == 2


def test_secret_values_are_not_introduced_by_graph_serialization(engine, context, provenance):
    from tests.fixtures.graph.conftest import add_evidence, add_node

    evidence = add_evidence(engine, context, provenance, claim="secret exists")
    node = add_node(
        engine, context, provenance, node_type=GraphNodeType.SECRET,
        identity="secret:credential-id", evidence=evidence
    )
    engine.add_node(node)
    payload = engine.to_json()
    parsed = json.loads(payload)
    assert "plaintext-secret-value" not in json.dumps(parsed)
    assert "credential-id" in payload


def test_deterministic_query_order_is_independent_of_insertion_order(context, provenance):
    from tests.fixtures.graph.conftest import add_evidence, add_node

    def build(order):
        engine = GraphEngine(
            analysis_id=context["analysis"], snapshot_id=context["snapshot"]
        )
        evidence = __import__("fas.domain.evidence").domain.evidence.Evidence(
            id=__import__("fas.domain.common").domain.common.new_id("evidence"),
            analysis_id=context["analysis"], snapshot_id=context["snapshot"],
            type=__import__("fas.domain.common").domain.common.EvidenceType.CODE,
            claim="fixture", provenance=(provenance,),
            observed_at=__import__("tests.fixtures.graph.conftest").fixtures.graph.conftest.NOW,
        )
        engine.add_evidence(evidence)
        nodes = [
            add_node(engine, context, provenance, node_type=GraphNodeType.SYMBOL, identity=name, evidence=evidence)
            for name in ("a", "b", "c")
        ]
        for index in order:
            engine.add_node(nodes[index])
        for left, right in ((0, 1), (1, 2)):
            engine.add_edge(GraphBuilder.make_edge(
                analysis_id=context["analysis"], snapshot_id=context["snapshot"],
                source_node_id=nodes[left].id, target_node_id=nodes[right].id,
                relationship_type=RelationshipType.CALLS, provenance=(provenance,),
                evidence_ids=(evidence.id,),
            ))
        return engine.to_json()
    assert build((0, 1, 2)) == build((2, 0, 1))
