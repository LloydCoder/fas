from datetime import datetime, timezone
from fas.analysis import AnalysisQueryEngine, QueryLimits
from fas.domain.common import GraphNodeType, Provenance, ProvenanceCategory, ProvenanceLevel, RelationshipType, new_id
from fas.domain.graph import GraphEdge, GraphNode
from fas.graph import GraphEngine, ResultStatus

def _provenance():
    return (Provenance(category=ProvenanceCategory.VERIFIED_ARTIFACT,
                       level=ProvenanceLevel.T3, source="test"),)

def _graph():
    analysis_id, snapshot_id = new_id("analysis"), new_id("snapshot")
    graph = GraphEngine(analysis_id=analysis_id, snapshot_id=snapshot_id, complete=True)
    source = GraphNode(id=new_id("node"), type=GraphNodeType.ENDPOINT, label="endpoint",
        analysis_id=analysis_id, snapshot_id=snapshot_id, canonical_identity="endpoint:test",
        provenance=_provenance())
    evidence_id = new_id("evidence")
    secret = GraphNode(id=new_id("node"), type=GraphNodeType.SECRET, label="secret",
        analysis_id=analysis_id, snapshot_id=snapshot_id, canonical_identity="secret:test",
        evidence_ids=(evidence_id,), provenance=_provenance(), security_relevant=True)
    edge = GraphEdge(id=new_id("edge"), source_node_id=source.id, target_node_id=secret.id,
        relationship_type=RelationshipType.FLOWS_TO, analysis_id=analysis_id, snapshot_id=snapshot_id,
        provenance=_provenance(), evidence_ids=(evidence_id,), observed_at=datetime.now(timezone.utc),
        security_relevant=True)
    graph.add_nodes((source, secret))
    graph.add_edge(edge)
    return graph, evidence_id

def test_node_and_edge_queries_are_deterministic():
    graph, _ = _graph()
    engine = AnalysisQueryEngine(graph)
    nodes = engine.nodes(node_types=frozenset({GraphNodeType.SECRET}))
    edges = engine.edges(relationship_types=frozenset({RelationshipType.FLOWS_TO}))
    assert nodes.status == ResultStatus.COMPLETE
    assert edges.status == ResultStatus.COMPLETE
    assert [n.id for n in nodes.nodes] == sorted(n.id for n in nodes.nodes)

def test_queries_report_truncation():
    graph, _ = _graph()
    result = AnalysisQueryEngine(graph, limits=QueryLimits(max_nodes=1, max_edges=1, max_paths=1)).nodes()
    assert result.status == ResultStatus.TRUNCATED
    assert not result.complete

def test_reachability_and_evidence_correlation():
    graph, evidence_id = _graph()
    result = AnalysisQueryEngine(graph).reachable(
        source_types=frozenset({GraphNodeType.ENDPOINT}),
        target_types=frozenset({GraphNodeType.SECRET}),
        relationships=frozenset({RelationshipType.FLOWS_TO}))
    assert result.status == ResultStatus.COMPLETE
    assert len(result.paths) == 1
    assert AnalysisQueryEngine.evidence_ids(paths=result.paths) == (evidence_id,)
