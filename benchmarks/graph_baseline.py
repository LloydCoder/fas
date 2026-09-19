"""Repeatable Phase 2 engineering baseline benchmark.

Run with:
    python benchmarks/graph_baseline.py
The script reports measured wall-clock times and does not encode pass/fail
performance claims.
"""

from __future__ import annotations

from time import perf_counter

from fas.domain.common import EvidenceType, GraphNodeType, Provenance, ProvenanceCategory, ProvenanceLevel, RelationshipType, new_id
from fas.domain.evidence import Evidence
from fas.graph import GraphBuilder, GraphEngine


def build_graph(node_count: int, edge_count: int) -> GraphEngine:
    analysis_id = new_id("analysis")
    snapshot_id = new_id("snapshot")
    provenance = Provenance(
        category=ProvenanceCategory.TOOL_OBSERVATION,
        level=ProvenanceLevel.T2,
        collector="benchmark",
        method="synthetic",
        source="benchmarks/graph_baseline.py",
        observed_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
    )
    engine = GraphEngine(analysis_id=analysis_id, snapshot_id=snapshot_id)
    evidence = Evidence(
        id=new_id("evidence"),
        analysis_id=analysis_id,
        snapshot_id=snapshot_id,
        type=EvidenceType.CODE,
        claim="synthetic benchmark evidence",
        provenance=(provenance,),
        observed_at=provenance.observed_at,
    )
    engine.add_evidence(evidence)
    nodes = [
        GraphBuilder.make_node(
            analysis_id=analysis_id,
            snapshot_id=snapshot_id,
            node_type=GraphNodeType.SYMBOL,
            canonical_identity=f"symbol-{index}",
            label=f"symbol-{index}",
            provenance=(provenance,),
            evidence_ids=(evidence.id,),
        )
        for index in range(node_count)
    ]
    engine.add_nodes(nodes)
    for index in range(edge_count):
        source = nodes[index % node_count]
        target = nodes[((index % node_count) + (index // node_count) + 1) % node_count]
        if source.id == target.id:
            continue
        engine.merge_edge_evidence(GraphBuilder.make_edge(
            analysis_id=analysis_id,
            snapshot_id=snapshot_id,
            source_node_id=source.id,
            target_node_id=target.id,
            relationship_type=RelationshipType.CALLS,
            provenance=(provenance,),
            evidence_ids=(evidence.id,),
            observed_at=provenance.observed_at,
        ))
    return engine


def benchmark(node_count: int, edge_count: int) -> None:
    started = perf_counter()
    engine = build_graph(node_count, edge_count)
    insertion = perf_counter() - started
    start = engine.nodes()[0].id
    started = perf_counter()
    engine.neighborhood(start, depth=3)
    neighborhood = perf_counter() - started
    started = perf_counter()
    engine.traverse(start, max_depth=6)
    traversal = perf_counter() - started
    started = perf_counter()
    engine.shortest_path(start, engine.nodes()[-1].id, max_depth=12)
    shortest = perf_counter() - started
    started = perf_counter()
    payload = engine.to_json()
    round_trip = perf_counter() - started
    other = GraphEngine.from_json(payload)
    removable = other.edges()[-1]
    other.remove_edge(removable.id)
    started = perf_counter()
    GraphEngine.diff(engine, other)
    diff = perf_counter() - started
    print(
        f"{node_count} nodes / {edge_count} edges: "
        f"build={insertion:.6f}s neighborhood={neighborhood:.6f}s "
        f"traversal={traversal:.6f}s shortest={shortest:.6f}s "
        f"serialize={round_trip:.6f}s diff={diff:.6f}s bytes={len(payload)}"
    )


if __name__ == "__main__":
    for nodes, edges in ((100, 300), (1000, 5000), (10000, 50000)):
        benchmark(nodes, edges)
