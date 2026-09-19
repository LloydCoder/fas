def test_fake_model_is_structured_and_llm_free():
    model=DeterministicFakeModel()
    response=model.request(InvestigatorRequest(prompt_version="phase4-v1",objective="test"),timeout_seconds=1)
    assert response.kind=="hypothesis"
    assert response.tool_calls==()


def test_missing_attacker_evidence_produces_unknown():
    graph,finding,ev=build_graph()
    plain=ev.model_copy(update={"id":new_id("evidence"),"observed_value":{"signal":"scanner"}})
    graph.store.register_evidence(plain)
    endpoint=next(n.id for n in graph.nodes() if n.type==GraphNodeType.ENDPOINT)
    sink=next(n.id for n in graph.nodes() if n.type==GraphNodeType.SYMBOL)
    source_node=graph.get_node(endpoint)
    sink_node=graph.get_node(sink)
    graph.upsert_node(source_node.model_copy(update={"evidence_ids":(plain.id,),"provenance":plain.provenance}))
    graph.upsert_node(sink_node.model_copy(update={"evidence_ids":(plain.id,),"provenance":plain.provenance}))
    for path_edge in graph.get_edges_between(endpoint,sink):
        graph.merge_edge_evidence(path_edge.model_copy(update={"evidence_ids":(plain.id,),"provenance":plain.provenance}))
    case=InvestigationEngine(graph=graph).create_case(finding=finding.model_copy(update={"supporting_evidence_ids":(plain.id,)}),objective="uncertainty")
    engine=InvestigationEngine(graph=graph)
    primitive=engine.primitives(case,finding.model_copy(update={"supporting_evidence_ids":(plain.id,)}))
    path=graph.bounded_paths(endpoint,sink).paths[0]
    attack=engine.reconstruct_attack_path(primitive.ctx,path)
    analysis=engine.analyze_exploitability(primitive.ctx,attack)
    assert "attacker influence is not deterministically established" in analysis.missing_evidence