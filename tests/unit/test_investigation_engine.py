from datetime import timezone, datetime
import pytest
from fas.domain import (
Evidence, EvidenceType, Finding, FindingStatus, GraphEdge, GraphNode,
    GraphNodeType, Provenance, ProvenanceCategory, ProvenanceLevel, RelationshipType,
    Severity, new_id,
)
from fas.investigation import InvestigationEngine, DeterministicFakeModel, InvestigatorRequest
from fas.investigation.engine import SnapshotScopeError, UnauthorizedInvestigatorTool
from fas.graph import GraphEngine

def prov():
    return Provenance(category=ProvenanceCategory.TOOL_OBSERVATION,level=ProvenanceLevel.T2,
        collector="fixture",method="fixture",source="tests",observed_at=datetime.now(timezone.utc))

def build_graph():
    analysis=new_id("analysis"); snapshot=new_id("snapshot")
    graph=GraphEngine(analysis_id=analysis,snapshot_id=snapshot,complete=True)
    ev=Evidence(id=new_id("evidence"),analysis_id=analysis,snapshot_id=snapshot,type=EvidenceType.DATA_FLOW,
        claim="attacker-controlled input reaches sink",observed_value={"attacker_controlled":True},
        provenance=(prov(),),observed_at=datetime.now(timezone.utc))
    source=GraphNode(id=new_id("node"),type=GraphNodeType.ENDPOINT,label="POST /input",analysis_id=analysis,snapshot_id=snapshot,
        canonical_identity="endpoint:input",evidence_ids=(ev.id,),provenance=(prov(),),security_relevant=True)
    sink=GraphNode(id=new_id("node"),type=GraphNodeType.SYMBOL,label="exec",analysis_id=analysis,snapshot_id=snapshot,
        canonical_identity="symbol:exec",evidence_ids=(ev.id,),provenance=(prov(),),security_relevant=True)
    edge=GraphEdge(id=new_id("edge"),source_node_id=source.id,target_node_id=sink.id,relationship_type=RelationshipType.FLOWS_TO,
        analysis_id=analysis,snapshot_id=snapshot,evidence_ids=(ev.id,),provenance=(prov(),),observed_at=datetime.now(timezone.utc),security_relevant=True)
    graph.add_evidence(ev); graph.add_node(source); graph.add_node(sink); graph.add_edge(edge)
    finding=Finding(id=new_id("finding"),title="Command injection",category="INJECTION",severity=Severity.HIGH,
        status=FindingStatus.CANDIDATE,supporting_evidence_ids=(ev.id,),snapshot_id=snapshot,
        created_at=datetime.now(timezone.utc),updated_at=datetime.now(timezone.utc))
    return graph,finding,ev

def test_investigation_produces_evidence_backed_exploitable_proposal():
    graph,finding,ev=build_graph()
    engine=InvestigationEngine(graph=graph)
    case=engine.create_case(finding=finding,objective="determine exploitability")
    primitive=engine.primitives(case,finding)
    symbol_id=next(n.id for n in graph.nodes() if n.type==GraphNodeType.SYMBOL)
    endpoint_id=next(n.id for n in graph.nodes() if n.type==GraphNodeType.ENDPOINT)
    result=primitive.find_attack_paths(endpoint_id,symbol_id)
    assert result.evidence_ids==(ev.id,)
    path=graph.bounded_paths(endpoint_id,symbol_id).paths[0]
    attack=engine.reconstruct_attack_path(primitive.ctx,path)
    analysis=engine.analyze_exploitability(primitive.ctx,attack)
    final=engine.complete(primitive.ctx,analysis,attack_path=attack,rationale="Evidence establishes attacker-controlled data flow to the sink.")
    assert final.verdict_proposal is not None
    assert final.verdict_proposal.verdict=="EXPLOITABLE"
    assert ev.id in final.verdict_proposal.supporting_evidence_ids

def test_cross_snapshot_investigation_is_rejected():
    graph,finding,_=build_graph()
    other=finding.model_copy(update={"snapshot_id":new_id("snapshot")})
    with pytest.raises(SnapshotScopeError):
        InvestigationEngine(graph=graph).create_case(finding=other,objective="scope")

def test_arbitrary_tool_is_denied():
    graph,finding,_=build_graph()
    engine=InvestigationEngine(graph=graph)
    case=engine.create_case(finding=finding,objective="security")
    primitive=engine.primitives(case,finding)
    with pytest.raises(UnauthorizedInvestigatorTool):
        primitive._call("shell",{})

def test_fake_model_is_structured_and_llm_free():
    model=DeterministicFakeModel()
    response=model.request(InvestigatorRequest(prompt_version="phase4-v1",objective="test"),timeout_seconds=1)
    assert response.kind=="hypothesis"
    assert response.tool_calls==()


def test_missing_attacker_evidence_produces_unknown():
    graph,finding,ev=build_graph()
    plain=ev.model_copy(update={"observed_value":{"signal":"scanner"}})
    graph.store.register_evidence(plain)
    endpoint=next(n.id for n in graph.nodes() if n.type==GraphNodeType.ENDPOINT)
    sink=next(n.id for n in graph.nodes() if n.type==GraphNodeType.SYMBOL)
    case=InvestigationEngine(graph=graph).create_case(finding=finding.model_copy(update={"supporting_evidence_ids":(plain.id,)}),objective="uncertainty")
    engine=InvestigationEngine(graph=graph)
    primitive=engine.primitives(case,finding.model_copy(update={"supporting_evidence_ids":(plain.id,)}))
    path=graph.bounded_paths(endpoint,sink).paths[0]
    attack=engine.reconstruct_attack_path(primitive.ctx,path)
    analysis=engine.analyze_exploitability(primitive.ctx,attack)
    assert "attacker influence is not deterministically established" in analysis.missing_evidence
