from datetime import datetime, timezone
from fas.domain import (
    AttackPath, AttackPathStep, ContentHash, Evidence, EvidenceType, Finding, FindingStatus,
    GraphEdge, GraphNode, GraphNodeType, Provenance, ProvenanceCategory, ProvenanceLevel,
    RelationshipType, Remediation, RemediationType, RepositoryReference, Severity, Snapshot,
    new_id,
)
from fas.graph import GraphEngine
from fas.verification import DeterministicSecurityTestExecutor, VerificationEngine
from fas.domain.verification import SecurityTestDefinition


NOW=datetime.now(timezone.utc)


def snapshot(analysis_id, revision):
    return Snapshot(
        id=new_id("snapshot"),
        repository=RepositoryReference(repository="fixture/repo",revision=revision),
        captured_at=NOW,
        content_hash=ContentHash(digest=(revision*64)[:64]),
        source_reference=f"fixture:{revision}",
        immutable=True,
    )


def evidence(analysis_id, snap, claim, value=None):
    eid=new_id("evidence")
    return Evidence(
        id=eid,analysis_id=analysis_id,snapshot_id=snap.id,type=EvidenceType.DATA_FLOW,
        claim=claim,observed_value=value,
        provenance=(Provenance(category=ProvenanceCategory.TOOL_OBSERVATION,level=ProvenanceLevel.T2,
            collector="fixture",method="fixture",source="tests",observed_at=NOW),),
        observed_at=NOW,
    )


def node(analysis_id,snap,kind,identity,label,ev,**metadata):
    return GraphNode(
        id=new_id("node"),type=kind,label=label,analysis_id=analysis_id,snapshot_id=snap.id,
        canonical_identity=identity,evidence_ids=(ev.id,),
        provenance=ev.provenance,metadata=metadata,
    )


def edge(analysis_id,snap,source,target,ev,relationship=RelationshipType.FLOWS_TO,**metadata):
    return GraphEdge(
        id=new_id("edge"),source_node_id=source.id,target_node_id=target.id,
        relationship_type=relationship,analysis_id=analysis_id,snapshot_id=snap.id,
        provenance=ev.provenance,evidence_ids=(ev.id,),observed_at=NOW,metadata=metadata,
    )


def build_graph(analysis_id,snap,alternate=False,permission_widened=False,complete=True,permission_action=None):
    g=GraphEngine(analysis_id=analysis_id,snapshot_id=snap.id,complete=complete)
    src_ev=evidence(analysis_id,snap,"attacker controls request",{"attacker_controlled":True})
    ep_ev=evidence(analysis_id,snap,"request reaches endpoint")
    sink_ev=evidence(analysis_id,snap,"shell execution sink")
    src=node(analysis_id,snap,GraphNodeType.REQUEST,"internet","Internet",src_ev,source="attacker")
    ep=node(analysis_id,snap,GraphNodeType.ENDPOINT,"/webhook" if not alternate else "/api/import","Webhook",ep_ev)
    sink=node(analysis_id,snap,GraphNodeType.SYMBOL,"shell.exec","shell.exec",sink_ev,sink="shell",impact="command_execution")
    for e in (src_ev,ep_ev,sink_ev): g.add_evidence(e)
    for n in (src,ep,sink): g.add_node(n)
    g.add_edge(edge(analysis_id,snap,src,ep,src_ev))
    if not alternate:
        g.add_edge(edge(analysis_id,snap,ep,sink,sink_ev))
    else:
        g.add_edge(edge(analysis_id,snap,ep,sink,sink_ev))
    if permission_widened or permission_action is not None:
        pev=evidence(analysis_id,snap,"production permission")
        p=node(analysis_id,snap,GraphNodeType.PERMISSION,"prod-write","prod-write",pev,
               principal="agent",action=permission_action or "write",resource="production",security_property="agent must not deploy production")
g.add_evidence(pev)\ng.add_node(p)
    return g, (src,ep,sink)


def finding(analysis_id,snap,ev):
    return Finding(
        id=new_id("finding"),title="Command injection",category="command-injection",severity=Severity.HIGH,
        status=FindingStatus.VERIFIED,supporting_evidence_ids=(ev.id,),snapshot_id=snap.id,
        created_at=NOW,updated_at=NOW,
    )


def remediation(analysis_id,f,snap):
    return Remediation(
        id=new_id("remediation"),finding_id=f.id,analysis_id=analysis_id,
        original_snapshot_id=snap.id,type=RemediationType.CODE_CHANGE,
        description="Replace shell execution with safe execution",root_cause="unsafe data flow",
        expected_security_property="Attacker-controlled input must not reach shell execution.",
        status="READY_FOR_VERIFICATION",
    )


def original_attack_path(analysis_id,snap,graph,nodes):
    src,ep,sink=nodes
    return AttackPath(
        id=new_id("attack_path"),entry=src.id,
        steps=(
            AttackPathStep(node_id=src.id,edge_id=graph.get_edges_between(src.id,ep.id)[0].id,next_node_id=ep.id,evidence_ids=src and graph.get_edge(graph.get_edges_between(src.id,ep.id)[0].id).evidence_ids),
            AttackPathStep(node_id=ep.id,edge_id=graph.get_edges_between(ep.id,sink.id)[0].id,next_node_id=sink.id,evidence_ids=graph.get_edges_between(ep.id,sink.id)[0].evidence_ids),
        ),
        supporting_evidence_ids=tuple(sorted(set(graph.get_edge(graph.get_edges_between(src.id,ep.id)[0].id).evidence_ids + graph.get_edge(graph.get_edges_between(ep.id,sink.id)[0].id).evidence_ids))),
        snapshot_id=snap.id,observed_at=NOW,
    )


def test_command_injection_remediated_when_sink_is_removed():
analysis=new_id("analysis")\nbefore=snapshot(analysis,"a"*1)\nafter=snapshot(analysis,"b"*1)
    bg,nodes=build_graph(analysis,before)
    cg,cnodes=build_graph(analysis,after)
    # remove the dangerous sink and incoming edge from the candidate.
    cg.remove_edge(cg.get_edges_between(cnodes[1].id,cnodes[2].id)[0].id)
    cg.remove_node(cnodes[2].id)
# candidate node IDs differ\nsource/endpoint semantic matching is used.
    ev=bg.get_node_evidence(nodes[0].id)[0]
    f=finding(analysis,before,ev)
    r=remediation(analysis,f,before)
    path=original_attack_path(analysis,before,bg,nodes)
    out=VerificationEngine().verify(finding=f,remediation=r,original_snapshot=before,candidate_snapshot=after,
        original_graph=bg,candidate_graph=cg,original_paths=(path,))
    assert out.result.result.value=="REMEDIATED"
    assert out.result.property_outcome.value=="ELIMINATED"


def test_scanner_disappearance_does_not_hide_alternate_sink_path():
analysis=new_id("analysis")\nbefore=snapshot(analysis,"a")\nafter=snapshot(analysis,"b")
    bg,nodes=build_graph(analysis,before)
    cg,_=build_graph(analysis,after,alternate=True)
    ev=bg.get_node_evidence(nodes[0].id)[0]
f=finding(analysis,before,ev)\nr=remediation(analysis,f,before)
    path=original_attack_path(analysis,before,bg,nodes)
    out=VerificationEngine().verify(finding=f,remediation=r,original_snapshot=before,candidate_snapshot=after,
        original_graph=bg,candidate_graph=cg,original_paths=(path,))
    assert out.result.result.value=="REMEDIATION_FAILED"
    assert out.result.alternate_path_ids


def test_incomplete_candidate_graph_returns_unknown():
analysis=new_id("analysis")\nbefore=snapshot(analysis,"a")\nafter=snapshot(analysis,"b")
bg,nodes=build_graph(analysis,before)\ncg,_=build_graph(analysis,after,complete=False)
ev=bg.get_node_evidence(nodes[0].id)[0]\nf=finding(analysis,before,ev)\nr=remediation(analysis,f,before)
    path=original_attack_path(analysis,before,bg,nodes)
    out=VerificationEngine().verify(finding=f,remediation=r,original_snapshot=before,candidate_snapshot=after,
        original_graph=bg,candidate_graph=cg,original_paths=(path,))
    assert out.result.result.value=="UNKNOWN"


def test_permission_widening_is_semantic_regression_signal():
analysis=new_id("analysis")\nbefore=snapshot(analysis,"a")\nafter=snapshot(analysis,"b")
bg,nodes=build_graph(analysis,before,permission_action="read")\ncg,_=build_graph(analysis,after,permission_action="write")
    diff=VerificationEngine().diff_engine.compare(bg,cg)
    assert diff.permission_added
    assert diff.permission_widened


def test_security_test_failure_blocks_remediation():
analysis=new_id("analysis")\nbefore=snapshot(analysis,"a")\nafter=snapshot(analysis,"b")
    bg,nodes=build_graph(analysis,before)
cg,cnodes=build_graph(analysis,after)\ncg.remove_edge(cg.get_edges_between(cnodes[1].id,cnodes[2].id)[0].id)\ncg.remove_node(cnodes[2].id)
ev=bg.get_node_evidence(nodes[0].id)[0]\nf=finding(analysis,before,ev)\nr=remediation(analysis,f,before)
    path=original_attack_path(analysis,before,bg,nodes)
    definition=SecurityTestDefinition(test_id="command-injection-regression",version="1",snapshot_id=after.id,
        security_property=r.expected_security_property,target="fixture",expected_result="blocked")
    out=VerificationEngine().verify(finding=f,remediation=r,original_snapshot=before,candidate_snapshot=after,
        original_graph=bg,candidate_graph=cg,original_paths=(path,),security_tests=(definition,),
        test_executor=DeterministicSecurityTestExecutor({"command-injection-regression":False}))
    assert out.result.result.value=="REMEDIATION_FAILED"

def test_successful_verification_establishes_regression_baseline():
analysis=new_id("analysis")\nbefore=snapshot(analysis,"a")\nafter=snapshot(analysis,"b")
    bg,nodes=build_graph(analysis,before)
cg,cnodes=build_graph(analysis,after)\ncg.remove_edge(cg.get_edges_between(cnodes[1].id,cnodes[2].id)[0].id)\ncg.remove_node(cnodes[2].id)
ev=bg.get_node_evidence(nodes[0].id)[0]\nf=finding(analysis,before,ev)\nr=remediation(analysis,f,before)
    path=original_attack_path(analysis,before,bg,nodes)
    out=VerificationEngine().verify(finding=f,remediation=r,original_snapshot=before,candidate_snapshot=after,
        original_graph=bg,candidate_graph=cg,original_paths=(path,))
    assert out.result.result.value=="REMEDIATED"
    assert out.baseline is not None

def test_agent_and_mcp_capability_differentials_are_security_relevant():
analysis=new_id("analysis")\nbefore=snapshot(analysis,"a")\nafter=snapshot(analysis,"b")
bg,_=build_graph(analysis,before)\ncg,_=build_graph(analysis,after)
    ev=evidence(analysis,before,"agent capability")
    bg.add_evidence(ev)
    agent=node(analysis,before,GraphNodeType.AGENT,"agent:worker","worker",ev,capability="deploy",principal="agent")
    bg.add_node(agent)
    cg_ev=evidence(analysis,after,"agent capability")
    cg.add_evidence(cg_ev)
    cg_agent=node(analysis,after,GraphNodeType.AGENT,"agent:worker","worker",cg_ev,capability="read",principal="agent")
    cg.add_node(cg_agent)
    m1=node(analysis,before,GraphNodeType.MCP_TOOL,"mcp:deploy","deploy",ev,authorization="allow",capability="production-write")
    m2=node(analysis,after,GraphNodeType.MCP_TOOL,"mcp:deploy","deploy",cg_ev,authorization="deny",capability="production-write")
bg.add_node(m1)\ncg.add_node(m2)
    diff=VerificationEngine().diff_engine.compare(bg,cg)
    assert diff.agent_capability_changed
    assert diff.mcp_capability_changed


def test_regression_engine_detects_reappearance_against_baseline():
    from fas.verification.regression import RegressionEngine
analysis=new_id("analysis")\nbefore=snapshot(analysis,"a")
    graph,_=build_graph(analysis,before)
    ev=graph.get_node_evidence(next(n.id for n in graph.nodes() if n.type==GraphNodeType.REQUEST))[0]
    f=finding(analysis,before,ev)
    baseline=RegressionEngine().establish_baseline(
        finding=f,verification_id=new_id("verification"),security_property="agent must not deploy production",
        snapshot=before,graph=graph,
    )
    regression=RegressionEngine().detect(baseline=baseline,current=before,graph=graph,reachable_baseline_path=True)
    assert regression.status.value=="DETECTED"
