from datetime import datetime, timezone

from fas.domain import (
    ContentHash, Evidence, EvidenceType, Finding, FindingStatus, GraphEdge, GraphNode,
    GraphNodeType, Provenance, ProvenanceCategory, ProvenanceLevel, RelationshipType,
    RepositoryReference, Severity, Snapshot, new_id,
)
from fas.graph import GraphEngine
from fas.investigation import InvestigationEngine
from fas.verification import VerificationEngine


def test_phase5_end_to_end_without_llm():
    now=datetime.now(timezone.utc)
    analysis=new_id("analysis")
    original=Snapshot(id=new_id("snapshot"),repository=RepositoryReference(repository="e2e",revision="before"),
        captured_at=now,content_hash=ContentHash(digest="a"*64),source_reference="fixture:before",immutable=True)
    candidate=Snapshot(id=new_id("snapshot"),repository=RepositoryReference(repository="e2e",revision="after"),
        captured_at=now,content_hash=ContentHash(digest="b"*64),source_reference="fixture:after",immutable=True)
    prov=Provenance(category=ProvenanceCategory.TOOL_OBSERVATION,level=ProvenanceLevel.T2,
        collector="e2e",method="fixture",source="tests",observed_at=now)
    ev=Evidence(id=new_id("evidence"),analysis_id=analysis,snapshot_id=original.id,type=EvidenceType.DATA_FLOW,
        claim="attacker input reaches shell",observed_value={"attacker_controlled":True},provenance=(prov,),observed_at=now)
    bg=GraphEngine(analysis_id=analysis,snapshot_id=original.id,complete=True); bg.add_evidence(ev)
    src=GraphNode(id=new_id("node"),type=GraphNodeType.REQUEST,label="Internet",analysis_id=analysis,snapshot_id=original.id,
        canonical_identity="request:internet",evidence_ids=(ev.id,),provenance=(prov,))
    sink=GraphNode(id=new_id("node"),type=GraphNodeType.SYMBOL,label="shell.exec",analysis_id=analysis,snapshot_id=original.id,
        canonical_identity="symbol:shell",evidence_ids=(ev.id,),provenance=(prov,),metadata={"sink":"shell","impact":"command_execution"})
    edge=GraphEdge(id=new_id("edge"),source_node_id=src.id,target_node_id=sink.id,relationship_type=RelationshipType.FLOWS_TO,
        analysis_id=analysis,snapshot_id=original.id,evidence_ids=(ev.id,),provenance=(prov,),observed_at=now)
    bg.add_node(src); bg.add_node(sink); bg.add_edge(edge)
    finding=Finding(id=new_id("finding"),title="command injection",category="INJECTION",severity=Severity.HIGH,
        status=FindingStatus.VERIFIED,supporting_evidence_ids=(ev.id,),snapshot_id=original.id,created_at=now,updated_at=now)

    case=InvestigationEngine(graph=bg).create_case(finding=finding,objective="verify exploitability")
    primitive=InvestigationEngine(graph=bg).primitives(case,finding)
    path=bg.bounded_paths(src.id,sink.id).paths[0]
    attack=InvestigationEngine(graph=bg).reconstruct_attack_path(primitive.ctx,path)
    assert attack.snapshot_id==original.id

    cg=GraphEngine(analysis_id=analysis,snapshot_id=candidate.id,complete=True)
    cev=Evidence(id=new_id("evidence"),analysis_id=analysis,snapshot_id=candidate.id,type=EvidenceType.CODE,
        claim="safe execution",observed_value={"sanitized":True},provenance=(prov,),observed_at=now)
    cs=GraphNode(id=new_id("node"),type=GraphNodeType.REQUEST,label="Internet",analysis_id=analysis,snapshot_id=candidate.id,
        canonical_identity="request:internet",evidence_ids=(cev.id,),provenance=(prov,))
    cg.add_evidence(cev); cg.add_node(cs)
    remediation={
        "id":new_id("remediation"),"finding_id":finding.id,"analysis_id":analysis,
        "original_snapshot_id":original.id,"target_snapshot_id":candidate.id,
        "type":"CODE_CHANGE","description":"replace shell execution","root_cause":"unsafe data flow",
        "expected_security_property":"Attacker-controlled input must not reach shell execution.",
    }
    from fas.domain.verification import Remediation
    rem=Remediation.model_validate(remediation)
    out=VerificationEngine().verify(
        finding=finding,remediation=rem,original_snapshot=original,candidate_snapshot=candidate,
        original_graph=bg,candidate_graph=cg,original_paths=(attack,),
    )
    assert out.result.result.value=="REMEDIATED"
    assert out.baseline is not None
