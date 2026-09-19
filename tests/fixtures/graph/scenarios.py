"""Realistic FAS graph scenario builders used by integration and security tests."""

from __future__ import annotations

from datetime import datetime, timezone

from fas.domain.common import EvidenceType, GraphNodeType, Provenance, ProvenanceCategory, ProvenanceLevel, RelationshipType, new_id
from fas.domain.evidence import Evidence
from fas.graph import GraphBuilder, GraphEngine


NOW = datetime(2026, 9, 19, 12, tzinfo=timezone.utc)


def _engine():
    analysis_id = new_id("analysis")
    snapshot_id = new_id("snapshot")
    provenance = Provenance(
        category=ProvenanceCategory.TOOL_OBSERVATION,
        level=ProvenanceLevel.T2,
        collector="scenario",
        method="synthetic_fixture",
        source="tests/fixtures/graph/scenarios.py",
        observed_at=NOW,
    )
    engine = GraphEngine(analysis_id=analysis_id, snapshot_id=snapshot_id)
    evidence = Evidence(
        id=new_id("evidence"),
        analysis_id=analysis_id,
        snapshot_id=snapshot_id,
        type=EvidenceType.CODE,
        claim="synthetic scenario evidence",
        provenance=(provenance,),
        observed_at=NOW,
    )
    engine.add_evidence(evidence)
    return engine, provenance, evidence


def _node(engine, provenance, evidence, node_type, identity):
    node = GraphBuilder.make_node(
        analysis_id=engine.scope.analysis_id,
        snapshot_id=engine.scope.snapshot_id,
        node_type=node_type,
        canonical_identity=identity,
        label=identity,
        provenance=(provenance,),
        evidence_ids=(evidence.id,),
        security_relevant=True,
    )
    engine.add_node(node)
    return node


def _edge(engine, provenance, evidence, source, target, relationship):
    edge = GraphBuilder.make_edge(
        analysis_id=engine.scope.analysis_id,
        snapshot_id=engine.scope.snapshot_id,
        source_node_id=source.id,
        target_node_id=target.id,
        relationship_type=relationship,
        provenance=(provenance,),
        evidence_ids=(evidence.id,),
        security_relevant=True,
        observed_at=NOW,
    )
    engine.merge_edge_evidence(edge)
    return edge


def scenario_code_flow():
    engine, provenance, evidence = _engine()
    endpoint = _node(engine, provenance, evidence, GraphNodeType.ENDPOINT, "/fetch")
    function = _node(engine, provenance, evidence, GraphNodeType.SYMBOL, "fetch_url")
    sink = _node(engine, provenance, evidence, GraphNodeType.SYMBOL, "http_client.request")
    _edge(engine, provenance, evidence, endpoint, function, RelationshipType.INVOKES)
    _edge(engine, provenance, evidence, function, sink, RelationshipType.CALLS)
    return engine


def scenario_authentication_boundary():
    engine, provenance, evidence = _engine()
    internet = _node(engine, provenance, evidence, GraphNodeType.SERVICE, "internet")
    endpoint = _node(engine, provenance, evidence, GraphNodeType.ENDPOINT, "/admin")
    auth = _node(engine, provenance, evidence, GraphNodeType.CONTROL, "authentication")
    privileged = _node(engine, provenance, evidence, GraphNodeType.SYMBOL, "admin_operation")
    boundary = _node(engine, provenance, evidence, GraphNodeType.TRUST_BOUNDARY, "authenticated_zone")
    _edge(engine, provenance, evidence, internet, endpoint, RelationshipType.EXPOSES)
    _edge(engine, provenance, evidence, endpoint, auth, RelationshipType.INVOKES)
    _edge(engine, provenance, evidence, auth, privileged, RelationshipType.AUTHENTICATES_AS)
    _edge(engine, provenance, evidence, privileged, boundary, RelationshipType.PASSES_THROUGH)
    return engine


def scenario_agent_tool_chain():
    engine, provenance, evidence = _engine()
    content = _node(engine, provenance, evidence, GraphNodeType.DATA_ASSET, "untrusted_content")
    agent = _node(engine, provenance, evidence, GraphNodeType.AGENT, "agent")
    tool = _node(engine, provenance, evidence, GraphNodeType.TOOL, "shell_tool")
    principal = _node(engine, provenance, evidence, GraphNodeType.PRINCIPAL, "ci-principal")
    resource = _node(engine, provenance, evidence, GraphNodeType.DATA_ASSET, "production")
    _edge(engine, provenance, evidence, content, agent, RelationshipType.FLOWS_TO)
    _edge(engine, provenance, evidence, agent, tool, RelationshipType.CAN_USE)
    _edge(engine, provenance, evidence, tool, principal, RelationshipType.EXECUTES)
    _edge(engine, provenance, evidence, principal, resource, RelationshipType.CAN_ACCESS)
    return engine


def scenario_mcp_chain():
    engine, provenance, evidence = _engine()
    task = _node(engine, provenance, evidence, GraphNodeType.AGENT_TASK, "task")
    server = _node(engine, provenance, evidence, GraphNodeType.MCP_SERVER, "payments-mcp")
    tool = _node(engine, provenance, evidence, GraphNodeType.MCP_TOOL, "refund")
    operation = _node(engine, provenance, evidence, GraphNodeType.SYMBOL, "refund_payment")
    resource = _node(engine, provenance, evidence, GraphNodeType.DATA_ASSET, "payment-record")
    _edge(engine, provenance, evidence, task, server, RelationshipType.CAN_USE)
    _edge(engine, provenance, evidence, server, tool, RelationshipType.EXPOSES)
    _edge(engine, provenance, evidence, tool, operation, RelationshipType.INVOKES)
    _edge(engine, provenance, evidence, operation, resource, RelationshipType.CAN_MODIFY)
    return engine


def scenario_multiple_evidence_sources():
    engine, provenance, evidence_a = _engine()
    evidence_b = Evidence(
        id=new_id("evidence"),
        analysis_id=engine.scope.analysis_id,
        snapshot_id=engine.scope.snapshot_id,
        type=EvidenceType.CALL_GRAPH,
        claim="independent collector confirms call",
        provenance=(provenance,),
        observed_at=NOW,
    )
    engine.add_evidence(evidence_b)
    source = _node(engine, provenance, evidence_a, GraphNodeType.SYMBOL, "a")
    target = _node(engine, provenance, evidence_a, GraphNodeType.SYMBOL, "b")
    edge = GraphBuilder.make_edge(
        analysis_id=engine.scope.analysis_id,
        snapshot_id=engine.scope.snapshot_id,
        source_node_id=source.id,
        target_node_id=target.id,
        relationship_type=RelationshipType.CALLS,
        provenance=(provenance,),
        evidence_ids=(evidence_a.id,),
        observed_at=NOW,
    )
    engine.add_edge(edge)
    engine.merge_edge_evidence(edge.model_copy(update={"evidence_ids": (evidence_b.id,), "id": new_id("edge")}))
    return engine


def scenario_conflicting_evidence():
    engine, provenance, evidence_a = _engine()
    evidence_b = Evidence(
        id=new_id("evidence"),
        analysis_id=engine.scope.analysis_id,
        snapshot_id=engine.scope.snapshot_id,
        type=EvidenceType.PERMISSION,
        claim="independent collector reports authorization denial",
        provenance=(provenance,),
        observed_at=NOW,
    )
    engine.add_evidence(evidence_b)
    principal = _node(engine, provenance, evidence_a, GraphNodeType.PRINCIPAL, "principal")
    resource = _node(engine, provenance, evidence_a, GraphNodeType.DATA_ASSET, "resource")
    edge = _edge(engine, provenance, evidence_a, principal, resource, RelationshipType.CAN_ACCESS)
    engine.merge_edge_evidence(edge.model_copy(update={"id": new_id("edge"), "evidence_ids": (evidence_b.id,)}))
    return engine


def scenario_cyclic_graph():
    engine, provenance, evidence = _engine()
    nodes = [_node(engine, provenance, evidence, GraphNodeType.SYMBOL, name) for name in ("a", "b", "c")]
    for index, source in enumerate(nodes):
        _edge(engine, provenance, evidence, source, nodes[(index + 1) % len(nodes)], RelationshipType.CALLS)
    return engine


def scenario_remediation_diff():
    original = scenario_agent_tool_chain()
    patched = GraphEngine.from_json(original.to_json())
    edge = next(edge for edge in patched.edges() if edge.relationship_type == RelationshipType.CAN_USE)
    patched.remove_edge(edge.id)
    return original, patched


def scenario_residual_path():
    original = scenario_agent_tool_chain()
    patched = GraphEngine.from_json(original.to_json())
    agent = next(node for node in patched.nodes() if node.type == GraphNodeType.AGENT)
    resource = next(node for node in patched.nodes() if node.canonical_identity.endswith(":production"))
    evidence = patched.get_node_evidence(agent.id)[0]
    provenance = agent.provenance[0]
    patched.merge_edge_evidence(GraphBuilder.make_edge(
        analysis_id=patched.scope.analysis_id,
        snapshot_id=patched.scope.snapshot_id,
        source_node_id=agent.id,
        target_node_id=resource.id,
        relationship_type=RelationshipType.CAN_ACCESS,
        provenance=(provenance,),
        evidence_ids=(evidence.id,),
        observed_at=NOW,
    ))
    return original, patched
