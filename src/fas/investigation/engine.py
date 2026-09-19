"""Deterministic Phase 4 investigation engine.

The engine is read-only by default. It operates on one immutable graph snapshot and
never treats model output or untrusted repository content as evidence.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from hashlib import sha256
from time import monotonic
from collections.abc import Callable, Iterable

from fas.domain import (
    Finding, GraphNode, InvestigationCase, InvestigationEvent, InvestigationHypothesis,
    InvestigationResult, InvestigationStatus, InvestigationToolResult, EvidenceRequest,
    InvestigationBudget, InvestigationConstraints, ExploitabilityAnalysis, VerdictProposal,
    TrustBoundaryAssessment, ToolPolicy, AttackPath,
    AttackPathStep, new_id, utc_now,
)
from fas.domain.common import GraphNodeType, RelationshipType, JSONValue
from fas.graph import GraphEngine, GraphPath, TraversalDirection


class InvestigationError(RuntimeError):
    pass


class InvestigationBudgetExceeded(InvestigationError):
    pass


class InvestigationCancelled(InvestigationError):
    pass


class UnauthorizedInvestigatorTool(InvestigationError):
    pass


class SnapshotScopeError(InvestigationError):
    pass


@dataclass
class InvestigationStore:
    """Append-oriented in-memory persistence seam for Phase 4.

    A future PostgreSQL implementation can replace this class without changing
    investigation contracts or deterministic primitives.
    """
    cases: dict[str, InvestigationCase] = field(default_factory=dict)
    hypotheses: dict[str, InvestigationHypothesis] = field(default_factory=dict)
    requests: dict[str, EvidenceRequest] = field(default_factory=dict)
    events: list[InvestigationEvent] = field(default_factory=list)
    results: dict[str, InvestigationResult] = field(default_factory=dict)
    tool_results: list[InvestigationToolResult] = field(default_factory=list)

    def create(self, case: InvestigationCase) -> None:
        if case.id in self.cases:
            raise InvestigationError("investigation already exists")
        self.cases[case.id] = case
        self.event(case, "CREATED", {"objective": case.objective})

    def save_case(self, case: InvestigationCase) -> None:
        self.cases[case.id] = case

    def add_hypothesis(self, item: InvestigationHypothesis) -> None:
        self.hypotheses[item.id] = item
        case = self.cases[item.investigation_id]
        self.save_case(case.model_copy(update={
            "hypotheses": (*case.hypotheses, item),
            "updated_at": utc_now(),
        }))
        self.event(case, "HYPOTHESIS_CREATED", {"hypothesis_id": item.id})

    def add_request(self, item: EvidenceRequest) -> None:
        if item.snapshot_id != self.cases[item.investigation_id].snapshot_id:
            raise SnapshotScopeError("evidence request crosses investigation snapshot")
        self.requests[item.id] = item
        case = self.cases[item.investigation_id]
        self.save_case(case.model_copy(update={
            "required_evidence": (*case.required_evidence, item),
            "updated_at": utc_now(),
        }))
        self.event(case, "EVIDENCE_REQUESTED", {"request_id": item.id})

    def add_tool_result(self, result: InvestigationToolResult) -> None:
        self.tool_results.append(result)

    def acquire_evidence(self, investigation_id: str, evidence_ids: Iterable[str]) -> None:
        case = self.cases[investigation_id]
        merged = tuple(sorted(set(case.acquired_evidence).union(evidence_ids)))
        self.save_case(case.model_copy(update={"acquired_evidence": merged, "updated_at": utc_now()}))
        self.event(case, "EVIDENCE_ACQUIRED", {"count": str(len(merged))})

    def event(self, case: InvestigationCase, event_type: str, payload: dict[str, str]) -> None:
        self.events.append(InvestigationEvent(
            id=new_id("investigation_event"),
            investigation_id=case.id,
            analysis_id=case.analysis_id,
            snapshot_id=case.snapshot_id,
            type=event_type,
            actor="fas",
            payload=payload,
        ))


@dataclass
class InvestigationContext:
    case: InvestigationCase
    graph: GraphEngine
    finding: Finding
    store: InvestigationStore
    started_at: float = field(default_factory=monotonic)
    evidence_requests_used: int = 0
    tool_calls_used: int = 0
    graph_nodes_used: int = 0
    graph_edges_used: int = 0
    runtime_tests_used: int = 0
    seen_calls: set[str] = field(default_factory=set)
    cancelled: Callable[[], bool] = lambda: False

    def check(self) -> None:
        if self.cancelled():
            raise InvestigationCancelled("investigation cancelled")
        b = self.case.budget
        if monotonic() - self.started_at > b.max_duration_seconds:
            raise InvestigationBudgetExceeded("investigation duration budget exhausted")
        if self.evidence_requests_used > b.max_evidence_requests:
            raise InvestigationBudgetExceeded("evidence-request budget exhausted")
        if self.tool_calls_used > b.max_tool_calls:
            raise InvestigationBudgetExceeded("tool-call budget exhausted")
        if self.graph_nodes_used > b.max_graph_nodes or self.graph_edges_used > b.max_graph_edges:
            raise InvestigationBudgetExceeded("graph inspection budget exhausted")


class DeterministicInvestigator:
    """Read-only deterministic primitives exposed to the constrained investigator."""

    def __init__(self, context: InvestigationContext, *, policy: ToolPolicy | None = None) -> None:
        self.ctx = context
        self.policy = policy or ToolPolicy()

    def _call(self, name: str, args: dict[str, str]) -> None:
        if name in self.policy.denied_tools or name not in self.policy.allowed_tools:
            raise UnauthorizedInvestigatorTool(name)
        fingerprint = sha256((name + "|" + "|".join(f"{k}={args[k]}" for k in sorted(args))).encode()).hexdigest()
        if fingerprint in self.ctx.seen_calls:
            raise InvestigationBudgetExceeded("repeated investigator tool request")
        self.ctx.seen_calls.add(fingerprint)
        self.ctx.store.event(self.ctx.case, "TOOL_INVOKED", {"tool": name})
        self.ctx.tool_calls_used += 1
        self.ctx.check()

    def _scope(self, snapshot_id: str | None = None) -> None:
        if snapshot_id is not None and snapshot_id != self.ctx.case.snapshot_id:
            raise SnapshotScopeError("investigator tool attempted cross-snapshot access")

    def _result(self, tool: str, status: str, result: dict[str, JSONValue], evidence: Iterable[str] = (), missing: Iterable[str] = ()) -> InvestigationToolResult:
        return InvestigationToolResult(
            tool_call_id=f"{self.ctx.case.id}:{self.ctx.tool_calls_used}",
            tool=tool,
            status=status,
            analysis_id=self.ctx.case.analysis_id,
            snapshot_id=self.ctx.case.snapshot_id,
            result=result,
            evidence_ids=tuple(sorted(set(evidence))),
            missing=tuple(sorted(set(missing))),
        )

    def get_evidence(self, evidence_id: str) -> InvestigationToolResult:
        self._call("get_evidence", {"evidence_id": evidence_id})
        evidence = self.ctx.graph.store.evidence(evidence_id)
        self._scope(evidence.snapshot_id)
        self.ctx.store.acquire_evidence(self.ctx.case.id, (evidence.id,))
        return self._result("get_evidence", "SUCCESS", {"evidence": evidence.model_dump(mode="json")}, [evidence.id])

    def query_graph(self, *, node_type: GraphNodeType | None = None, relationship: RelationshipType | None = None) -> InvestigationToolResult:
        args={"node_type": node_type.value if node_type else "", "relationship": relationship.value if relationship else ""}
        self._call("query_graph", args)
        query_nodes = frozenset({node_type}) if node_type else None
        query_edges = frozenset({relationship}) if relationship else None
        from fas.graph.contracts import GraphQuery
        result = self.ctx.graph.nodes(GraphQuery(node_types=query_nodes, relationship_types=query_edges))
        self.ctx.graph_nodes_used += len(result)
        self.ctx.check()
        return self._result("query_graph", "SUCCESS" if result else "EMPTY", {"nodes":[n.model_dump(mode="json") for n in result]})

    def _node(self, tool: str, node_id: str) -> GraphNode:
        self._call(tool, {"node_id": node_id})
        node = self.ctx.graph.get_node(node_id)
        self._scope(node.snapshot_id)
        self.ctx.graph_nodes_used += 1
        self.ctx.check()
        return node

    def inspect_symbol(self, node_id: str) -> InvestigationToolResult:
        node=self._node("inspect_symbol",node_id)
        if node.type != GraphNodeType.SYMBOL:
            return self._result("inspect_symbol","EMPTY",{},missing=["symbol node not found"])
        return self._result("inspect_symbol","SUCCESS",{"node":node.model_dump(mode="json")},node.evidence_ids)

    def inspect_file(self, node_id: str) -> InvestigationToolResult:
        node=self._node("inspect_file",node_id)
        if node.type != GraphNodeType.FILE:
            return self._result("inspect_file","EMPTY",{},missing=["file node not found"])
        return self._result("inspect_file","SUCCESS",{"node":node.model_dump(mode="json")},node.evidence_ids)

    def inspect_code_location(self, node_id: str) -> InvestigationToolResult:
        return self._inspect_typed("inspect_code_location",node_id,GraphNodeType.CODE_LOCATION)

    def _inspect_typed(self, tool: str, node_id: str, expected: GraphNodeType) -> InvestigationToolResult:
        node=self._node(tool,node_id)
        if node.type != expected:
            return self._result(tool,"EMPTY",{},missing=[f"{expected.value} node not found"])
        return self._result(tool,"SUCCESS",{"node":node.model_dump(mode="json")},node.evidence_ids)

    def trace_callers(self,node_id:str)->InvestigationToolResult:
        self._call("trace_callers",{"node_id":node_id})
        result=self.ctx.graph.traverse(node_id,direction=TraversalDirection.INBOUND,max_depth=self.ctx.case.budget.max_depth,max_nodes=self.ctx.case.budget.max_graph_nodes,max_edges=self.ctx.case.budget.max_graph_edges,allowed_relationship_types=frozenset({RelationshipType.CALLS}))
        self.ctx.graph_nodes_used+=len(result.node_ids)
        self.ctx.graph_edges_used+=len(result.edge_ids)
        self.ctx.check()
        return self._result("trace_callers", "SUCCESS" if result.node_ids else "EMPTY", {"node_ids":result.node_ids,"depths":result.depths})

    def trace_callees(self,node_id:str)->InvestigationToolResult:
        self._call("trace_callees",{"node_id":node_id})
        result=self.ctx.graph.traverse(node_id,direction=TraversalDirection.OUTBOUND,max_depth=self.ctx.case.budget.max_depth,max_nodes=self.ctx.case.budget.max_graph_nodes,max_edges=self.ctx.case.budget.max_graph_edges,allowed_relationship_types=frozenset({RelationshipType.CALLS}))
        self.ctx.graph_nodes_used+=len(result.node_ids)
        self.ctx.graph_edges_used+=len(result.edge_ids)
        self.ctx.check()
        return self._result("trace_callees", "SUCCESS" if result.node_ids else "EMPTY", {"node_ids":result.node_ids,"depths":result.depths})

    def trace_dataflow(self,node_id:str)->InvestigationToolResult:
        self._call("trace_dataflow",{"node_id":node_id})
        result=self.ctx.graph.traverse(node_id,max_depth=self.ctx.case.budget.max_depth,max_nodes=self.ctx.case.budget.max_graph_nodes,max_edges=self.ctx.case.budget.max_graph_edges,allowed_relationship_types=frozenset({RelationshipType.FLOWS_TO,RelationshipType.READS,RelationshipType.WRITES}))
        self.ctx.graph_nodes_used+=len(result.node_ids)
        self.ctx.graph_edges_used+=len(result.edge_ids)
        self.ctx.check()
        return self._result("trace_dataflow", "SUCCESS" if result.node_ids else "EMPTY", {"node_ids":result.node_ids,"depths":result.depths})

    def trace_control_flow(self,node_id:str)->InvestigationToolResult:
        self._call("trace_control_flow",{"node_id":node_id})
        result=self.ctx.graph.traverse(node_id,max_depth=self.ctx.case.budget.max_depth,max_nodes=self.ctx.case.budget.max_graph_nodes,max_edges=self.ctx.case.budget.max_graph_edges)
        self.ctx.graph_nodes_used+=len(result.node_ids)
        self.ctx.graph_edges_used+=len(result.edge_ids)
        self.ctx.check()
        return self._result("trace_control_flow", "SUCCESS" if result.node_ids else "EMPTY", {"node_ids":result.node_ids,"depths":result.depths})

    def find_paths_between(self,source_id:str,target_id:str)->InvestigationToolResult:
        self._call("find_paths_between",{"source_id":source_id,"target_id":target_id})
        paths=self.ctx.graph.bounded_paths(source_id,target_id,max_depth=self.ctx.case.budget.max_depth,max_paths=self.ctx.case.budget.max_tool_calls)
        self.ctx.graph_edges_used += sum(len(p.edges) for p in paths.paths)
        evidence=tuple(sorted({e for p in paths.paths for e in p.evidence_ids}))
        return self._result("find_paths_between", "SUCCESS" if paths.paths else "EMPTY", {"paths":[p.path_id for p in paths.paths],"status":paths.status.value},evidence)

    def find_attack_paths(self,source_id:str,target_id:str)->InvestigationToolResult:
        return self.find_paths_between(source_id,target_id)

    def find_reachable_nodes(self,source_id:str)->InvestigationToolResult:
        self._call("find_reachable_nodes",{"source_id":source_id})
        result=self.ctx.graph.reachable_nodes(source_id,max_depth=self.ctx.case.budget.max_depth,max_nodes=self.ctx.case.budget.max_graph_nodes,max_edges=self.ctx.case.budget.max_graph_edges)
        self.ctx.graph_nodes_used += len(result.node_ids)
        self.ctx.graph_edges_used += len(result.edge_ids)
        self.ctx.check()
        return self._result("find_reachable_nodes","SUCCESS",{"node_ids":result.node_ids,"status":result.status.value})

    def inspect_identity(self,node_id:str)->InvestigationToolResult:
        return self._inspect_typed("inspect_identity",node_id,GraphNodeType.IDENTITY)

    def inspect_permission(self,node_id:str)->InvestigationToolResult:
        return self._inspect_typed("inspect_permission",node_id,GraphNodeType.PERMISSION)

    def inspect_agent(self,node_id:str)->InvestigationToolResult:
        return self._inspect_typed("inspect_agent",node_id,GraphNodeType.AGENT)

    def inspect_agent_task(self,node_id:str)->InvestigationToolResult:
        return self._inspect_typed("inspect_agent_task",node_id,GraphNodeType.AGENT_TASK)

    def inspect_tool(self,node_id:str)->InvestigationToolResult:
        return self._inspect_typed("inspect_tool",node_id,GraphNodeType.TOOL)

    def inspect_mcp_server(self,node_id:str)->InvestigationToolResult:
        return self._inspect_typed("inspect_mcp_server",node_id,GraphNodeType.MCP_SERVER)

    def inspect_mcp_tool(self,node_id:str)->InvestigationToolResult:
        return self._inspect_typed("inspect_mcp_tool",node_id,GraphNodeType.MCP_TOOL)

    def inspect_trust_boundary(self,node_id:str)->InvestigationToolResult:
        return self._inspect_typed("inspect_trust_boundary",node_id,GraphNodeType.TRUST_BOUNDARY)

    def inspect_dependency(self,node_id:str)->InvestigationToolResult:
        return self._inspect_typed("inspect_dependency",node_id,GraphNodeType.DEPENDENCY)

    def inspect_configuration(self,node_id:str)->InvestigationToolResult:
        return self._inspect_typed("inspect_configuration",node_id,GraphNodeType.CONFIGURATION)

    def trace_endpoint(self,node_id:str)->InvestigationToolResult:
        return self._inspect_typed("trace_endpoint",node_id,GraphNodeType.ENDPOINT)

    def inspect_mcp(self,node_id:str)->InvestigationToolResult:
        node=self._node("inspect_mcp",node_id)
        if node.type not in {GraphNodeType.MCP_SERVER,GraphNodeType.MCP_TOOL}:
            return self._result("inspect_mcp","EMPTY",{},missing=["MCP node not found"])
        return self._result("inspect_mcp","SUCCESS",{"node":node.model_dump(mode="json")},node.evidence_ids)

    def find_alternate_paths(self,source_id:str,target_id:str,primary_edge_ids:frozenset[str]=frozenset())->InvestigationToolResult:
        self._call("find_alternate_paths",{"source_id":source_id,"target_id":target_id})
        paths=self.ctx.graph.bounded_paths(source_id,target_id,max_depth=self.ctx.case.budget.max_depth,max_paths=min(100,self.ctx.case.budget.max_tool_calls))
        alternate=tuple(p for p in paths.paths if not primary_edge_ids.intersection(e.id for e in p.edges))
        evidence=tuple(sorted({e for p in alternate for e in p.evidence_ids}))
        return self._result("find_alternate_paths","SUCCESS" if alternate else "EMPTY",{"paths":[p.path_id for p in alternate]},evidence)

    def inspect_permission_chain(self,node_id:str)->InvestigationToolResult:
        self._call("inspect_permission",{"node_id":node_id})
        result=self.ctx.graph.traverse(node_id,direction=TraversalDirection.OUTBOUND,max_depth=self.ctx.case.budget.max_depth,max_nodes=self.ctx.case.budget.max_graph_nodes,max_edges=self.ctx.case.budget.max_graph_edges,allowed_relationship_types=frozenset({RelationshipType.HAS_PERMISSION,RelationshipType.CAN_ACCESS,RelationshipType.CAN_MODIFY,RelationshipType.AUTHENTICATES_AS,RelationshipType.CAN_USE}))
        evidence=tuple(sorted({e for edge_id in result.edge_ids for e in self.ctx.graph.get_edge(edge_id).evidence_ids}))
        return self._result("inspect_permission","SUCCESS" if result.node_ids else "EMPTY",{"node_ids":result.node_ids},evidence)

    def find_controls(self)->InvestigationToolResult:
        self._call("find_controls",{})
        nodes=self.ctx.graph.nodes()
        controls=[n for n in nodes if n.type==GraphNodeType.CONTROL]
        evidence=tuple(sorted({e for n in controls for e in n.evidence_ids}))
        return self._result("find_controls","SUCCESS" if controls else "EMPTY",{"nodes":[n.model_dump(mode="json") for n in controls]},evidence)

    def request_evidence(self, request: EvidenceRequest)->InvestigationToolResult:
        self._call("request_evidence",{"request_id":request.id})
        if request.investigation_id != self.ctx.case.id or request.snapshot_id != self.ctx.case.snapshot_id:
            raise SnapshotScopeError("evidence request is outside investigation scope")
        self.ctx.evidence_requests_used += 1
        self.ctx.store.add_request(request)
        return self._result("request_evidence","SUCCESS",{"request_id":request.id})

    def propose_hypothesis(self, statement:str)->InvestigationHypothesis:
        self._call("propose_hypothesis",{"statement":statement})
        item=InvestigationHypothesis(id=new_id("hypothesis"),investigation_id=self.ctx.case.id,statement=statement)
        self.ctx.store.add_hypothesis(item)
        return item


class InvestigationEngine:
    def __init__(self, *, graph: GraphEngine, store: InvestigationStore | None = None) -> None:
        self.graph=graph
        self.store=store or InvestigationStore()

    def create_case(self, *, finding: Finding, objective: str, budget=None, constraints=None) -> InvestigationCase:
        if finding.snapshot_id != self.graph.scope.snapshot_id:
            raise SnapshotScopeError("finding is outside graph snapshot")
        if self.graph.scope.snapshot_id is None:
            raise SnapshotScopeError("Phase 4 investigation requires a snapshot-scoped graph")
        case=InvestigationCase(
            id=new_id("investigation"),analysis_id=self.graph.scope.analysis_id,finding_id=finding.id,
            snapshot_id=finding.snapshot_id,status=InvestigationStatus.CREATED,objective=objective,
            graph_scope=f"analysis={self.graph.scope.analysis_id}\n            snapshot={self.graph.scope.snapshot_id}",
            budget=budget or InvestigationBudget(),
            constraints=constraints or InvestigationConstraints(),
        )
        self.store.create(case)
        return case

    def context(self, case: InvestigationCase, finding: Finding, *, cancelled:Callable[[],bool]=lambda:False)->InvestigationContext:
        if case.analysis_id != self.graph.scope.analysis_id or case.snapshot_id != self.graph.scope.snapshot_id or finding.snapshot_id != case.snapshot_id:
            raise SnapshotScopeError("investigation scope mismatch")
        return InvestigationContext(case,self.graph,finding,self.store,cancelled=cancelled)

    def primitives(self, case: InvestigationCase, finding: Finding, *, cancelled:Callable[[],bool]=lambda:False)->DeterministicInvestigator:
        return DeterministicInvestigator(self.context(case,finding,cancelled=cancelled))

    def reconstruct_attack_path(self, context:InvestigationContext, path:GraphPath, *, entry: str|None=None)->AttackPath:
        if path.snapshot_id != context.case.snapshot_id:
            raise SnapshotScopeError("attack path crosses snapshot")
        steps=[]
        for index,edge in enumerate(path.edges):
            step=AttackPathStep(node_id=edge.source_node_id,edge_id=edge.id,next_node_id=edge.target_node_id,evidence_ids=edge.evidence_ids)
            if not step.evidence_ids:
                raise InvestigationError("attack path contains an evidence-less transition")
            steps.append(step)
        return AttackPath(id=new_id("attack_path"),entry=path.nodes[0].id,steps=tuple(steps),trust_boundaries_crossed=path.trust_boundary_node_ids,supporting_evidence_ids=path.evidence_ids,snapshot_id=path.snapshot_id,observed_at=utc_now())

    def validate_attack_path(self, context: InvestigationContext, path: GraphPath) -> tuple[bool, tuple[str, ...]]:
        if path.snapshot_id != context.case.snapshot_id:
            raise SnapshotScopeError("attack path crosses snapshot")
        issues: list[str] = []
        if not path.edges:
            issues.append("path has no security transition")
        for edge in path.edges:
            if not edge.evidence_ids:
                issues.append(f"edge {edge.id} has no evidence")
            if edge.snapshot_id != context.case.snapshot_id:
                issues.append(f"edge {edge.id} crosses snapshot")
        for node in path.nodes:
            if node.snapshot_id != context.case.snapshot_id:
                issues.append(f"node {node.id} crosses snapshot")
        if not path.evidence_ids:
            issues.append("path has no supporting evidence")
        return not issues, tuple(sorted(set(issues)))

    def find_alternate_paths(self, context: InvestigationContext, source_id: str, target_id: str, primary_edge_ids: frozenset[str]) -> tuple[GraphPath, ...]:
        paths = context.graph.bounded_paths(source_id, target_id, max_depth=context.case.budget.max_depth, max_paths=min(100, context.case.budget.max_tool_calls))
        return tuple(path for path in paths.paths if not primary_edge_ids.intersection(edge.id for edge in path.edges))

    def analyze_exploitability(self, context:InvestigationContext, path:AttackPath|None, *, missing:Iterable[str]=(), contradictions:Iterable[str]=())->ExploitabilityAnalysis:
        missing_values=set(missing)
        contradiction_values=set(contradictions)
        if path is None:
            missing_values.add("validated attack path unavailable")
            return ExploitabilityAnalysis(evidence_sufficient=False,missing_evidence=tuple(sorted(missing_values)),contradictions=tuple(sorted(contradiction_values)))
        if path.snapshot_id != context.case.snapshot_id:
            contradiction_values.add("attack path is outside investigation snapshot")
        edges=[]
        for step in path.steps:
            try:
                edge=context.graph.get_edge(step.edge_id)
            except Exception as exc:
                contradiction_values.add(f"attack path step {step.edge_id} is unavailable: {type(exc).__name__}")
                continue
            if edge.snapshot_id != context.case.snapshot_id or not edge.evidence_ids:
                contradiction_values.add(f"attack path step {step.edge_id} is not evidence-backed")
            edges.append(edge)
        evidence_records=[context.graph.store.evidence(eid) for eid in sorted(path.supporting_evidence_ids)]
        attacker_influence=None
        identity=None
        permissions=[]
        for evidence in evidence_records:
            value=evidence.observed_value
            if isinstance(value,dict):
                if value.get("attacker_controlled") is True:
                    attacker_influence=True
                if isinstance(value.get("identity"),str):
                    identity=value["identity"]
                if isinstance(value.get("permission"),str):
                    permissions.append(value["permission"])
        if attacker_influence is not True:
            missing_values.add("attacker influence is not deterministically established")
        reachable=bool(edges) and not contradiction_values
        data_flow_established=any(edge.relationship_type.value=="FLOWS_TO" for edge in edges)
        if not data_flow_established:
            missing_values.add("deterministic data-flow relationship is not established")
        alternate=()
        if edges:
            alternate=self.find_alternate_paths(context,path.entry,path.steps[-1].next_node_id,frozenset(edge.id for edge in edges))
        alternate_paths_found=bool(alternate)
        return ExploitabilityAnalysis(
            attacker_influence=attacker_influence,
            reachable=reachable,
            data_flow_established=data_flow_established,
            evidence_sufficient=not missing_values and not contradiction_values,
            identity=identity,
            permissions=tuple(sorted(set(permissions))),
            alternate_paths_found=alternate_paths_found,
            missing_evidence=tuple(sorted(missing_values)),
            contradictions=tuple(sorted(contradiction_values)),
            trust_boundaries=tuple(TrustBoundaryAssessment(boundary_node_id=n.id,source=n.metadata.get("source",n.label),target=n.metadata.get("target",n.label),evidence_ids=n.evidence_ids) for n in (context.graph.get_node(i) for i in path.trust_boundaries_crossed)),
        )

    def propose_verdict(self, context:InvestigationContext, analysis:ExploitabilityAnalysis, *, attack_path:AttackPath|None, rationale:str)->VerdictProposal:
        evidence=tuple(sorted(set((attack_path.supporting_evidence_ids if attack_path else ()) + tuple(e for c in analysis.controls for e in c.evidence_ids))))
        if analysis.missing_evidence or analysis.contradictions or not analysis.evidence_sufficient:
            verdict="UNKNOWN"
        elif analysis.attacker_influence and analysis.reachable and attack_path:
            verdict="EXPLOITABLE"
        else:
            verdict="NOT_EXPLOITABLE"
        return VerdictProposal(verdict=verdict,supporting_evidence_ids=evidence,missing_evidence=analysis.missing_evidence,attack_path_ids=(attack_path.id,) if attack_path else (),rationale=rationale,preconditions=analysis.preconditions,trust_boundaries=analysis.trust_boundaries,identity=analysis.identity,permissions=analysis.permissions,controls=analysis.controls,investigation_id=context.case.id,snapshot_id=context.case.snapshot_id)

    def complete(self, context:InvestigationContext, analysis:ExploitabilityAnalysis, *, attack_path:AttackPath|None, rationale:str)->InvestigationResult:
        proposal=self.propose_verdict(context,analysis,attack_path=attack_path,rationale=rationale)
        status=InvestigationStatus.READY_FOR_VERDICT if proposal.verdict else InvestigationStatus.PARTIAL
        result=InvestigationResult(investigation_id=context.case.id,finding_id=context.case.finding_id,analysis_id=context.case.analysis_id,snapshot_id=context.case.snapshot_id,status=status,hypotheses=context.case.hypotheses,evidence_ids=tuple(sorted(set(context.case.acquired_evidence))),missing_evidence=analysis.missing_evidence,contradictions=tuple(),attack_paths=proposal.attack_path_ids,controls=analysis.controls,identities=(analysis.identity,) if analysis.identity else (),permissions=analysis.permissions,trust_boundaries=analysis.trust_boundaries,exploitability_analysis=analysis,verdict_proposal=proposal,limitations=(),audit_reference=f"investigation:{context.case.id}")
        self.store.results[context.case.id]=result
        return result
