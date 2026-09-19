"""Phase 4 evidence-grounded investigation contracts.

These models separate candidate findings, hypotheses, evidence requests, deterministic
tool results, attack-path validation, exploitability reasoning, and verdict proposals.
No model-generated statement is authoritative evidence.
"""
from __future__ import annotations
from datetime import datetime
from typing import Literal
from pydantic import Field, model_validator
from .common import (
    AnalysisId, AttackPathId, ControlId, DomainModel, EvidenceId, EvidenceRequestId, JSONValue,
    EvidenceRequestType, FindingId, HypothesisId, HypothesisStatus, InvestigationEventId,
    InvestigationEventType, InvestigationId, InvestigationStatus, InvestigationToolStatus,
    NodeId, SnapshotId, utc_now,
)


class InvestigationBudget(DomainModel):
    max_duration_seconds: float = Field(default=300, gt=0, le=86400)
    max_evidence_requests: int = Field(default=100, ge=1, le=10000)
    max_graph_nodes: int = Field(default=10000, ge=1, le=1_000_000)
    max_graph_edges: int = Field(default=25000, ge=1, le=2_000_000)
    max_tool_calls: int = Field(default=200, ge=1, le=10000)
    max_depth: int = Field(default=12, ge=1, le=100)
    max_llm_turns: int = Field(default=20, ge=0, le=1000)
    max_runtime_tests: int = Field(default=0, ge=0, le=100)


class InvestigationConstraints(DomainModel):
    read_only: bool = True
    allow_runtime_tests: bool = False
    allow_network: bool = False
    allow_external_tools: bool = False


class InvestigationHypothesis(DomainModel):
    id: HypothesisId
    investigation_id: InvestigationId
    statement: str = Field(min_length=1, max_length=8192)
    status: HypothesisStatus = HypothesisStatus.UNRESOLVED
    supporting_evidence_ids: tuple[EvidenceId, ...] = ()
    contradicting_evidence_ids: tuple[EvidenceId, ...] = ()
    missing_evidence: tuple[str, ...] = ()
    derived_from: tuple[HypothesisId, ...] = ()
    created_at: datetime = Field(default_factory=utc_now)


class EvidenceRequest(DomainModel):
    id: EvidenceRequestId
    investigation_id: InvestigationId
    type: EvidenceRequestType
    target: str = Field(min_length=1, max_length=4096)
    purpose: str = Field(min_length=1, max_length=8192)
    snapshot_id: SnapshotId
    constraints: dict[str, str] = Field(default_factory=dict)
    status: Literal["REQUESTED", "FULFILLED", "MISSING", "REJECTED"] = "REQUESTED"
    created_at: datetime = Field(default_factory=utc_now)


class InvestigationToolResult(DomainModel):
    tool_call_id: str = Field(min_length=4, max_length=128)
    tool: str = Field(min_length=1, max_length=128)
    status: InvestigationToolStatus
    analysis_id: AnalysisId
    snapshot_id: SnapshotId
    result: dict[str, JSONValue] = Field(default_factory=dict)
    evidence_ids: tuple[EvidenceId, ...] = ()
    artifact_ids: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()


class ControlAssessment(DomainModel):
    control_id: ControlId
    name: str = Field(min_length=1, max_length=512)
    exists: bool
    applicable: bool
    enforced: bool | None = None
    bypassable: bool | None = None
    evidence_ids: tuple[EvidenceId, ...] = ()
    notes: str = Field(default="", max_length=4096)


class PermissionAssessment(DomainModel):
    principal: str = Field(min_length=1, max_length=2048)
    permission: str = Field(min_length=1, max_length=2048)
    resource: str = Field(min_length=1, max_length=4096)
    action: str = Field(min_length=1, max_length=1024)
    evidence_ids: tuple[EvidenceId, ...] = ()


class TrustBoundaryAssessment(DomainModel):
    boundary_node_id: NodeId
    source: str = Field(min_length=1, max_length=2048)
    target: str = Field(min_length=1, max_length=2048)
    evidence_ids: tuple[EvidenceId, ...] = ()


class ExploitabilityAnalysis(DomainModel):
    attacker_influence: bool | None = None
    reachable: bool | None = None
    data_flow_established: bool | None = None
    authentication_required: bool | None = None
    authorization_required: bool | None = None
    identity: str | None = None
    permissions: tuple[PermissionAssessment, ...] = ()
    controls: tuple[ControlAssessment, ...] = ()
    trust_boundaries: tuple[TrustBoundaryAssessment, ...] = ()
    preconditions: tuple[str, ...] = ()
    impact: str | None = None
    alternate_paths_found: bool | None = None
    evidence_sufficient: bool = False
    contradictions: tuple[str, ...] = ()
    missing_evidence: tuple[str, ...] = ()


class VerdictProposal(DomainModel):
    verdict: Literal["EXPLOITABLE", "NOT_EXPLOITABLE", "CONDITIONALLY_EXPLOITABLE", "UNKNOWN"]
    supporting_evidence_ids: tuple[EvidenceId, ...] = ()
    contradicting_evidence_ids: tuple[EvidenceId, ...] = ()
    missing_evidence: tuple[str, ...] = ()
    attack_path_ids: tuple[AttackPathId, ...] = ()
    rationale: str = Field(min_length=1, max_length=16384)
    preconditions: tuple[str, ...] = ()
    affected_assets: tuple[str, ...] = ()
    trust_boundaries: tuple[TrustBoundaryAssessment, ...] = ()
    identity: str | None = None
    permissions: tuple[PermissionAssessment, ...] = ()
    controls: tuple[ControlAssessment, ...] = ()
    investigation_id: InvestigationId
    snapshot_id: SnapshotId

    @model_validator(mode="after")
    def evidence_rules(self) -> "VerdictProposal":
        if self.verdict == "EXPLOITABLE":
            if not self.supporting_evidence_ids or not self.attack_path_ids or self.missing_evidence:
                raise ValueError("EXPLOITABLE requires evidence, attack path, and no missing evidence")
        elif self.verdict == "NOT_EXPLOITABLE" and not self.supporting_evidence_ids:
            raise ValueError("NOT_EXPLOITABLE requires blocking evidence")
        elif self.verdict == "CONDITIONALLY_EXPLOITABLE" and (not self.supporting_evidence_ids or not self.preconditions):
            raise ValueError("CONDITIONALLY_EXPLOITABLE requires evidence and conditions")
        elif self.verdict == "UNKNOWN" and not self.missing_evidence:
            raise ValueError("UNKNOWN requires missing evidence")
        return self


class InvestigationCase(DomainModel):
    id: InvestigationId
    analysis_id: AnalysisId
    finding_id: FindingId
    snapshot_id: SnapshotId
    status: InvestigationStatus = InvestigationStatus.CREATED
    objective: str = Field(min_length=1, max_length=8192)
    hypotheses: tuple[InvestigationHypothesis, ...] = ()
    required_evidence: tuple[EvidenceRequest, ...] = ()
    acquired_evidence: tuple[EvidenceId, ...] = ()
    missing_evidence: tuple[str, ...] = ()
    contradicting_evidence: tuple[EvidenceId, ...] = ()
    graph_scope: str
    attack_paths: tuple[AttackPathId, ...] = ()
    constraints: InvestigationConstraints = Field(default_factory=InvestigationConstraints)
    budget: InvestigationBudget = Field(default_factory=InvestigationBudget)
    investigator_metadata: dict[str, str] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def timestamps(self) -> "InvestigationCase":
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot precede created_at")
        for request in self.required_evidence:
            if request.snapshot_id != self.snapshot_id:
                raise ValueError("evidence request escapes investigation snapshot")
        return self


class InvestigationResult(DomainModel):
    schema_version: str = "1.0"
    investigation_id: InvestigationId
    finding_id: FindingId
    analysis_id: AnalysisId
    snapshot_id: SnapshotId
    status: InvestigationStatus
    hypotheses: tuple[InvestigationHypothesis, ...] = ()
    evidence_ids: tuple[EvidenceId, ...] = ()
    missing_evidence: tuple[str, ...] = ()
    contradictions: tuple[EvidenceId, ...] = ()
    attack_paths: tuple[AttackPathId, ...] = ()
    controls: tuple[ControlAssessment, ...] = ()
    identities: tuple[str, ...] = ()
    permissions: tuple[PermissionAssessment, ...] = ()
    trust_boundaries: tuple[TrustBoundaryAssessment, ...] = ()
    exploitability_analysis: ExploitabilityAnalysis
    verdict_proposal: VerdictProposal | None = None
    limitations: tuple[str, ...] = ()
    audit_reference: str = Field(min_length=1, max_length=2048)
    created_at: datetime = Field(default_factory=utc_now)


class InvestigationEvent(DomainModel):
    id: InvestigationEventId
    investigation_id: InvestigationId
    analysis_id: AnalysisId
    snapshot_id: SnapshotId
    type: InvestigationEventType
    actor: str = Field(min_length=1, max_length=512)
    payload: dict[str, str] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class ToolPolicy(DomainModel):
    allowed_tools: frozenset[str] = frozenset({
        "get_evidence", "query_graph", "inspect_file", "inspect_symbol",
        "inspect_code_location", "trace_callers", "trace_callees", "trace_dataflow",
        "trace_control_flow", "trace_endpoint", "inspect_dependency", "inspect_configuration",
        "inspect_identity", "inspect_permission", "inspect_agent", "inspect_agent_task",
        "inspect_tool", "inspect_mcp_server", "inspect_mcp_tool", "inspect_trust_boundary",
        "find_attack_paths", "find_paths_between", "find_reachable_nodes", "find_controls",
        "find_alternate_paths", "request_evidence", "propose_hypothesis",
        "propose_attack_path", "propose_verdict",
    })
    denied_tools: frozenset[str] = frozenset({"shell", "sql", "filesystem_write", "network", "database_write"})


__all__ = [
    "InvestigationBudget", "InvestigationConstraints", "InvestigationHypothesis",
    "EvidenceRequest", "InvestigationToolResult", "ControlAssessment", "PermissionAssessment",
    "TrustBoundaryAssessment", "ExploitabilityAnalysis", "VerdictProposal",
    "InvestigationCase", "InvestigationResult", "InvestigationEvent", "ToolPolicy",
]
