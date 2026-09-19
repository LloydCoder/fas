"""Phase 5 remediation, verification, regression, and reporting contracts.

Phase 5 preserves before/after evidence, makes security properties explicit, and requires
deterministic evidence for remediation conclusions. Historical records are immutable.
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from fas.domain.common import (
    AnalysisId, AttackPathComparisonId, AttackPathId, DomainModel, EvidenceId, FindingId,
    GraphDiffId, GraphNodeType, Provenance, RegressionTestId, RemediationId, RemediationStatus,
    ResidualPathId, SecurityBaselineId, SecurityRegressionId, SnapshotId, VerificationEvidenceId,
    VerificationId, VerificationPlanId, VerificationRunId, VerificationStatus, VerdictType,
    utc_now,
)


class RemediationType(StrEnum):
    CODE_CHANGE="CODE_CHANGE"
    CONFIGURATION_CHANGE="CONFIGURATION_CHANGE"
    DEPENDENCY_UPDATE="DEPENDENCY_UPDATE"
    PERMISSION_REDUCTION="PERMISSION_REDUCTION"
    AUTHORIZATION_CHANGE="AUTHORIZATION_CHANGE"
    AUTHENTICATION_CHANGE="AUTHENTICATION_CHANGE"
    NETWORK_CONTROL="NETWORK_CONTROL"
    AGENT_POLICY_CHANGE="AGENT_POLICY_CHANGE"
    TOOL_PERMISSION_CHANGE="TOOL_PERMISSION_CHANGE"
    MCP_CONFIGURATION_CHANGE="MCP_CONFIGURATION_CHANGE"
    INFRASTRUCTURE_CHANGE="INFRASTRUCTURE_CHANGE"
    SECRET_ROTATION="SECRET_ROTATION"
    CREDENTIAL_SCOPE_REDUCTION="CREDENTIAL_SCOPE_REDUCTION"
    COMPENSATING_CONTROL="COMPENSATING_CONTROL"


class SecurityPropertyOutcome(StrEnum):
    ELIMINATED="ELIMINATED"
    MITIGATED="MITIGATED"
    PARTIALLY_MITIGATED="PARTIALLY_MITIGATED"
    UNCHANGED="UNCHANGED"
    WORSENED="WORSENED"
    UNKNOWN="UNKNOWN"


class VerificationCheck(StrEnum):
    REPRODUCE_ORIGINAL_CONDITION="REPRODUCE_ORIGINAL_CONDITION"
    VERIFY_CODE_CHANGE="VERIFY_CODE_CHANGE"
    VERIFY_GRAPH_CHANGE="VERIFY_GRAPH_CHANGE"
    VERIFY_CONTROL="VERIFY_CONTROL"
    VERIFY_PERMISSION="VERIFY_PERMISSION"
    VERIFY_IDENTITY="VERIFY_IDENTITY"
    VERIFY_DATAFLOW="VERIFY_DATAFLOW"
    VERIFY_ATTACK_PATH="VERIFY_ATTACK_PATH"
    VERIFY_ALTERNATE_PATHS="VERIFY_ALTERNATE_PATHS"
    VERIFY_SECURITY_TEST="VERIFY_SECURITY_TEST"
    VERIFY_REGRESSION="VERIFY_REGRESSION"
    VERIFY_ARTIFACT_INTEGRITY="VERIFY_ARTIFACT_INTEGRITY"


class CheckStatus(StrEnum):
    PENDING="PENDING"
    PASSED="PASSED"
    FAILED="FAILED"
    BLOCKED="BLOCKED"
    NOT_APPLICABLE="NOT_APPLICABLE"


class AttackPathComparisonStatus(StrEnum):
    ORIGINAL_PATH_PERSISTENT="ORIGINAL_PATH_PERSISTENT"
    ORIGINAL_PATH_BROKEN="ORIGINAL_PATH_BROKEN"
    ALTERNATE_PATH_FOUND="ALTERNATE_PATH_FOUND"
    PATH_STRENGTHENED="PATH_STRENGTHENED"
    PATH_WEAKENED="PATH_WEAKENED"
    PATH_RELOCATED="PATH_RELOCATED"
    UNKNOWN="UNKNOWN"


class DiffKind(StrEnum):
    ADDED="ADDED"
    REMOVED="REMOVED"
    UNCHANGED="UNCHANGED"
    MODIFIED="MODIFIED"


class RegressionStatus(StrEnum):
    DETECTED="DETECTED"
    NOT_DETECTED="NOT_DETECTED"
    UNKNOWN="UNKNOWN"


class Remediation(DomainModel):
    id: RemediationId
    finding_id: FindingId
    analysis_id: AnalysisId
    original_snapshot_id: SnapshotId
    target_snapshot_id: SnapshotId | None = None
    type: RemediationType
    description: str = Field(min_length=1, max_length=16384)
    root_cause: str = Field(min_length=1, max_length=8192)
    affected_components: tuple[str, ...] = ()
    expected_security_property: str = Field(min_length=1, max_length=8192)
    proposed_changes: tuple[str, ...] = ()
    actual_changes: tuple[str, ...] = ()
    status: RemediationStatus = RemediationStatus.PROPOSED
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    provenance: tuple[Provenance, ...] = ()

    @model_validator(mode="after")
    def valid_scope(self) -> "Remediation":
        if self.target_snapshot_id is not None and self.target_snapshot_id == self.original_snapshot_id:
            raise ValueError("target snapshot must differ from original snapshot")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot precede created_at")
        return self


class VerificationCheckResult(DomainModel):
    check: VerificationCheck
    status: CheckStatus
    evidence_ids: tuple[EvidenceId, ...] = ()
    notes: str = Field(default="", max_length=8192)
    blocking: bool = False


class VerificationPlan(DomainModel):
    id: VerificationPlanId
    finding_id: FindingId
    remediation_id: RemediationId
    original_snapshot_id: SnapshotId
    candidate_snapshot_id: SnapshotId
    security_property: str = Field(min_length=1, max_length=8192)
    required_checks: tuple[VerificationCheck, ...] = Field(min_length=1)
    scope_components: tuple[str, ...] = ()
    created_at: datetime = Field(default_factory=utc_now)
    plan_fingerprint: str = Field(min_length=8, max_length=128)


class VerificationRun(DomainModel):
    id: VerificationRunId
    verification_id: VerificationId
    plan_id: VerificationPlanId
    started_at: datetime
    completed_at: datetime | None = None
    tool_versions: dict[str, str] = Field(default_factory=dict)
    adapter_versions: dict[str, str] = Field(default_factory=dict)
    configuration_fingerprint: str | None = None
    checks_executed: tuple[VerificationCheckResult, ...] = ()
    paths_evaluated: int = 0
    alternate_paths_discovered: int = 0
    duration_ms: int | None = Field(default=None, ge=0)


class GraphDiff(DomainModel):
    id: GraphDiffId
    analysis_id: AnalysisId
    original_snapshot_id: SnapshotId
    candidate_snapshot_id: SnapshotId
    added_node_ids: tuple[str, ...] = ()
    removed_node_ids: tuple[str, ...] = ()
    modified_node_ids: tuple[str, ...] = ()
    added_edge_ids: tuple[str, ...] = ()
    removed_edge_ids: tuple[str, ...] = ()
    modified_edge_ids: tuple[str, ...] = ()
    unchanged_node_count: int = Field(default=0, ge=0)
    unchanged_edge_count: int = Field(default=0, ge=0)
    permission_added: tuple[str, ...] = ()
    permission_removed: tuple[str, ...] = ()
    permission_widened: tuple[str, ...] = ()
    permission_narrowed: tuple[str, ...] = ()
    identity_changed: tuple[str, ...] = ()
    trust_boundary_changed: tuple[str, ...] = ()
    endpoint_changed: tuple[str, ...] = ()
    tool_capability_changed: tuple[str, ...] = ()
    agent_capability_changed: tuple[str, ...] = ()
    credential_changed: tuple[str, ...] = ()
    dataflow_changed: tuple[str, ...] = ()
    control_changed: tuple[str, ...] = ()
    dependency_changed: tuple[str, ...] = ()


class AttackPathComparison(DomainModel):
    id: AttackPathComparisonId
    original_path_id: AttackPathId
    candidate_path_ids: tuple[AttackPathId, ...] = ()
    status: AttackPathComparisonStatus
    equivalent_security_impact: bool | None = None
    source_signature: tuple[str, ...] = ()
    sink_signature: tuple[str, ...] = ()
    evidence_ids: tuple[EvidenceId, ...] = ()
    rationale: str = Field(min_length=1, max_length=8192)


class ResidualPath(DomainModel):
    id: ResidualPathId
    verification_id: VerificationId
    path_id: AttackPathId
    security_property: str
    evidence_ids: tuple[EvidenceId, ...] = ()
    exploitable: bool | None = None
    equivalent_impact: bool = False
    description: str = Field(min_length=1, max_length=8192)


class VerificationEvidence(DomainModel):
    id: VerificationEvidenceId
    verification_id: VerificationId
    claim: str = Field(min_length=1, max_length=8192)
    evidence_ids: tuple[EvidenceId, ...] = ()
    artifact_ids: tuple[str, ...] = ()
    graph_diff_id: GraphDiffId | None = None
    attack_path_comparison_id: AttackPathComparisonId | None = None
    runtime_result_id: str | None = None
    provenance: tuple[Provenance, ...] = ()
    created_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def requires_reference(self) -> "VerificationEvidence":
        if not (self.evidence_ids or self.artifact_ids or self.graph_diff_id or self.attack_path_comparison_id or self.runtime_result_id):
            raise ValueError("verification evidence requires at least one traceable reference")
        return self


class SecurityRegression(DomainModel):
    id: SecurityRegressionId
    verification_id: VerificationId
    baseline_id: SecurityBaselineId | None = None
    status: RegressionStatus
    security_property: str
    evidence_ids: tuple[EvidenceId, ...] = ()
    attack_path_ids: tuple[AttackPathId, ...] = ()
    description: str = Field(min_length=1, max_length=8192)


class RegressionTest(DomainModel):
    id: RegressionTestId
    finding_id: FindingId
    verification_id: VerificationId
    security_property: str
    test_definition: dict[str, str]
    fixture: dict[str, str] = Field(default_factory=dict)
    expected_result: str
    version: str = Field(min_length=1, max_length=128)
    provenance: tuple[Provenance, ...] = ()
    created_at: datetime = Field(default_factory=utc_now)


class SecurityBaseline(DomainModel):
    id: SecurityBaselineId
    finding_id: FindingId
    verification_id: VerificationId
    security_property: str
    snapshot_id: SnapshotId
    attack_path_ids: tuple[AttackPathId, ...] = ()
    evidence_ids: tuple[EvidenceId, ...] = ()
    control_signatures: tuple[str, ...] = ()
    permission_signatures: tuple[str, ...] = ()
    identity_signatures: tuple[str, ...] = ()
    agent_capability_signatures: tuple[str, ...] = ()
    mcp_capability_signatures: tuple[str, ...] = ()
    regression_test_ids: tuple[RegressionTestId, ...] = ()
    created_at: datetime = Field(default_factory=utc_now)


class SecurityTestDefinition(DomainModel):
    test_id: str = Field(min_length=1, max_length=256)
    version: str = Field(min_length=1, max_length=128)
    snapshot_id: SnapshotId
    security_property: str = Field(min_length=1, max_length=8192)
    target: str = Field(min_length=1, max_length=2048)
    expected_result: str = Field(min_length=1, max_length=2048)
    input_digest: str | None = Field(default=None, max_length=128)
    timeout_seconds: int = Field(default=10, ge=1, le=300)
    network_policy: Literal["DENY_ALL", "LOOPBACK_ONLY", "EXPLICIT_ALLOWLIST"] = "DENY_ALL"
    filesystem_policy: Literal["FIXTURE_ONLY", "READ_ONLY", "ISOLATED_TEMP"] = "FIXTURE_ONLY"
    secret_policy: Literal["DENY_ALL"] = "DENY_ALL"


class SecurityTestResult(DomainModel):
    test_id: str
    test_version: str
    snapshot_id: SnapshotId
    executor: str
    executor_version: str
    expected_result: str
    actual_result: str
    passed: bool
    exit_code: int | None = None
    input_digest: str | None = None
    artifact_ids: tuple[str, ...] = ()
    evidence_ids: tuple[EvidenceId, ...] = ()
    started_at: datetime
    completed_at: datetime
    output_digest: str | None = None
    environment: dict[str, str] = Field(default_factory=dict)


class VerificationResult(DomainModel):
    verification_id: VerificationId
    finding_id: FindingId
    analysis_id: AnalysisId
    original_snapshot_id: SnapshotId
    candidate_snapshot_id: SnapshotId
    result: VerdictType
    security_property: str
    property_outcome: SecurityPropertyOutcome
    original_path_status: AttackPathComparisonStatus
    graph_diff_id: GraphDiffId | None = None
    attack_path_comparison_ids: tuple[AttackPathComparisonId, ...] = ()
    residual_path_ids: tuple[ResidualPathId, ...] = ()
    alternate_path_ids: tuple[AttackPathId, ...] = ()
    regression_ids: tuple[SecurityRegressionId, ...] = ()
    verification_evidence_ids: tuple[VerificationEvidenceId, ...] = ()
    supporting_evidence_ids: tuple[EvidenceId, ...] = ()
    contradicting_evidence_ids: tuple[EvidenceId, ...] = ()
    missing_evidence: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    checks: tuple[VerificationCheckResult, ...] = ()
    completeness_required: int = Field(ge=1)
    completeness_completed: int = Field(ge=0)
    created_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None

    @model_validator(mode="after")
    def result_invariants(self) -> "VerificationResult":
        if self.completeness_completed > self.completeness_required:
            raise ValueError("verification completeness exceeds required checks")
        if self.result == VerdictType.REMEDIATED:
            if self.property_outcome != SecurityPropertyOutcome.ELIMINATED:
                raise ValueError("REMEDIATED requires ELIMINATED security property outcome")
            if self.missing_evidence or self.contradicting_evidence_ids:
                raise ValueError("REMEDIATED cannot contain blocking missing or contradictory evidence")
            if self.completeness_completed < self.completeness_required:
                raise ValueError("REMEDIATED requires all checks complete")
            if not self.supporting_evidence_ids or not self.verification_evidence_ids:
                raise ValueError("REMEDIATED requires verification evidence")
            if self.original_path_status not in {AttackPathComparisonStatus.ORIGINAL_PATH_BROKEN, AttackPathComparisonStatus.PATH_WEAKENED}:
                raise ValueError("REMEDIATED requires the original path to be broken or explicitly weakened")
        if self.result == VerdictType.UNKNOWN and not self.missing_evidence:
            raise ValueError("UNKNOWN requires missing evidence")
        if self.result == VerdictType.REGRESSED and not self.regression_ids:
            raise ValueError("REGRESSED requires regression records")
        if self.result == VerdictType.REMEDIATION_FAILED and not (self.residual_path_ids or self.alternate_path_ids or self.contradicting_evidence_ids):
            raise ValueError("REMEDIATION_FAILED requires failure evidence")
        return self


class VerificationReport(DomainModel):
    verification_id: VerificationId
    finding_id: FindingId
    security_property: str
    original_snapshot_id: SnapshotId
    candidate_snapshot_id: SnapshotId
    original_attack_paths: tuple[AttackPathId, ...] = ()
    candidate_attack_paths: tuple[AttackPathId, ...] = ()
    removed_paths: tuple[AttackPathId, ...] = ()
    remaining_paths: tuple[AttackPathId, ...] = ()
    alternate_paths: tuple[AttackPathId, ...] = ()
    graph_diff_id: GraphDiffId | None = None
    attack_path_comparison_ids: tuple[AttackPathComparisonId, ...] = ()
    residual_path_ids: tuple[ResidualPathId, ...] = ()
    regressions: tuple[SecurityRegressionId, ...] = ()
    tests: tuple[SecurityTestResult, ...] = ()
    evidence: tuple[VerificationEvidenceId, ...] = ()
    limitations: tuple[str, ...] = ()
    result: VerdictType


__all__ = [
    "RemediationType","SecurityPropertyOutcome","VerificationCheck","CheckStatus",
    "AttackPathComparisonStatus","DiffKind","RegressionStatus","Remediation",
    "VerificationCheckResult","VerificationPlan","VerificationRun","GraphDiff",
    "AttackPathComparison","ResidualPath","VerificationEvidence","SecurityRegression",
    "RegressionTest","SecurityBaseline","SecurityTestDefinition","SecurityTestResult",
    "VerificationResult","VerificationReport",
]
