"""Shared FAS domain primitives and invariants."""

from __future__ import annotations

import json
import re
import secrets
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated
from typing_extensions import TypeAliasType

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

SCHEMA_VERSION = "1.0"

JSONValue = TypeAliasType(
    "JSONValue",
    dict[str, "JSONValue"] | list["JSONValue"] | str | int | float | bool | None,
)


def _ulid() -> str:
    """Generate a sortable 26-character ULID using only the standard library."""
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    value = (int(time.time_ns() // 1_000_000) << 80) | secrets.randbits(80)
    chars: list[str] = []
    for _ in range(26):
        chars.append(alphabet[value & 31])
        value >>= 5
    return "".join(reversed(chars))


def new_id(prefix: str) -> str:
    if not re.fullmatch(r"[a-z][a-z0-9_]*", prefix):
        raise ValueError("invalid FAS identifier prefix")
    return f"{prefix}_{_ulid()}"


FasId = Annotated[str, StringConstraints(min_length=4, max_length=64, pattern=r"^[a-z][a-z0-9_]*_[0-9A-HJKMNP-TV-Z]{26}$")]
AnalysisId = Annotated[FasId, StringConstraints(pattern=r"^analysis_[0-9A-HJKMNP-TV-Z]{26}$")]
SnapshotId = Annotated[FasId, StringConstraints(pattern=r"^snapshot_[0-9A-HJKMNP-TV-Z]{26}$")]
ProjectId = Annotated[FasId, StringConstraints(pattern=r"^project_[0-9A-HJKMNP-TV-Z]{26}$")]
ArtifactId = Annotated[FasId, StringConstraints(pattern=r"^artifact_[0-9A-HJKMNP-TV-Z]{26}$")]
ObservationId = Annotated[FasId, StringConstraints(pattern=r"^observation_[0-9A-HJKMNP-TV-Z]{26}$")]
EvidenceId = Annotated[FasId, StringConstraints(pattern=r"^evidence_[0-9A-HJKMNP-TV-Z]{26}$")]
NodeId = Annotated[FasId, StringConstraints(pattern=r"^node_[0-9A-HJKMNP-TV-Z]{26}$")]
EdgeId = Annotated[FasId, StringConstraints(pattern=r"^edge_[0-9A-HJKMNP-TV-Z]{26}$")]
FindingId = Annotated[FasId, StringConstraints(pattern=r"^finding_[0-9A-HJKMNP-TV-Z]{26}$")]
AttackPathId = Annotated[FasId, StringConstraints(pattern=r"^attack_path_[0-9A-HJKMNP-TV-Z]{26}$")]
VerdictId = Annotated[FasId, StringConstraints(pattern=r"^verdict_[0-9A-HJKMNP-TV-Z]{26}$")]
RemediationId = Annotated[FasId, StringConstraints(pattern=r"^remediation_[0-9A-HJKMNP-TV-Z]{26}$")]
VerificationId = Annotated[FasId, StringConstraints(pattern=r"^verification_[0-9A-HJKMNP-TV-Z]{26}$")]
InvestigationId = Annotated[FasId, StringConstraints(pattern=r"^investigation_[0-9A-HJKMNP-TV-Z]{26}$")]
HypothesisId = Annotated[FasId, StringConstraints(pattern=r"^hypothesis_[0-9A-HJKMNP-TV-Z]{26}$")]
EvidenceRequestId = Annotated[FasId, StringConstraints(pattern=r"^evidence_request_[0-9A-HJKMNP-TV-Z]{26}$")]
InvestigationEventId = Annotated[FasId, StringConstraints(pattern=r"^investigation_event_[0-9A-HJKMNP-TV-Z]{26}$")]
InvestigatorToolCallId = Annotated[FasId, StringConstraints(pattern=r"^tool_call_[0-9A-HJKMNP-TV-Z]{26}$")]
ControlId = Annotated[FasId, StringConstraints(pattern=r"^control_[0-9A-HJKMNP-TV-Z]{26}$")]
AuditEventId = Annotated[FasId, StringConstraints(pattern=r"^audit_event_[0-9A-HJKMNP-TV-Z]{26}$")]
ReportId = Annotated[FasId, StringConstraints(pattern=r"^report_[0-9A-HJKMNP-TV-Z]{26}$")]
ToolRunId = Annotated[FasId, StringConstraints(pattern=r"^tool_run_[0-9A-HJKMNP-TV-Z]{26}$")]
VerificationPlanId = Annotated[FasId, StringConstraints(pattern=r"^verification_plan_[0-9A-HJKMNP-TV-Z]{26}$")]
VerificationRunId = Annotated[FasId, StringConstraints(pattern=r"^verification_run_[0-9A-HJKMNP-TV-Z]{26}$")]
GraphDiffId = Annotated[FasId, StringConstraints(pattern=r"^graph_diff_[0-9A-HJKMNP-TV-Z]{26}$")]
AttackPathComparisonId = Annotated[FasId, StringConstraints(pattern=r"^attack_path_comparison_[0-9A-HJKMNP-TV-Z]{26}$")]
ResidualPathId = Annotated[FasId, StringConstraints(pattern=r"^residual_path_[0-9A-HJKMNP-TV-Z]{26}$")]
SecurityRegressionId = Annotated[FasId, StringConstraints(pattern=r"^security_regression_[0-9A-HJKMNP-TV-Z]{26}$")]
VerificationEvidenceId = Annotated[FasId, StringConstraints(pattern=r"^verification_evidence_[0-9A-HJKMNP-TV-Z]{26}$")]
RegressionTestId = Annotated[FasId, StringConstraints(pattern=r"^regression_test_[0-9A-HJKMNP-TV-Z]{26}$")]
SecurityBaselineId = Annotated[FasId, StringConstraints(pattern=r"^security_baseline_[0-9A-HJKMNP-TV-Z]{26}$")]


class DomainModel(BaseModel):
    """Immutable canonical model with deterministic JSON support."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_assignment=True,
    )
    schema_version: str = Field(default=SCHEMA_VERSION, min_length=1, max_length=32)

    def canonical_json(self) -> str:
        return json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class FasEnum(str, Enum):
    pass


class InvestigationStatus(FasEnum):
    CREATED = "CREATED"
    PLANNING = "PLANNING"
    COLLECTING = "COLLECTING"
    ANALYZING = "ANALYZING"
    AWAITING_EVIDENCE = "AWAITING_EVIDENCE"
    READY_FOR_VERDICT = "READY_FOR_VERDICT"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class HypothesisStatus(FasEnum):
    SUPPORTED = "SUPPORTED"
    REFUTED = "REFUTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    UNRESOLVED = "UNRESOLVED"


class EvidenceRequestType(FasEnum):
    FILE = "FILE"; CODE_LOCATION = "CODE_LOCATION"; SYMBOL = "SYMBOL"; CALLERS = "CALLERS"
    CALLEES = "CALLEES"; DATAFLOW = "DATAFLOW"; CONTROL_FLOW = "CONTROL_FLOW"
    DEPENDENCY = "DEPENDENCY"; CONFIGURATION = "CONFIGURATION"; IDENTITY = "IDENTITY"
    PERMISSION = "PERMISSION"; ENDPOINT = "ENDPOINT"; AGENT = "AGENT"; TOOL = "TOOL"
    MCP = "MCP"; TRUST_BOUNDARY = "TRUST_BOUNDARY"; RUNTIME_TEST = "RUNTIME_TEST"; GRAPH_PATH = "GRAPH_PATH"


class InvestigationToolStatus(FasEnum):
    SUCCESS = "SUCCESS"; PARTIAL = "PARTIAL"; EMPTY = "EMPTY"; UNSUPPORTED = "UNSUPPORTED"; FAILED = "FAILED"


class InvestigationEventType(FasEnum):
    CREATED = "CREATED"; HYPOTHESIS_CREATED = "HYPOTHESIS_CREATED"; EVIDENCE_REQUESTED = "EVIDENCE_REQUESTED"
    EVIDENCE_ACQUIRED = "EVIDENCE_ACQUIRED"; GRAPH_QUERIED = "GRAPH_QUERIED"; TOOL_INVOKED = "TOOL_INVOKED"
    TOOL_RESULT = "TOOL_RESULT"; HYPOTHESIS_UPDATED = "HYPOTHESIS_UPDATED"; ATTACK_PATH_PROPOSED = "ATTACK_PATH_PROPOSED"
    ATTACK_PATH_VALIDATED = "ATTACK_PATH_VALIDATED"; VERDICT_PROPOSED = "VERDICT_PROPOSED"; STATE_CHANGED = "STATE_CHANGED"
    CANCELLED = "CANCELLED"; FAILED = "FAILED"


class AnalysisStatus(FasEnum):
    CREATED = "CREATED"
    INGESTING = "INGESTING"
    DISCOVERING = "DISCOVERING"
    COLLECTING = "COLLECTING"
    NORMALIZING = "NORMALIZING"
    GRAPH_BUILDING = "GRAPH_BUILDING"
    ANALYZING = "ANALYZING"
    VERIFYING = "VERIFYING"
    VERDICT_READY = "VERDICT_READY"
    REMEDIATION_PENDING = "REMEDIATION_PENDING"
    REMEDIATION_ANALYZING = "REMEDIATION_ANALYZING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    CANCELLED = "CANCELLED"


class ArtifactType(FasEnum):
    SOURCE_FILE = "SOURCE_FILE"
    GENERATED_FILE = "GENERATED_FILE"
    CONFIGURATION = "CONFIGURATION"
    DEPENDENCY_METADATA = "DEPENDENCY_METADATA"
    SARIF = "SARIF"
    TOOL_OUTPUT = "TOOL_OUTPUT"
    RUNTIME_CAPTURE = "RUNTIME_CAPTURE"
    TEST_RESULT = "TEST_RESULT"
    BINARY = "BINARY"
    PACKAGE = "PACKAGE"
    EVIDENCE_BUNDLE = "EVIDENCE_BUNDLE"


class ProvenanceCategory(FasEnum):
    HUMAN_ASSERTION = "HUMAN_ASSERTION"
    LLM_INFERENCE = "LLM_INFERENCE"
    TOOL_OBSERVATION = "TOOL_OBSERVATION"
    VERIFIED_ARTIFACT = "VERIFIED_ARTIFACT"
    RUNTIME_OBSERVATION = "RUNTIME_OBSERVATION"
    SECURITY_TEST = "SECURITY_TEST"


class ProvenanceLevel(FasEnum):
    T0 = "T0"
    T1 = "T1"
    T2 = "T2"
    T3 = "T3"
    T4 = "T4"
    T5 = "T5"


class EvidenceType(FasEnum):
    CODE = "CODE"
    CODE_LOCATION = "CODE_LOCATION"
    DATA_FLOW = "DATA_FLOW"
    CALL_GRAPH = "CALL_GRAPH"
    CONFIGURATION = "CONFIGURATION"
    DEPENDENCY = "DEPENDENCY"
    IDENTITY = "IDENTITY"
    PERMISSION = "PERMISSION"
    NETWORK = "NETWORK"
    RUNTIME = "RUNTIME"
    TEST = "TEST"
    POLICY = "POLICY"
    TOOL_OUTPUT = "TOOL_OUTPUT"
    HUMAN_ASSERTION = "HUMAN_ASSERTION"


class GraphNodeType(FasEnum):
    REPOSITORY = "REPOSITORY"
    FILE = "FILE"
    SYMBOL = "SYMBOL"
    CODE_LOCATION = "CODE_LOCATION"
    PACKAGE = "PACKAGE"
    DEPENDENCY = "DEPENDENCY"
    SERVICE = "SERVICE"
    ENDPOINT = "ENDPOINT"
    REQUEST = "REQUEST"
    DATA_ASSET = "DATA_ASSET"
    IDENTITY = "IDENTITY"
    PRINCIPAL = "PRINCIPAL"
    ROLE = "ROLE"
    PERMISSION = "PERMISSION"
    AGENT = "AGENT"
    AGENT_TASK = "AGENT_TASK"
    TOOL = "TOOL"
    MCP_SERVER = "MCP_SERVER"
    MCP_TOOL = "MCP_TOOL"
    CREDENTIAL = "CREDENTIAL"
    SECRET = "SECRET"
    CONFIGURATION = "CONFIGURATION"
    INFRASTRUCTURE_RESOURCE = "INFRASTRUCTURE_RESOURCE"
    TRUST_BOUNDARY = "TRUST_BOUNDARY"
    FINDING = "FINDING"
    EVIDENCE = "EVIDENCE"
    ATTACK_PATH = "ATTACK_PATH"
    REMEDIATION = "REMEDIATION"
    CONTROL = "CONTROL"
    RUNTIME_OBSERVATION = "RUNTIME_OBSERVATION"
    TEST = "TEST"


class RelationshipType(FasEnum):
    CONTAINS = "CONTAINS"
    DEFINES = "DEFINES"
    CALLS = "CALLS"
    READS = "READS"
    WRITES = "WRITES"
    FLOWS_TO = "FLOWS_TO"
    IMPLEMENTED_BY = "IMPLEMENTED_BY"
    HAS_PERMISSION = "HAS_PERMISSION"
    CAN_USE = "CAN_USE"
    EXECUTES = "EXECUTES"
    TRUSTED_BY = "TRUSTED_BY"
    EXPOSES = "EXPOSES"
    INVOKES = "INVOKES"
    AUTHENTICATES_AS = "AUTHENTICATES_AS"
    CAN_ACCESS = "CAN_ACCESS"
    CAN_MODIFY = "CAN_MODIFY"
    LOCATED_AT = "LOCATED_AT"
    SUPPORTED_BY = "SUPPORTED_BY"
    INVOLVES = "INVOLVES"
    PART_OF = "PART_OF"
    STARTS_AT = "STARTS_AT"
    PASSES_THROUGH = "PASSES_THROUGH"
    ENDS_AT = "ENDS_AT"
    MODIFIES = "MODIFIES"
    BREAKS = "BREAKS"
    VERIFIED_BY = "VERIFIED_BY"


class FindingStatus(FasEnum):
    CANDIDATE = "CANDIDATE"
    INVESTIGATING = "INVESTIGATING"
    VERIFIED = "VERIFIED"
    CLOSED = "CLOSED"


class Severity(FasEnum):
    UNKNOWN = "UNKNOWN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class VerdictType(FasEnum):
    EXPLOITABLE = "EXPLOITABLE"
    NOT_EXPLOITABLE = "NOT_EXPLOITABLE"
    CONDITIONALLY_EXPLOITABLE = "CONDITIONALLY_EXPLOITABLE"
    REMEDIATED = "REMEDIATED"
    REMEDIATION_FAILED = "REMEDIATION_FAILED"
    REGRESSED = "REGRESSED"
    UNKNOWN = "UNKNOWN"


class RemediationStatus(FasEnum):
    PROPOSED = "PROPOSED"
    PLANNED = "PLANNED"
    APPLIED = "APPLIED"
    READY_FOR_VERIFICATION = "READY_FOR_VERIFICATION"
    VERIFYING = "VERIFYING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    CANCELLED = "CANCELLED"


class VerificationTargetType(FasEnum):
    FINDING = "FINDING"
    REMEDIATION = "REMEDIATION"
    VERDICT = "VERDICT"
    ATTACK_PATH = "ATTACK_PATH"
    CLAIM = "CLAIM"


class VerificationType(FasEnum):
    REMEDIATION = "REMEDIATION"
    EXPLOITABILITY = "EXPLOITABILITY"
    REGRESSION = "REGRESSION"
    SECURITY_TEST = "SECURITY_TEST"


class VerificationStatus(FasEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    PASSED = "PASSED"
    INCONCLUSIVE = "INCONCLUSIVE"
    CREATED = "CREATED"
    PLANNING = "PLANNING"
    COLLECTING = "COLLECTING"
    COMPARING = "COMPARING"
    REANALYZING = "REANALYZING"
    TESTING = "TESTING"
    VERIFYING = "VERIFYING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ActorType(FasEnum):
    SYSTEM = "SYSTEM"
    HUMAN = "HUMAN"
    TOOL = "TOOL"
    LLM = "LLM"
    RUNTIME = "RUNTIME"


class Confidence(DomainModel):
    value: float = Field(ge=0.0, le=1.0)


class ContentHash(DomainModel):
    algorithm: str = Field(default="sha256", pattern=r"^sha256$")
    digest: str = Field(pattern=r"^[0-9a-fA-F]{64}$")

    @property
    def value(self) -> str:
        return f"{self.algorithm}:{self.digest.lower()}"

    @classmethod
    def parse(cls, value: str) -> "ContentHash":
        if not isinstance(value, str) or not value.startswith("sha256:"):
            raise ValueError("content hash must use sha256:<64-hex> form")
        return cls(digest=value[7:])


class IntegrityMetadata(DomainModel):
    content_hash: ContentHash
    verified: bool = False
    verification_method: str | None = Field(default=None, min_length=1, max_length=256)


class RepositoryReference(DomainModel):
    repository: str = Field(min_length=1, max_length=2048)
    revision: str | None = Field(default=None, min_length=1, max_length=512)
    ref: str | None = Field(default=None, min_length=1, max_length=512)


class ArtifactReference(DomainModel):
    artifact_id: ArtifactId


class SourceLocation(DomainModel):
    artifact_id: ArtifactId
    path: str = Field(min_length=1, max_length=4096)
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    column_start: int | None = Field(default=None, ge=1)
    column_end: int | None = Field(default=None, ge=1)
    symbol: str | None = Field(default=None, min_length=1, max_length=1024)
    commit: str | None = Field(default=None, min_length=1, max_length=512)

    @model_validator(mode="after")
    def validate_range(self) -> "SourceLocation":
        if self.line_start is None and self.line_end is not None:
            raise ValueError("line_end requires line_start")
        if self.line_start is not None and self.line_end is not None and self.line_end < self.line_start:
            raise ValueError("line_end cannot precede line_start")
        if self.column_start is None and self.column_end is not None:
            raise ValueError("column_end requires column_start")
        if self.column_start is not None and self.column_end is not None and self.column_end < self.column_start:
            raise ValueError("column_end cannot precede column_start")
        return self


class Provenance(DomainModel):
    category: ProvenanceCategory
    level: ProvenanceLevel
    collector: str = Field(min_length=1, max_length=256)
    collector_version: str | None = Field(default=None, min_length=1, max_length=128)
    method: str = Field(min_length=1, max_length=256)
    source: str = Field(min_length=1, max_length=2048)
    observed_at: datetime
    parent_evidence_ids: tuple[EvidenceId, ...] = ()
    tool_execution_ref: str | None = Field(default=None, min_length=1, max_length=1024)
    actor_type: ActorType = ActorType.SYSTEM
    integrity: IntegrityMetadata | None = None

    @field_validator("observed_at")
    @classmethod
    def timestamp_is_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("provenance timestamp must be timezone-aware")
        return value.astimezone(timezone.utc)


class MissingEvidence(DomainModel):
    description: str = Field(min_length=1, max_length=4096)
    required_for: str | None = Field(default=None, min_length=1, max_length=512)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
