"""Finding contract. Findings are correlated conditions, not raw observations."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import Field, field_validator

from fas.domain.common import (
    AttackPathId, DomainModel, EvidenceId, FindingId, FindingStatus, NodeId, ObservationId,
    Severity, SnapshotId, SourceLocation,
)


class Finding(DomainModel):
    id: FindingId
    title: str = Field(min_length=1, max_length=1024)
    description: str = Field(default="", max_length=16384)
    category: str = Field(min_length=1, max_length=512)
    severity: Severity = Severity.UNKNOWN
    status: FindingStatus = FindingStatus.CANDIDATE
    affected_locations: tuple[SourceLocation, ...] = ()
    supporting_evidence_ids: tuple[EvidenceId, ...] = ()
    contradicting_evidence_ids: tuple[EvidenceId, ...] = ()
    related_observation_ids: tuple[ObservationId, ...] = ()
    involved_node_ids: tuple[NodeId, ...] = ()
    attack_path_ids: tuple[AttackPathId, ...] = ()
    snapshot_id: SnapshotId
    created_at: datetime
    updated_at: datetime
    metadata: dict[str, str] = {}

    @field_validator("created_at", "updated_at")
    @classmethod
    def timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("finding timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)

    @field_validator("updated_at")
    @classmethod
    def not_before_creation(cls, value: datetime, info):
        created = info.data.get("created_at")
        if created is not None and value < created:
            raise ValueError("updated_at cannot precede created_at")
        return value
