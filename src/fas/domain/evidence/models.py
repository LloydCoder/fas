"""Evidence contracts."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import Field, field_validator

from fas.domain.common import (
    ArtifactId, Confidence, DomainModel, EvidenceId, EvidenceType, IntegrityMetadata,
    ObservationId, Provenance, SourceLocation,
)


class Evidence(DomainModel):
    id: EvidenceId
    type: EvidenceType
    claim: str = Field(min_length=1, max_length=16384)
    source: SourceLocation | None = None
    observed_value: object | None = None
    provenance: tuple[Provenance, ...] = Field(min_length=1)
    confidence: Confidence | None = None
    integrity: IntegrityMetadata | None = None
    related_artifact_ids: tuple[ArtifactId, ...] = ()
    related_observation_ids: tuple[ObservationId, ...] = ()
    observed_at: datetime
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("observed_at")
    @classmethod
    def observation_time_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must be timezone-aware")
        return value.astimezone(timezone.utc)
