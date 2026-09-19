"""Analysis, snapshot, artifact, and observation contracts."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, field_validator, model_validator

from fas.domain.common import (
    AnalysisId, AnalysisStatus, ArtifactId, ArtifactType, ContentHash,
    DomainModel, ObservationId, Provenance, RepositoryReference, SnapshotId, SourceLocation,
    utc_now,
)


class Analysis(DomainModel):
    id: AnalysisId
    project: str = Field(min_length=1, max_length=2048)
    status: AnalysisStatus = AnalysisStatus.CREATED
    created_at: datetime = Field(default_factory=utc_now)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    snapshot_ids: tuple[SnapshotId, ...] = ()
    configuration_ref: str | None = Field(default=None, min_length=1, max_length=2048)
    metadata: dict[str, str] = Field(default_factory=dict)
    failure_reason: str | None = Field(default=None, min_length=1, max_length=4096)

    @model_validator(mode="after")
    def validate_timestamps(self) -> "Analysis":
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        if self.started_at is not None and self.started_at < self.created_at:
            raise ValueError("started_at cannot precede created_at")
        if self.completed_at is not None:
            if self.completed_at < self.created_at:
                raise ValueError("completed_at cannot precede created_at")
            if self.started_at is not None and self.completed_at < self.started_at:
                raise ValueError("completed_at cannot precede started_at")
        if self.status in {AnalysisStatus.FAILED, AnalysisStatus.CANCELLED} and not self.failure_reason:
            raise ValueError("failed/cancelled analyses require failure_reason")
        return self


class Snapshot(DomainModel):
    id: SnapshotId
    repository: RepositoryReference
    captured_at: datetime
    content_hash: ContentHash | None = None
    source_reference: str = Field(min_length=1, max_length=2048)
    environment_identity: str | None = Field(default=None, min_length=1, max_length=2048)
    configuration_identity: str | None = Field(default=None, min_length=1, max_length=2048)
    artifact_ids: tuple[ArtifactId, ...] = ()
    immutable: bool = True

    @field_validator("captured_at")
    @classmethod
    def timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("captured_at must be timezone-aware")
        return value


class Artifact(DomainModel):
    id: ArtifactId
    type: ArtifactType
    name: str = Field(min_length=1, max_length=4096)
    media_type: str | None = Field(default=None, min_length=1, max_length=256)
    size_bytes: int | None = Field(default=None, ge=0)
    content_hash: ContentHash | None = None
    snapshot_id: SnapshotId
    provenance: tuple[Provenance, ...] = Field(min_length=1)
    external_reference: str | None = Field(default=None, min_length=1, max_length=4096)
    metadata: dict[str, str] = Field(default_factory=dict)


class Observation(DomainModel):
    id: ObservationId
    source: str = Field(min_length=1, max_length=512)
    category: str = Field(min_length=1, max_length=512)
    location: SourceLocation | None = None
    message: str = Field(min_length=1, max_length=16384)
    raw_reference: str | None = Field(default=None, min_length=1, max_length=4096)
    raw_artifact_id: ArtifactId | None = None
    observed_value: object | None = None
    provenance: tuple[Provenance, ...] = Field(min_length=1)
    observed_at: datetime
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("observed_at")
    @classmethod
    def observation_time_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must be timezone-aware")
        return value.astimezone(__import__("datetime").timezone.utc)
