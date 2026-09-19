"""Remediation and verification contracts."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import Field, field_validator

from fas.domain.common import (
    AttackPathId, DomainModel, FindingId, RemediationId, RemediationStatus, SnapshotId,
    VerificationId, VerificationStatus, VerificationType,
)


class Remediation(DomainModel):
    id: RemediationId
    target_finding_id: FindingId
    original_snapshot_id: SnapshotId
    proposed_change_reference: str | None = Field(default=None, min_length=1, max_length=4096)
    actual_change_reference: str | None = Field(default=None, min_length=1, max_length=4096)
    patched_snapshot_id: SnapshotId | None = None
    expected_broken_path_ids: tuple[AttackPathId, ...] = ()
    status: RemediationStatus = RemediationStatus.PROPOSED
    created_at: datetime
    metadata: dict[str, str] = {}

    @field_validator("created_at")
    @classmethod
    def timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        return value


class Verification(DomainModel):
    id: VerificationId
    target_id: str = Field(min_length=1, max_length=128)
    target_type: VerificationType
    status: VerificationStatus = VerificationStatus.PENDING
    evidence_ids: tuple[str, ...] = ()
    before_snapshot_id: SnapshotId | None = None
    after_snapshot_id: SnapshotId | None = None
    attack_paths_before: tuple[AttackPathId, ...] = ()
    attack_paths_after: tuple[AttackPathId, ...] = ()
    residual_path_ids: tuple[AttackPathId, ...] = ()
    new_path_ids: tuple[AttackPathId, ...] = ()
    verified_at: datetime | None = None
    verifier: str | None = Field(default=None, min_length=1, max_length=1024)
    metadata: dict[str, str] = {}

    @field_validator("verified_at")
    @classmethod
    def timezone_required(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("verified_at must be timezone-aware")
        return value

    @model_validator(mode="after")
    def verification_consistency(self) -> "Verification":
        if self.status in {VerificationStatus.PASSED, VerificationStatus.FAILED} and not self.evidence_ids:
            raise ValueError("completed verification requires evidence_ids")
        if self.status == VerificationStatus.PASSED and self.verified_at is None:
            raise ValueError("passed verification requires verified_at")
        return self
