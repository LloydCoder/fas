"""Formal verdict contract and deterministic invariants."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import Field, field_validator, model_validator

from fas.domain.common import (
    AttackPathId, Confidence, DomainModel, EvidenceId, FindingId, MissingEvidence,
    VerdictId, VerdictType,
)


class Verdict(DomainModel):
    id: VerdictId
    verdict: VerdictType
    finding_id: FindingId
    confidence: Confidence
    rationale: str = Field(min_length=1, max_length=16384)
    supporting_evidence_ids: tuple[EvidenceId, ...] = ()
    contradicting_evidence_ids: tuple[EvidenceId, ...] = ()
    missing_evidence: tuple[MissingEvidence, ...] = ()
    conditions: tuple[str, ...] = ()
    attack_path_id: AttackPathId | None = None
    prior_verdict_id: VerdictId | None = None
    verifier: str | None = Field(default=None, min_length=1, max_length=1024)
    created_at: datetime
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("created_at")
    @classmethod
    def timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_verdict_invariants(self) -> "Verdict":
        v = self.verdict
        if v == VerdictType.EXPLOITABLE:
            if not self.supporting_evidence_ids:
                raise ValueError("EXPLOITABLE requires supporting evidence")
            if self.attack_path_id is None:
                raise ValueError("EXPLOITABLE requires an attack_path_id")
            if self.missing_evidence:
                raise ValueError("EXPLOITABLE cannot contain unresolved missing evidence")
        elif v == VerdictType.NOT_EXPLOITABLE:
            if not self.supporting_evidence_ids:
                raise ValueError("NOT_EXPLOITABLE requires evidence for the blocking condition")
        elif v == VerdictType.CONDITIONALLY_EXPLOITABLE:
            if not self.conditions:
                raise ValueError("CONDITIONALLY_EXPLOITABLE requires explicit conditions")
            if not self.supporting_evidence_ids:
                raise ValueError("CONDITIONALLY_EXPLOITABLE requires supporting evidence")
        elif v == VerdictType.UNKNOWN:
            if not self.missing_evidence:
                raise ValueError("UNKNOWN requires missing_evidence")
        elif v == VerdictType.REMEDIATED:
            if not self.supporting_evidence_ids:
                raise ValueError("REMEDIATED requires verification evidence")
        elif v == VerdictType.REMEDIATION_FAILED:
            if not self.supporting_evidence_ids:
                raise ValueError("REMEDIATION_FAILED requires residual/alternate evidence")
        elif v == VerdictType.REGRESSED:
            if self.prior_verdict_id is None:
                raise ValueError("REGRESSED requires prior_verdict_id")
            if not self.supporting_evidence_ids:
                raise ValueError("REGRESSED requires evidence of the regression")
        return self
