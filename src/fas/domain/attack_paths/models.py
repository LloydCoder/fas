"""Concrete attack-path contract. Discovery/traversal is deferred."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import Field, field_validator, model_validator

from fas.domain.common import AttackPathId, Confidence, DomainModel, EdgeId, EvidenceId, NodeId, SnapshotId


class AttackPathStep(DomainModel):
    node_id: NodeId
    edge_id: EdgeId
    next_node_id: NodeId
    evidence_ids: tuple[EvidenceId, ...] = ()
    security_critical: bool = True

    @model_validator(mode="after")
    def critical_steps_need_evidence(self) -> "AttackPathStep":
        if self.security_critical and not self.evidence_ids:
            raise ValueError("security-critical attack-path steps require evidence")
        if self.node_id == self.next_node_id:
            raise ValueError("attack-path step cannot connect a node to itself")
        return self


class AttackPath(DomainModel):
    id: AttackPathId
    entry: NodeId
    steps: tuple[AttackPathStep, ...] = Field(min_length=1)
    trust_boundaries_crossed: tuple[NodeId, ...] = ()
    supporting_evidence_ids: tuple[EvidenceId, ...] = ()
    confidence: Confidence | None = None
    snapshot_id: SnapshotId
    observed_at: datetime
    status: Literal["COMPLETE", "PARTIAL", "TRUNCATED"] = "COMPLETE"
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("observed_at")
    @classmethod
    def timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_support(self) -> "AttackPath":
        step_evidence = {e for step in self.steps for e in step.evidence_ids}
        if not self.supporting_evidence_ids and not step_evidence:
            raise ValueError("attack path requires supporting evidence")
        return self
