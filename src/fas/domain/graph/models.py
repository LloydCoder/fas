"""Evidence graph node and edge contracts."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import Field, field_validator, model_validator

from fas.domain.common import (
    AnalysisId,
    Confidence,
    DomainModel,
    EdgeId,
    EvidenceId,
    GraphNodeType,
    NodeId,
    Provenance,
    RelationshipType,
    SnapshotId,
)


class GraphNode(DomainModel):
    id: NodeId
    type: GraphNodeType
    label: str = Field(min_length=1, max_length=2048)
    analysis_id: AnalysisId
    snapshot_id: SnapshotId
    canonical_identity: str = Field(min_length=1, max_length=4096)
    evidence_ids: tuple[EvidenceId, ...] = ()
    provenance: tuple[Provenance, ...] = Field(min_length=1)
    security_relevant: bool = False
    metadata: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def security_nodes_require_evidence(self) -> "GraphNode":
        if self.security_relevant and not self.evidence_ids:
            raise ValueError("security-relevant graph nodes require evidence_ids")
        return self


class GraphEdge(DomainModel):
    id: EdgeId
    source_node_id: NodeId
    target_node_id: NodeId
    relationship_type: RelationshipType
    analysis_id: AnalysisId
    snapshot_id: SnapshotId
    confidence: Confidence | None = None
    provenance: tuple[Provenance, ...] = Field(min_length=1)
    evidence_ids: tuple[EvidenceId, ...] = ()
    observed_at: datetime
    security_relevant: bool = False
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("observed_at")
    @classmethod
    def timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def security_edges_require_evidence(self) -> "GraphEdge":
        if self.security_relevant and not self.evidence_ids:
            raise ValueError("security-relevant graph edges require evidence_ids")
        return self
