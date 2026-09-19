"""Canonical audit, report, and tool-run contracts."""
from __future__ import annotations
from datetime import datetime
from pydantic import Field, field_validator
from .common import AnalysisId, AuditEventId, DomainModel, JSONValue, ReportId, SnapshotId, ToolRunId, utc_now

class AuditEvent(DomainModel):
    id: AuditEventId
    analysis_id: AnalysisId
    snapshot_id: SnapshotId
    event_type: str = Field(min_length=1,max_length=256)
    actor: str = Field(min_length=1,max_length=512)
    subject_id: str = Field(min_length=1,max_length=256)
    payload: dict[str,JSONValue] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    @field_validator("created_at")
    @classmethod
    def timezone_required(cls,value:datetime)->datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        return value

class ToolRun(DomainModel):
    id: ToolRunId
    analysis_id: AnalysisId
    snapshot_id: SnapshotId
    tool_name: str = Field(min_length=1,max_length=256)
    tool_version: str|None = Field(default=None,max_length=128)
    argv: tuple[str,...]
    cwd: str = Field(min_length=1,max_length=4096)
    environment_fingerprint: str = Field(min_length=1,max_length=256)
    configuration_fingerprint: str|None = Field(default=None,max_length=256)
    started_at: datetime
    completed_at: datetime|None = None
    exit_code: int|None = None
    status: str = Field(min_length=1,max_length=64)
    stdout_hash: str|None = Field(default=None,max_length=128)
    stderr_hash: str|None = Field(default=None,max_length=128)
    raw_artifact_id: str|None = Field(default=None,max_length=128)

class Report(DomainModel):
    id: ReportId
    analysis_id: AnalysisId
    snapshot_id: SnapshotId
    title: str = Field(min_length=1,max_length=1024)
    finding_ids: tuple[str,...] = ()
    investigation_ids: tuple[str,...] = ()
    verdict_ids: tuple[str,...] = ()
    generated_at: datetime = Field(default_factory=utc_now)
    format: str = Field(default="json",min_length=1,max_length=32)
    content: dict[str,JSONValue] = Field(default_factory=dict)

__all__=["AuditEvent","ToolRun","Report"]
