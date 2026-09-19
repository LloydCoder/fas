"""Phase 3 collection contracts."""
from __future__ import annotations
from dataclasses import dataclass,field
from pathlib import Path
from typing import Protocol
from fas.domain.analysis import Artifact,Observation
from fas.domain.common import AnalysisId,SnapshotId
@dataclass(frozen=True,slots=True)
class CollectionContext:
    analysis_id:AnalysisId
    snapshot_id:SnapshotId
    root:Path
    repository:str
    revision:str|None=None
    max_files:int=100_000
    max_file_bytes:int=5*1024*1024
    def __post_init__(self):
        if self.max_files<1 or self.max_file_bytes<1:
            raise ValueError("collection limits must be positive")
        root=self.root.expanduser().resolve()
        if not root.is_dir(): raise ValueError(f"collection root is not a directory:
            {root}")
        object.__setattr__(self,"root",root)
@dataclass(frozen=True,slots=True)
class CollectionBatch:
    artifacts:tuple[Artifact,...]=()
    observations:tuple[Observation,...]=()
    complete:bool=True
    skipped:int=0
    warnings:tuple[str,...]=()
    raw_artifacts:tuple[object,...]=()
    tool_runs:tuple[object,...]=()
class CollectionError(RuntimeError): pass
class Collector(Protocol):
    name:str
    def collect(self,context:CollectionContext)->CollectionBatch: ...
@dataclass(slots=True)
class _BatchBuilder:
    artifacts:list[Artifact]=field(default_factory=list)
    observations:list[Observation]=field(default_factory=list)
    warnings:list[str]=field(default_factory=list)
    skipped:int=0
    complete:bool=True
    raw_artifacts:list[object]=field(default_factory=list)
    tool_runs:list[object]=field(default_factory=list)
    def build(self)->CollectionBatch:
        return CollectionBatch(tuple(self.artifacts),tuple(self.observations),self.complete,self.skipped,tuple(self.warnings),tuple(self.raw_artifacts),tuple(self.tool_runs))
