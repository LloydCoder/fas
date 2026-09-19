"""Complete Phase 3 collection lifecycle contracts."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping
from .base import CollectionContext, CollectionBatch, Collector

class CollectionStatus(str, Enum):
    SUCCESS="SUCCESS"; PARTIAL="PARTIAL"; FAILED="FAILED"; TIMEOUT="TIMEOUT"; CANCELLED="CANCELLED"
    UNSUPPORTED="UNSUPPORTED"; INVALID_INPUT="INVALID_INPUT"; TOOL_ERROR="TOOL_ERROR"; RESOURCE_LIMIT="RESOURCE_LIMIT"

class RetryDisposition(str, Enum):
    RETRY="RETRY"; DO_NOT_RETRY="DO_NOT_RETRY"

@dataclass(frozen=True, slots=True)
class CollectorSpec:
    name: str
    required: bool=True
    timeout_seconds: float=60.0
    max_attempts: int=1
    enabled: bool=True
    metadata: Mapping[str,str]=field(default_factory=dict)
    def __post_init__(self):
        if not self.name or self.timeout_seconds<=0 or self.max_attempts<1: raise ValueError("invalid collector spec")

@dataclass(frozen=True, slots=True)
class CollectionPlan:
    context: CollectionContext
    collectors: tuple[Collector,...]
    specs: tuple[CollectorSpec,...]=()
    fail_fast: bool=False
    def __post_init__(self):
        names=[c.name for c in self.collectors]
        if len(names)!=len(set(names)): raise ValueError("collector names must be unique")
        specs=self.specs or tuple(CollectorSpec(c.name) for c in self.collectors)
        if {s.name for s in specs}!={c.name for c in self.collectors}: raise ValueError("specs must match collectors")
        object.__setattr__(self,"specs",specs)

@dataclass(frozen=True, slots=True)
class CollectorOutcome:
    collector: str
    status: CollectionStatus
    attempts: int
    batch: CollectionBatch=CollectionBatch()
    error: str|None=None
    duration_ms: int=0
    retry: RetryDisposition=RetryDisposition.DO_NOT_RETRY

@dataclass(frozen=True, slots=True)
class CollectionSummary:
    status: CollectionStatus
    outcomes: tuple[CollectorOutcome,...]
    artifacts: int
    observations: int
    skipped: int
    warnings: tuple[str,...]=()
    def __post_init__(self):
        if self.artifacts<0 or self.observations<0 or self.skipped<0: raise ValueError("counts cannot be negative")

@dataclass(frozen=True, slots=True)
class CollectionResult:
    plan: CollectionPlan
    outcomes: tuple[CollectorOutcome,...]
    batch: CollectionBatch
    summary: CollectionSummary
    run_id: str
    replayable: bool=True
