"""Governed autonomous research contracts.

The loop can propose hypotheses and request evidence, but authority remains with
existing collectors, evidence validation, verification, and verdict layers.
"""
from __future__ import annotations
from dataclasses import dataclass
from enum import StrEnum

class RequestKind(StrEnum):
    COLLECT="COLLECT"
    RECHECK="RECHECK"
    COMPARE="COMPARE"
    VERIFY="VERIFY"

class ApprovalState(StrEnum):
    PENDING="PENDING"
    APPROVED="APPROVED"
    DENIED="DENIED"

@dataclass(frozen=True, slots=True)
class Hypothesis:
    hypothesis_id:str
    statement:str
    confidence:float|None=None
    supporting_evidence_ids:tuple[str,...]=()
    limitations:tuple[str,...]=()

@dataclass(frozen=True, slots=True)
class EvidenceRequest:
    request_id:str
    kind:RequestKind
    target:str
    rationale:str
    hypothesis_id:str
    required_approval:bool=True
    approval:ApprovalState=ApprovalState.PENDING

@dataclass(frozen=True, slots=True)
class ResearchBudget:
    max_requests:int=32
    max_runtime_seconds:int=900
    max_hypotheses:int=128
    def __post_init__(self)->None:
        if self.max_requests<1 or self.max_runtime_seconds<1 or self.max_hypotheses<1:
            raise ValueError("research budget values must be positive")

@dataclass(frozen=True, slots=True)
class ResearchRun:
    run_id:str
    snapshot_id:str
    requests:tuple[EvidenceRequest,...]
    hypotheses:tuple[Hypothesis,...]
    completed_requests:int
    stopped_reason:str|None=None
    authoritative:bool=False
    def __post_init__(self)->None:
        if self.authoritative:
            raise ValueError("autonomous research cannot be authoritative")

class AuthorityBoundary:
    """Explicit guard preventing autonomous output from becoming a verdict."""
    @staticmethod
    def reject_authoritative_write() -> None:
        raise PermissionError("autonomous research cannot create authoritative evidence or verdicts")
