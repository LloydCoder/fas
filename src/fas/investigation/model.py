"""Model-agnostic constrained investigator provider contracts."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol
from pydantic import BaseModel, ConfigDict, Field

class ModelToolCall(BaseModel):
    model_config=ConfigDict(extra="forbid",frozen=True)
    name:str=Field(min_length=1,max_length=128)
    arguments:dict[str,str]=Field(default_factory=dict)

class InvestigatorRequest(BaseModel):
    model_config=ConfigDict(extra="forbid",frozen=True)
    prompt_version:str=Field(min_length=1,max_length=64)
    objective:str=Field(min_length=1,max_length=8192)
    context:dict[str,str]=Field(default_factory=dict)
    allowed_tools:tuple[str,...]=()
    max_tokens:int|None=Field(default=None,ge=1,max=200000)

class InvestigatorResponse(BaseModel):
    model_config=ConfigDict(extra="forbid",frozen=True)
    kind:str=Field(min_length=1,max_length=64)
    payload:dict[str,str]=Field(default_factory=dict)
    tool_calls:tuple[ModelToolCall,...]=()
    model_id:str=Field(min_length=1,max_length=256)
    usage_tokens:int|None=Field(default=None,ge=0)
    termination_reason:str=Field(min_length=1,max_length=256)

class InvestigatorModel(Protocol):
    model_id:str
    def request(self, request:InvestigatorRequest, *, timeout_seconds:float) -> InvestigatorResponse: ...

@dataclass(frozen=True)
class DeterministicFakeModel:
    model_id:str="fake-investigator-v1"
    prompt_version:str="phase4-v1"
    response_kind:str="hypothesis"
    def request(self, request:InvestigatorRequest, *, timeout_seconds:float) -> InvestigatorResponse:
        if request.prompt_version != self.prompt_version:
            raise ValueError("unsupported investigator prompt version")
        return InvestigatorResponse(
            kind=self.response_kind,
            payload={"statement":"Investigate the candidate finding using deterministic evidence tools."},
            model_id=self.model_id,
            termination_reason="FIXTURE_COMPLETE",
        )

__all__=["ModelToolCall","InvestigatorRequest","InvestigatorResponse","InvestigatorModel","DeterministicFakeModel"]
