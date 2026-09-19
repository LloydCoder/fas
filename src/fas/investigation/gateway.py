"""Constrained model gateway: validates structured output and tool authorization outside the model."""
from __future__ import annotations
from dataclasses import dataclass, field
from .model import InvestigatorModel, InvestigatorRequest, InvestigatorResponse
from fas.domain.investigation import ToolPolicy

class ModelOutputRejected(ValueError):
    pass

@dataclass(frozen=True)
class ConstrainedInvestigator:
    model: InvestigatorModel
    policy: ToolPolicy = field(default_factory=ToolPolicy)
    timeout_seconds: float = 30.0

    def request(self, request: InvestigatorRequest) -> InvestigatorResponse:
        allowed=tuple(sorted(set(request.allowed_tools) & self.policy.allowed_tools))
        safe=request.model_copy(update={"allowed_tools":allowed})
        response=self.model.request(safe,timeout_seconds=self.timeout_seconds)
        for call in response.tool_calls:
            if call.name not in self.policy.allowed_tools or call.name in self.policy.denied_tools:
                raise ModelOutputRejected(f"unauthorized investigator tool: {call.name}")
        if response.kind not in {"hypothesis","evidence_request","attack_path_proposal","verdict_proposal","question"}:
            raise ModelOutputRejected("unsupported structured investigator response kind")
        return response
