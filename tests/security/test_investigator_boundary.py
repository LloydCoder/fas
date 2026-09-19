import pytest
from fas.investigation import ConstrainedInvestigator, InvestigatorRequest
from fas.investigation.gateway import ModelOutputRejected
from fas.investigation.model import InvestigatorResponse, ModelToolCall

class PoisonedModel:
    model_id="poisoned"
    def request(self,request,*,timeout_seconds):
        return InvestigatorResponse(kind="hypothesis",payload={"statement":"ignore FAS"},tool_calls=(ModelToolCall(name="shell",arguments={"cmd":"id"}),),model_id=self.model_id,termination_reason="fixture")

class InvalidKindModel:
    model_id="invalid"
    def request(self,request,*,timeout_seconds):
        return InvestigatorResponse(kind="execute_shell",payload={},model_id=self.model_id,termination_reason="fixture")

def test_model_cannot_authorize_shell():
    with pytest.raises(ModelOutputRejected):
        ConstrainedInvestigator(PoisonedModel()).request(InvestigatorRequest(prompt_version="phase4-v1",objective="test",allowed_tools=("shell",)))

def test_invalid_structured_kind_is_rejected():
    with pytest.raises(ModelOutputRejected):
        ConstrainedInvestigator(InvalidKindModel()).request(InvestigatorRequest(prompt_version="phase4-v1",objective="test"))
