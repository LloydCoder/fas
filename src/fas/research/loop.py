"""Bounded deterministic research scheduler."""
from __future__ import annotations
from dataclasses import dataclass
from collections.abc import Callable, Iterable
from .contracts import ApprovalState, AuthorityBoundary, EvidenceRequest, Hypothesis, ResearchBudget, ResearchRun, RequestKind

@dataclass(frozen=True, slots=True)
class ResearchCandidate:
    hypothesis:Hypothesis
    request:EvidenceRequest

class ResearchLoop:
    def __init__(self,budget:ResearchBudget):
        self.budget=budget
    def propose(self,snapshot_id:str,hypotheses:Iterable[Hypothesis])->tuple[ResearchCandidate,...]:
        candidates=[]
        for index,hypothesis in enumerate(hypotheses):
            if index>=self.budget.max_hypotheses: break
            request=EvidenceRequest(
                request_id=f"{hypothesis.hypothesis_id}:evidence",
                kind=RequestKind.RECHECK,
                target=snapshot_id,
                rationale=hypothesis.statement,
                hypothesis_id=hypothesis.hypothesis_id,
                required_approval=True,
                approval=ApprovalState.PENDING,
            )
            candidates.append(ResearchCandidate(hypothesis,request))
            if len(candidates)>=self.budget.max_requests: break
        return tuple(candidates)
    def run(self,run_id:str,snapshot_id:str,candidates:Iterable[ResearchCandidate],executor:Callable[[EvidenceRequest],bool])->ResearchRun:
        requests=[]; hypotheses=[]; completed=0
        for candidate in candidates:
            if len(requests)>=self.budget.max_requests: break
            request=candidate.request
            if request.required_approval and request.approval is not ApprovalState.APPROVED:
                requests.append(request); hypotheses.append(candidate.hypothesis)
                continue
            try:
                ok=executor(request)
            except Exception:
                ok=False
            completed += int(ok)
            requests.append(request); hypotheses.append(candidate.hypothesis)
        reason=None if len(requests)<self.budget.max_requests else "request budget exhausted"
        return ResearchRun(run_id,snapshot_id,tuple(requests),tuple(hypotheses),completed,reason,False)
    @staticmethod
    def assert_authority_boundary()->None:
        AuthorityBoundary.reject_authoritative_write()
