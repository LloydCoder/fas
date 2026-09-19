"""Bounded investigation lifecycle orchestration."""
from __future__ import annotations
from dataclasses import dataclass
from collections.abc import Callable
from fas.domain import Finding, InvestigationCase, InvestigationStatus, InvestigationResult
from .engine import InvestigationEngine, InvestigationContext, InvestigationCancelled, InvestigationBudgetExceeded

_ALLOWED={
    InvestigationStatus.CREATED:{InvestigationStatus.PLANNING,InvestigationStatus.CANCELLED},
    InvestigationStatus.PLANNING:{InvestigationStatus.COLLECTING,InvestigationStatus.FAILED,InvestigationStatus.CANCELLED},
    InvestigationStatus.COLLECTING:{InvestigationStatus.ANALYZING,InvestigationStatus.AWAITING_EVIDENCE,InvestigationStatus.PARTIAL,InvestigationStatus.FAILED,InvestigationStatus.CANCELLED},
    InvestigationStatus.AWAITING_EVIDENCE:{InvestigationStatus.COLLECTING,InvestigationStatus.ANALYZING,InvestigationStatus.CANCELLED},
    InvestigationStatus.ANALYZING:{InvestigationStatus.READY_FOR_VERDICT,InvestigationStatus.AWAITING_EVIDENCE,InvestigationStatus.PARTIAL,InvestigationStatus.FAILED,InvestigationStatus.CANCELLED},
    InvestigationStatus.READY_FOR_VERDICT:{InvestigationStatus.COMPLETED,InvestigationStatus.PARTIAL},
    InvestigationStatus.PARTIAL:{InvestigationStatus.ANALYZING,InvestigationStatus.COMPLETED,InvestigationStatus.CANCELLED},
    InvestigationStatus.COMPLETED:set(), InvestigationStatus.FAILED:set(), InvestigationStatus.CANCELLED:set(),
}

@dataclass
class InvestigationRunner:
    engine: InvestigationEngine

    def transition(self, case:InvestigationCase, target:InvestigationStatus)->InvestigationCase:
        if target not in _ALLOWED.get(case.status,set()):
            raise ValueError(f"invalid investigation transition: {case.status}->{target}")
        updated=case.model_copy(update={"status":target,"updated_at":__import__("fas.domain",fromlist=["utc_now"]).utc_now()})
        self.engine.store.save_case(updated)
        self.engine.store.event(updated,"STATE_CHANGED",{"from":case.status.value,"to":target.value})
        return updated

    def run(self, *, case:InvestigationCase, finding:Finding, analyze:Callable[[InvestigationContext],InvestigationResult], cancelled:Callable[[],bool]=lambda:False)->InvestigationResult:
        case=self.transition(case,InvestigationStatus.PLANNING)
        case=self.transition(case,InvestigationStatus.COLLECTING)
        context=self.engine.context(case,finding,cancelled=cancelled)
        try:
            case=self.transition(case,InvestigationStatus.ANALYZING)
            result=analyze(context)
            if result.status==InvestigationStatus.READY_FOR_VERDICT:
                case=self.transition(case,InvestigationStatus.READY_FOR_VERDICT)
            else:
                case=self.transition(case,InvestigationStatus.PARTIAL)
            return result
        except InvestigationCancelled:
            self.transition(case,InvestigationStatus.CANCELLED)
            raise
        except InvestigationBudgetExceeded:
            self.transition(case,InvestigationStatus.PARTIAL)
            raise
        except Exception:
            self.transition(case,InvestigationStatus.FAILED)
            raise
