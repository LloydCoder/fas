"""Phase 4 investigation engine public API."""
from .engine import (
    DeterministicInvestigator, InvestigationBudgetExceeded, InvestigationCancelled,
    InvestigationEngine, InvestigationError, InvestigationStore, SnapshotScopeError,
    UnauthorizedInvestigatorTool,
)
from .runner import InvestigationRunner
from .model import DeterministicFakeModel, InvestigatorModel, InvestigatorRequest, InvestigatorResponse, ModelToolCall
from .prompt import INVESTIGATOR_PROMPT_VERSION, INVESTIGATOR_SYSTEM_PROMPT

__all__=[
    "InvestigationEngine","InvestigationStore","InvestigationRunner","DeterministicInvestigator","InvestigationError",
    "InvestigationBudgetExceeded","InvestigationCancelled","SnapshotScopeError",
    "UnauthorizedInvestigatorTool","InvestigatorModel","InvestigatorRequest","InvestigatorResponse",
    "ModelToolCall","DeterministicFakeModel","INVESTIGATOR_PROMPT_VERSION","INVESTIGATOR_SYSTEM_PROMPT",
]
