"""Append-only investigation persistence seam.

The repository is deliberately backend-neutral. The JSONL implementation is suitable for
local/reproducible operation and tests; a PostgreSQL adapter can implement the same protocol
without changing Phase 4 domain contracts.
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Protocol
from fas.domain.investigation import InvestigationCase, InvestigationEvent, InvestigationResult

class InvestigationRepository(Protocol):
    def save_case(self, case:InvestigationCase)->None: ...
    def append_event(self,event:InvestigationEvent)->None: ...
    def save_result(self,result:InvestigationResult)->None: ...
    def load_case(self,investigation_id:str)->InvestigationCase: ...
    def load_result(self,investigation_id:str)->InvestigationResult: ...

class JsonlInvestigationRepository:
    def __init__(self,path:Path):
        self.path=path
        self.path.parent.mkdir(parents=True,exist_ok=True)
    def _append(self,kind:str,payload:dict)->None:
        with self.path.open("a",encoding="utf-8") as handle:
            handle.write(json.dumps({"kind":kind,"payload":payload},sort_keys=True,separators=(",",":"))+"\n")
    def save_case(self,case): self._append("case",case.model_dump(mode="json"))
    def append_event(self,event): self._append("event",event.model_dump(mode="json"))
    def save_result(self,result): self._append("result",result.model_dump(mode="json"))
    def _latest(self,kind:str,ident:str):
        if not self.path.exists(): raise KeyError(ident)
        latest=None
        for line in self.path.read_text(encoding="utf-8").splitlines():
            item=json.loads(line)
            payload=item["payload"]
            if item["kind"]==kind and payload.get("id",payload.get("investigation_id"))==ident:
                latest=payload
        if latest is None: raise KeyError(ident)
        return latest
    def load_case(self,investigation_id): return InvestigationCase.model_validate(self._latest("case",investigation_id))
    def load_result(self,investigation_id): return InvestigationResult.model_validate(self._latest("result",investigation_id))
