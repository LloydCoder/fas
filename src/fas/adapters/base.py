"""Tool adapter contract."""
from __future__ import annotations
from typing import Any,Protocol
from fas.domain.analysis import Observation
from fas.collectors.base import CollectionContext
class ToolAdapter(Protocol):
    name:str
    def parse(self,payload:str|bytes|dict[str,Any]|list[Any],context:CollectionContext,*,raw_artifact_id:str|None=None)->tuple[Observation,...]: ...
