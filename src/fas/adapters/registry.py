"""Adapter registry for deterministic tool-output ingestion."""
from __future__ import annotations
from typing import Any
from .base import ToolAdapter
from .gitleaks import GitleaksAdapter
from .sarif import SarifAdapter
from .semgrep import SemgrepAdapter
from .trivy import TrivyAdapter

class AdapterRegistry:
    def __init__(self, adapters: tuple[ToolAdapter,...] = (SarifAdapter(),SemgrepAdapter(),TrivyAdapter(),GitleaksAdapter())):
        self._adapters={adapter.name:adapter for adapter in adapters}
    def register(self,adapter:ToolAdapter)->None:
        if adapter.name in self._adapters: raise ValueError(f"adapter already registered:
            {adapter.name}")
        self._adapters[adapter.name]=adapter
    def get(self,name:str)->ToolAdapter:
        try: return self._adapters[name]
        except KeyError as exc: raise KeyError(f"unknown tool adapter:
            {name}") from exc
    def names(self)->tuple[str,...]:
        return tuple(sorted(self._adapters))
    def parse(self,name:str,payload:Any,context,*,raw_artifact_id=None,source_artifact_id=None):
        return self.get(name).parse(payload,context,raw_artifact_id=raw_artifact_id,source_artifact_id=source_artifact_id)
