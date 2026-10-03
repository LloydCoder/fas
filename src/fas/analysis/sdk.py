"""Extension contracts for deterministic security analyzers."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol
from fas.domain.analysis import Observation
from fas.collectors.base import CollectionContext

@dataclass(frozen=True, slots=True)
class AnalyzerResult:
    analyzer: str
    observations: tuple[Observation, ...]
    complete: bool
    reason: str | None = None

class SecurityAnalyzer(Protocol):
    name: str
    version: str
    def analyze(self, context: CollectionContext) -> AnalyzerResult: ...

class AnalyzerRegistry:
    def __init__(self) -> None:
        self._items: dict[str, SecurityAnalyzer] = {}
    def register(self, analyzer: SecurityAnalyzer) -> None:
        if not analyzer.name or not analyzer.version:
            raise ValueError("analyzer name and version are required")
        if analyzer.name in self._items:
            raise ValueError(f"analyzer already registered: {analyzer.name}")
        self._items[analyzer.name] = analyzer
    def get(self, name: str) -> SecurityAnalyzer:
        return self._items[name]
    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._items))
