"""Persistence seams exposed by FAS Phase 2.

The graph store protocol is intentionally implemented in the graph package so
algorithms and persistence semantics can evolve independently. This module
provides the persistence-facing import surface.
"""

from fas.graph.store import GraphStore, InMemoryGraphStore, MutationEvent

__all__ = ["GraphStore", "InMemoryGraphStore", "MutationEvent"]

from .investigation import InvestigationRepository, JsonlInvestigationRepository
