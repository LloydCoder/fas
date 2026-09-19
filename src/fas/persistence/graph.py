"""Persistence-facing graph store contract."""

from fas.graph.store import GraphStore, InMemoryGraphStore, MutationEvent

__all__ = ["GraphStore", "InMemoryGraphStore", "MutationEvent"]
