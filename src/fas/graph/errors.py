"""Explicit Phase 2 graph errors."""

class GraphError(Exception):
    """Base class for graph application errors."""


class NodeNotFound(GraphError):
    pass


class EdgeNotFound(GraphError):
    pass


class DuplicateNode(GraphError):
    pass


class DuplicateEdge(GraphError):
    pass


class InvalidEdge(GraphError):
    pass


class SnapshotMismatch(GraphError):
    pass


class InvalidRelationship(GraphError):
    pass


class GraphInvariantViolation(GraphError):
    pass


class TraversalLimitExceeded(GraphError):
    pass


class PathEnumerationLimitExceeded(GraphError):
    pass


class GraphDeserializationError(GraphError):
    pass


class GraphSealedError(GraphError):
    pass
