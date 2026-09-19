"""Reusable Phase 2 graph fixtures."""

from datetime import datetime, timezone

import pytest

from fas.domain.common import (
    EvidenceType,
    Provenance,
    ProvenanceCategory,
    ProvenanceLevel,
    new_id,
)
from fas.domain.evidence import Evidence
from fas.graph import GraphBuilder, GraphEngine, GraphLimits


NOW = datetime(2026, 9, 19, 12, tzinfo=timezone.utc)


@pytest.fixture
def context():
    return {
        "analysis": new_id("analysis"),
        "snapshot": new_id("snapshot"),
        "other_snapshot": new_id("snapshot"),
    }


@pytest.fixture
def provenance():
    return Provenance(
        category=ProvenanceCategory.TOOL_OBSERVATION,
        level=ProvenanceLevel.T2,
        collector="fixture",
        collector_version="1",
        method="fixture",
        source="tests/fixtures/graph",
        observed_at=NOW,
    )


@pytest.fixture
def engine(context):
    return GraphEngine(
        analysis_id=context["analysis"],
        snapshot_id=context["snapshot"],
        limits=GraphLimits(
            max_traversal_depth=8,
            max_nodes_visited=100,
            max_edges_visited=200,
            max_paths=5,
            max_path_depth=8,
        ),
    )


def add_evidence(engine, context, provenance, *, claim="fixture evidence"):
    evidence = Evidence(
        id=new_id("evidence"),
        analysis_id=context["analysis"],
        snapshot_id=context["snapshot"],
        type=EvidenceType.CODE,
        claim=claim,
        provenance=(provenance,),
        observed_at=NOW,
    )
    engine.add_evidence(evidence)
    return evidence


def add_node(engine, context, provenance, *, node_type, identity, evidence):
    return GraphBuilder.make_node(
        analysis_id=context["analysis"],
        snapshot_id=context["snapshot"],
        node_type=node_type,
        canonical_identity=identity,
        label=identity,
        provenance=(provenance,),
        evidence_ids=(evidence.id,),
        security_relevant=True,
    )
