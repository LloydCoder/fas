from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from fas.domain.analysis import Analysis, Artifact, Observation, Snapshot
from fas.domain.attack_paths import AttackPath, AttackPathStep
from fas.domain.common import (
    AnalysisStatus, ArtifactType, ContentHash, EvidenceType, GraphNodeType, Provenance,
    ProvenanceCategory, ProvenanceLevel, RelationshipType, VerdictType, new_id,
)
from fas.domain.evidence import Evidence
from fas.domain.findings import Finding
from fas.domain.graph import GraphEdge, GraphNode
from fas.domain.remediation import Remediation, Verification
from fas.domain.verdicts import Verdict


NOW = datetime(2026, 9, 19, 12, tzinfo=timezone.utc)
HASH = "a" * 64


def ids():
    return {k: new_id(k) for k in (
        "analysis", "snapshot", "artifact", "observation", "evidence", "node", "edge",
        "finding", "attack_path", "verdict", "remediation", "verification"
    )}


@pytest.fixture
def context():
    i = ids()
    p = Provenance(
        category=ProvenanceCategory.TOOL_OBSERVATION,
        level=ProvenanceLevel.T2,
        collector="test-collector",
        collector_version="1.0",
        method="unit_test",
        source="fixture",
        observed_at=NOW,
    )
    return i, p


def test_identifier_validation_and_generation():
    value = new_id("evidence")
    assert value.startswith("evidence_")
    assert len(value.split("_", 1)[1]) == 26
    with pytest.raises(ValidationError):
        Evidence(id="bad", analysis_id=i["analysis"], snapshot_id=i["snapshot"], type=EvidenceType.CODE, claim="x", provenance=(), observed_at=NOW)


def test_hash_and_source_location_invariants(context):
    i, p = context
    assert ContentHash.parse(f"sha256:{HASH}").value == f"sha256:{HASH}"
    with pytest.raises(ValueError):
        ContentHash.parse("sha1:" + HASH)

    from fas.domain.common import SourceLocation
    loc = SourceLocation(artifact_id=i["artifact"], path="src/app.py", line_start=4, line_end=8)
    assert loc.line_end == 8
    with pytest.raises(ValidationError):
        SourceLocation(artifact_id=i["artifact"], path="x.py", line_start=8, line_end=7)


def test_provenance_is_typed_and_timezone_normalized(context):
    _, p = context
    assert p.level == ProvenanceLevel.T2
    with pytest.raises(ValidationError):
        Provenance(
            category=ProvenanceCategory.LLM_INFERENCE,
            level="T9",
            collector="x",
            method="x",
            source="x",
            observed_at=NOW,
        )
    with pytest.raises(ValidationError):
        Provenance(
            category=ProvenanceCategory.TOOL_OBSERVATION,
            level=ProvenanceLevel.T2,
            collector="x",
            method="x",
            source="x",
            observed_at=datetime(2026, 1, 1),
        )


def test_analysis_snapshot_artifact_observation(context):
    i, p = context
    snapshot = Snapshot(
        id=i["snapshot"],
        repository={"repository": "https://github.com/example/project", "revision": "abc123"},
        captured_at=NOW,
        source_reference="git://example/project@abc123",
    )
    artifact = Artifact(
        id=i["artifact"],
        type=ArtifactType.SOURCE_FILE,
        name="src/app.py",
        snapshot_id=snapshot.id,
        provenance=(p,),
    )
    observation = Observation(
        id=i["observation"],
        source="semgrep",
        category="command-injection",
        message="possible sink",
        raw_artifact_id=artifact.id,
        provenance=(p,),
        observed_at=NOW,
    )
    analysis = Analysis(
        id=i["analysis"],
        project="example/project",
        status=AnalysisStatus.COLLECTING,
        snapshot_ids=(snapshot.id,),
        started_at=NOW,
    )
    assert analysis.snapshot_ids == (snapshot.id,)
    assert artifact.snapshot_id == snapshot.id
    assert observation.raw_artifact_id == artifact.id


def test_analysis_timestamp_and_failure_invariants(context):
    i, _ = context
    with pytest.raises(ValidationError):
        Analysis(
            id=i["analysis"],
            project="x",
            created_at=NOW,
            started_at=NOW - timedelta(seconds=1),
        )
    with pytest.raises(ValidationError):
        Analysis(id=i["analysis"], project="x", status=AnalysisStatus.FAILED)


def test_evidence_distinguishes_from_observation(context):
    i, p = context
    e = Evidence(
        id=i["evidence"],
        analysis_id=i["analysis"],
        snapshot_id=i["snapshot"],
        type=EvidenceType.CODE,
        claim="function invokes shell",
        observed_value={"symbol": "run"},
        provenance=(p,),
        observed_at=NOW,
    )
    assert e.id != i["observation"]
    assert e.provenance[0].category == ProvenanceCategory.TOOL_OBSERVATION
    with pytest.raises(ValidationError):
        Evidence(id=i["evidence"], analysis_id=i["analysis"], snapshot_id=i["snapshot"], type=EvidenceType.CODE, claim="x", provenance=(), observed_at=NOW)


def test_graph_requires_provenance_and_security_evidence(context):
    i, p = context
    with pytest.raises(ValidationError):
        GraphNode(id=i["node"], type=GraphNodeType.FILE, label="x", analysis_id=i["analysis"], snapshot_id=i["snapshot"], canonical_identity="file:fixture", provenance=())
    with pytest.raises(ValidationError):
        GraphNode(
            id=i["node"], type=GraphNodeType.SECRET, label="x", analysis_id=i["analysis"], snapshot_id=i["snapshot"], canonical_identity="secret:fixture", provenance=(p,), security_relevant=True
        )
    node = GraphNode(
        id=i["node"], type=GraphNodeType.FILE, label="x", analysis_id=i["analysis"], snapshot_id=i["snapshot"], canonical_identity="file:fixture", provenance=(p,), evidence_ids=(i["evidence"],)
    )
    edge = GraphEdge(
        id=i["edge"], source_node_id=node.id, target_node_id=new_id("node"),
        relationship_type=RelationshipType.CALLS, analysis_id=i["analysis"], snapshot_id=i["snapshot"], provenance=(p,), observed_at=NOW,
        security_relevant=True, evidence_ids=(i["evidence"],),
    )
    assert edge.relationship_type == RelationshipType.CALLS


def test_finding_and_attack_path(context):
    i, p = context
    finding = Finding(
        id=i["finding"],
        title="Command injection",
        category="injection",
        snapshot_id=i["snapshot"],
        created_at=NOW,
        updated_at=NOW,
        supporting_evidence_ids=(i["evidence"],),
        related_observation_ids=(i["observation"],),
        involved_node_ids=(i["node"],),
    )
    step = AttackPathStep(
        node_id=i["node"], edge_id=i["edge"], next_node_id=new_id("node"),
        evidence_ids=(i["evidence"],)
    )
    path = AttackPath(
        id=i["attack_path"],
        entry=i["node"],
        steps=(step,),
        snapshot_id=i["snapshot"],
        observed_at=NOW,
        supporting_evidence_ids=(i["evidence"],),
    )
    assert finding.id == i["finding"]
    assert path.steps[0].evidence_ids == (i["evidence"],)


def test_attack_path_without_evidence_is_rejected(context):
    i, _ = context
    with pytest.raises(ValidationError):
        AttackPathStep(node_id=i["node"], edge_id=i["edge"], next_node_id=new_id("node"))


@pytest.mark.parametrize("kind", list(VerdictType))
def test_every_verdict_type_is_representable(kind, context):
    i, _ = context
    kwargs = {
        "id": i["verdict"], "verdict": kind, "finding_id": i["finding"],
        "confidence": {"value": 0.8}, "rationale": "documented rationale", "created_at": NOW,
    }
    if kind == VerdictType.UNKNOWN:
        kwargs["missing_evidence"] = ({"description": "runtime authorization state"},)
    elif kind == VerdictType.EXPLOITABLE:
        kwargs["supporting_evidence_ids"] = (i["evidence"],)
        kwargs["attack_path_id"] = i["attack_path"]
    elif kind == VerdictType.NOT_EXPLOITABLE:
        kwargs["supporting_evidence_ids"] = (i["evidence"],)
    elif kind == VerdictType.CONDITIONALLY_EXPLOITABLE:
        kwargs["supporting_evidence_ids"] = (i["evidence"],)
        kwargs["conditions"] = ("principal has permission X",)
    elif kind == VerdictType.REMEDIATED:
        kwargs["supporting_evidence_ids"] = (i["evidence"],)
    elif kind == VerdictType.REMEDIATION_FAILED:
        kwargs["supporting_evidence_ids"] = (i["evidence"],)
    elif kind == VerdictType.REGRESSED:
        kwargs["supporting_evidence_ids"] = (i["evidence"],)
        kwargs["prior_verdict_id"] = new_id("verdict")
    verdict = Verdict(**kwargs)
    assert verdict.verdict == kind


def test_verdict_invariants(context):
    i, _ = context
    base = dict(
        id=i["verdict"], finding_id=i["finding"], confidence={"value": 1.0},
        rationale="x", created_at=NOW,
    )
    with pytest.raises(ValidationError):
        Verdict(verdict=VerdictType.EXPLOITABLE, **base)
    with pytest.raises(ValidationError):
        Verdict(verdict=VerdictType.UNKNOWN, **base)
    with pytest.raises(ValidationError):
        Verdict(verdict=VerdictType.CONDITIONALLY_EXPLOITABLE, **base)
    with pytest.raises(ValidationError):
        Verdict(verdict=VerdictType.REGRESSED, **base)


def test_remediation_and_verification(context):
    i, _ = context
    remediation = Remediation(
        id=i["remediation"], target_finding_id=i["finding"],
        original_snapshot_id=i["snapshot"], patched_snapshot_id=new_id("snapshot"),
        expected_broken_path_ids=(i["attack_path"],), created_at=NOW,
    )
    verification = Verification(
        id=i["verification"], target_id=remediation.id, target_type="REMEDIATION",
        verification_type="REMEDIATION", status="PASSED", evidence_ids=(i["evidence"],),
        before_snapshot_id=remediation.original_snapshot_id,
        after_snapshot_id=remediation.patched_snapshot_id, verified_at=NOW,
    )
    assert verification.status.value == "PASSED"


def test_frozen_models_reject_mutation(context):
    i, p = context
    e = Evidence(id=i["evidence"], analysis_id=i["analysis"], snapshot_id=i["snapshot"], type=EvidenceType.CODE, claim="x", provenance=(p,), observed_at=NOW)
    with pytest.raises(ValidationError):
        e.claim = "changed"


def test_unknown_fields_are_rejected(context):
    i, p = context
    with pytest.raises(ValidationError):
        Evidence(id=i["evidence"], type=EvidenceType.CODE, claim="x", provenance=(p,), observed_at=NOW, extra="bad")


def test_round_trip_is_semantically_stable(context):
    i, p = context
    e = Evidence(
        id=i["evidence"], type=EvidenceType.CODE, claim="x", observed_value={"a": [1, True]},
        provenance=(p,), observed_at=NOW,
    )
    restored = Evidence.model_validate_json(e.model_dump_json())
    assert restored == e
    assert restored.canonical_json() == e.canonical_json()


def test_hostile_oversized_and_invalid_values_are_rejected(context):
    i, p = context
    with pytest.raises(ValidationError):
        Evidence(id=i["evidence"], type=EvidenceType.CODE, claim="", provenance=(p,), observed_at=NOW)
    with pytest.raises(ValidationError):
        Evidence(id=i["evidence"], type="UNTRUSTED", claim="x", provenance=(p,), observed_at=NOW)
