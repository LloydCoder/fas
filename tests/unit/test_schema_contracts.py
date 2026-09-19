import json
from pathlib import Path

import pytest

from fas.domain.analysis import Analysis
from fas.domain.attack_paths import AttackPath
from fas.domain.evidence import Evidence
from fas.domain.findings import Finding
from fas.domain.graph import GraphEdge, GraphNode
from fas.domain.remediation import Remediation, Verification
from fas.domain.verdicts import Verdict

ROOT = Path(__file__).parents[2]
SCHEMAS = ROOT / "schemas"

MODELS = {
    "analysis.schema.json": Analysis,
    "evidence.schema.json": Evidence,
    "finding.schema.json": Finding,
    "attack-path.schema.json": AttackPath,
    "verdict.schema.json": Verdict,
    "remediation.schema.json": Remediation,
    "verification.schema.json": Verification,
}


@pytest.mark.parametrize(("filename", "model"), MODELS.items())
def test_schema_has_canonical_metadata_and_required_fields(filename, model):
    schema = json.loads((SCHEMAS / filename).read_text())
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["x-fas-canonical-model"] == model.__name__
    assert schema["x-fas-schema-version"] == "1.0"
    for field in model.model_fields:
        if model.model_fields[field].is_required():
            assert field in schema["required"]


def test_verdict_schema_cannot_silently_drop_verdicts():
    schema = json.loads((SCHEMAS / "verdict.schema.json").read_text())
    assert set(schema["properties"]["verdict"]["enum"]) == {
        "EXPLOITABLE", "NOT_EXPLOITABLE", "CONDITIONALLY_EXPLOITABLE",
        "REMEDIATED", "REMEDIATION_FAILED", "REGRESSED", "UNKNOWN",
    }


def test_graph_domain_contracts_have_scope_and_identity():
    assert {"analysis_id", "snapshot_id", "canonical_identity"}.issubset(GraphNode.model_fields)
    assert {"analysis_id", "snapshot_id", "source_node_id", "target_node_id"}.issubset(GraphEdge.model_fields)
