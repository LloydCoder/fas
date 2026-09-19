from fas.adapters import GitleaksAdapter
from fas.collectors import CollectionContext
from fas.collectors import ObservationNormalizer
import json

def test_gitleaks_secret_is_not_promoted_to_evidence(tmp_path):
    context=CollectionContext(analysis_id="analysis_01J00000000000000000000000",snapshot_id="snapshot_01J00000000000000000000000",root=tmp_path,repository="fixture")
    obs=GitleaksAdapter().parse([{"RuleID":"token","Description":"token","File":"x.py","Secret":"TOP-SECRET","Match":"TOP-SECRET","Fingerprint":"fp"}],context)[0]
    evidence=ObservationNormalizer().normalize(obs,context)
    assert "TOP-SECRET" not in json.dumps(evidence.model_dump())
