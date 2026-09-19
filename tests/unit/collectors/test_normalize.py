from datetime import datetime, timezone
from fas.collectors import CollectionContext, ObservationNormalizer
from fas.domain.analysis import Observation
from fas.domain.common import Provenance, ProvenanceCategory, ProvenanceLevel, new_id

def test_observation_normalization_preserves_provenance(context,tmp_path):
    now=datetime(2026,9,19,tzinfo=timezone.utc)
    provenance=Provenance(category=ProvenanceCategory.LLM_INFERENCE,level=ProvenanceLevel.T1,collector="test",method="hypothesis",source="unit",observed_at=now)
    observation=Observation(id=new_id("observation"),analysis_id=context["analysis"],snapshot_id=context["snapshot"],source="test",category="tool_result",message="candidate condition",observed_value={"x":1},provenance=(provenance,),observed_at=now)
    ctx=CollectionContext(analysis_id=context["analysis"],snapshot_id=context["snapshot"],root=tmp_path,repository="fixture")
    evidence=ObservationNormalizer().normalize(observation,ctx)
    assert evidence.related_observation_ids==(observation.id,)
    assert evidence.provenance==observation.provenance
    assert evidence.observed_value==observation.observed_value
    assert evidence.type.value=="TOOL_OUTPUT"

def test_normalization_rejects_cross_scope(context,tmp_path):
    now=datetime(2026,9,19,tzinfo=timezone.utc)
    provenance=Provenance(category=ProvenanceCategory.TOOL_OBSERVATION,level=ProvenanceLevel.T2,collector="test",method="fixture",source="unit",observed_at=now)
    observation=Observation(id=new_id("observation"),analysis_id=context["analysis"],snapshot_id=context["other_snapshot"],source="test",category="tool_result",message="outside",provenance=(provenance,),observed_at=now)
    ctx=CollectionContext(analysis_id=context["analysis"],snapshot_id=context["snapshot"],root=tmp_path,repository="fixture")
    import pytest
    from fas.collectors import NormalizationError
    with pytest.raises(NormalizationError):
        ObservationNormalizer().normalize(observation,ctx)
