from datetime import datetime, timedelta, timezone
from fas.analysis import EvidenceCorrelationEngine
from fas.domain.common import EvidenceType, Provenance, ProvenanceCategory, ProvenanceLevel, new_id
from fas.domain.evidence import Evidence

def _e(ts):
    return Evidence(id=new_id("evidence"), analysis_id=new_id("analysis"), snapshot_id=new_id("snapshot"),
        type=EvidenceType.CODE, claim="  same   claim ", provenance=(Provenance(
        category=ProvenanceCategory.VERIFIED_ARTIFACT, level=ProvenanceLevel.T3,
        collector="test", method="fixture", source="test", observed_at=ts),),
        observed_at=ts)

def test_equivalent_evidence_correlates_deterministically():
    ts=datetime(2026,1,1,tzinfo=timezone.utc)
    a,b=_e(ts),_e(ts)
    groups=EvidenceCorrelationEngine().groups((b,a))
    assert len(groups)==1
    assert groups[0].evidence_ids==tuple(sorted((a.id,b.id)))

def test_temporal_window_is_explicit_and_ordered():
    start=datetime(2026,1,1,tzinfo=timezone.utc)
    a,b=_e(start),_e(start+timedelta(hours=1))
    result=EvidenceCorrelationEngine().within((b,a),start=start,window=timedelta(hours=1))
    assert result.complete
    assert result.evidence_ids==(a.id,b.id)
