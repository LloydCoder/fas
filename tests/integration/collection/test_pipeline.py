from fas.adapters import SemgrepAdapter
from fas.collectors import CollectionBatch,CollectionContext,CollectionPipeline
from fas.domain.common import new_id
from fas.graph import GraphEngine

def test_collection_pipeline_ingests_observations_as_evidence(tmp_path):
    analysis_id=new_id("analysis"); snapshot_id=new_id("snapshot")
    context=CollectionContext(analysis_id=analysis_id,snapshot_id=snapshot_id,root=tmp_path,repository="fixture")
    engine=GraphEngine(analysis_id=analysis_id,snapshot_id=snapshot_id)
    observations=SemgrepAdapter().parse({"results":[{"check_id":"R1","path":"app.py","extra":{"message":"candidate"}}]},context)
    result=CollectionPipeline(engine).ingest(CollectionBatch(observations=observations),context)
    assert len(result.evidence)==1
    assert engine.get_evidence_observations(result.evidence[0].id)[0].id==observations[0].id

def test_pipeline_preserves_partial_collection(tmp_path):
    analysis_id=new_id("analysis"); snapshot_id=new_id("snapshot")
    context=CollectionContext(analysis_id=analysis_id,snapshot_id=snapshot_id,root=tmp_path,repository="fixture")
    engine=GraphEngine(analysis_id=analysis_id,snapshot_id=snapshot_id)
    result=CollectionPipeline(engine).ingest(CollectionBatch(complete=False,skipped=2,warnings=("limit",)),context)
    assert result.complete is False
    assert result.skipped==2
    assert result.warnings==("limit",)
