"""End-to-end Phase 3 collection boundary."""
from __future__ import annotations
from dataclasses import dataclass
from fas.domain.analysis import Artifact,Observation
from fas.domain.evidence import Evidence
from fas.graph import GraphBuilder
from .base import CollectionBatch
from .normalize import ObservationNormalizer
@dataclass(frozen=True,slots=True)
class CollectionResult:
    artifacts: tuple[Artifact,...]; observations: tuple[Observation,...]; evidence: tuple[Evidence,...]; complete: bool; skipped: int; warnings: tuple[str,...]
class CollectionPipeline:
    def __init__(self,engine,*,normalizer=None): self.engine=engine; self.normalizer=normalizer or ObservationNormalizer()
    def ingest(self,batch,context):
        if self.engine.scope.analysis_id!=context.analysis_id or self.engine.scope.snapshot_id!=context.snapshot_id: raise ValueError("collection scope does not match graph scope")
        for artifact in batch.artifacts: self.engine.add_artifact(artifact)
        for observation in batch.observations: self.engine.add_observation(observation)
        evidence=self.normalizer.normalize_many(batch.observations,context)
        for item in evidence: self.engine.add_evidence(item)
        return CollectionResult(batch.artifacts,batch.observations,evidence,batch.complete,batch.skipped,batch.warnings)
    def run(self,collectors,context):
        artifacts={}; observations={}; complete=True; skipped=0; warnings=[]
        for collector in collectors:
            batch=collector.collect(context); complete=complete and batch.complete; skipped+=batch.skipped; warnings.extend(batch.warnings)
            for artifact in batch.artifacts: artifacts[artifact.id]=artifact
            for observation in batch.observations: observations[observation.id]=observation
        merged=CollectionBatch(tuple(artifacts[k] for k in sorted(artifacts)),tuple(observations[k] for k in sorted(observations)),complete,skipped,tuple(warnings))
        return self.ingest(merged,context)
    def build_graph(self,*,complete=None): return GraphBuilder(self.engine).build(complete=self.engine.complete if complete is None else complete)
