"""Configuration and CI/CD inventory without executing configuration."""
from __future__ import annotations
from .base import _BatchBuilder
from .discovery import RepositoryDiscoveryCollector
from fas.domain.analysis import Observation
from fas.domain.common import ArtifactType,SourceLocation
class ConfigurationCollector:
    name="configuration"
    def collect(self,context):
        base=RepositoryDiscoveryCollector().collect(context)
        b=_BatchBuilder(list(base.artifacts),[],list(base.warnings),base.skipped,base.complete)
        for artifact in base.artifacts:
            if artifact.type not in {ArtifactType.CONFIGURATION,ArtifactType.DEPENDENCY_METADATA}:
                continue
            b.observations.append(Observation(id=__import__("fas.collectors.discovery",fromlist=["_stable_id"])._stable_id("observation",f"config|{artifact.id}"),analysis_id=context.analysis_id,snapshot_id=context.snapshot_id,source=self.name,category="configuration",location=SourceLocation(artifact_id=artifact.id,path=artifact.name),message=f"Configuration artifact discovered: {artifact.name}",observed_value={"path":artifact.name,"media_type":artifact.media_type,"size_bytes":artifact.size_bytes},provenance=artifact.provenance,observed_at=artifact.provenance[0].observed_at,metadata={"executed":"false"}))
        return b.build()
