"""CI/CD and container metadata discovery without executing workflows."""
from __future__ import annotations
from .base import _BatchBuilder
from .discovery import _stable_id,_provenance
from fas.domain.analysis import Artifact,Observation
from fas.domain.common import ArtifactType,ContentHash,SourceLocation
_TARGETS={".github/workflows","Dockerfile","docker-compose.yml","docker-compose.yaml",".gitlab-ci.yml","Jenkinsfile","bitbucket-pipelines.yml","azure-pipelines.yml","k8s","kubernetes","helm"}
class CICDCollector:
    name="ci-cd"
    def collect(self,context):
        b=_BatchBuilder()
        for path in sorted(context.root.rglob("*")):
            try:
                rel=path.relative_to(context.root).as_posix()
                match=path.is_file() and (rel.startswith(".github/workflows/") or path.name in _TARGETS or any(rel.startswith(x+"/") for x in ("k8s","kubernetes","helm")))
                if not match or path.is_symlink(): continue
                size=path.stat().st_size
                if size>context.max_file_bytes: b.complete=False;b.skipped+=1;b.warnings.append(f"CI/CD file too large: {rel}");continue
                data=path.read_bytes(); digest=__import__("hashlib").sha256(data).hexdigest(); aid=_stable_id("artifact",f"{context.snapshot_id}|ci-cd|{rel}|{digest}"); prov=_provenance("ci_cd_hash",rel)
                artifact=Artifact(id=aid,analysis_id=context.analysis_id,type=ArtifactType.CONFIGURATION,name=rel,size_bytes=size,content_hash=ContentHash(digest=digest),snapshot_id=context.snapshot_id,provenance=(prov,),external_reference=str(path),metadata={"executed":"false","domain":"ci-cd"})
                b.artifacts.append(artifact)
                b.observations.append(Observation(id=_stable_id("observation",f"ci-cd|{aid}"),analysis_id=context.analysis_id,snapshot_id=context.snapshot_id,source=self.name,category="ci_cd_configuration",location=SourceLocation(artifact_id=aid,path=rel),message=f"CI/CD or deployment configuration discovered: {rel}",observed_value={"path":rel,"size_bytes":size,"content_hash":artifact.content_hash.value},provenance=(prov,),observed_at=prov.observed_at,metadata={"executed":"false"}))
            except OSError as exc: b.complete=False;b.skipped+=1;b.warnings.append(f"CI/CD unreadable: {exc}")
        return b.build()
