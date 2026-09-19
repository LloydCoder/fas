"""External security-tool collector with raw-artifact and adapter boundaries."""
from __future__ import annotations
import hashlib
from datetime import datetime,timezone
from pathlib import Path
from .base import CollectionBatch,_BatchBuilder,CollectionContext
from .executor import SecureExecutor,CancellationToken
from .raw import RawArtifact,ToolRun,environment_fingerprint,stable_run_id,raw_artifact_from_bytes
from fas.domain.analysis import Artifact
from fas.domain.common import ArtifactType,ContentHash,Provenance,ProvenanceCategory,ProvenanceLevel
class ToolCollector:
    """Execute one allowlisted tool, persist bounded raw output, then parse observations."""
    def __init__(self,tool_name:str,argv:tuple[str,...],adapter,executor:SecureExecutor,raw_dir:Path):
        if not argv: raise ValueError("argv is required")
        self.name=f"tool:{tool_name}"; self.tool_name=tool_name; self.argv=argv; self.adapter=adapter; self.executor=executor; self.raw_dir=raw_dir
    def collect(self,context:CollectionContext):
        started=datetime.now(timezone.utc); result=self.executor.run(self.argv,cwd=context.root)
        run_id=stable_run_id(context)
        self.raw_dir.mkdir(parents=True,exist_ok=True)
        raw_name=f"{run_id}-{self.tool_name}.stdout"; raw_path=self.raw_dir/raw_name
        raw_path.write_bytes(result.stdout)
        digest=hashlib.sha256(result.stdout).hexdigest()
        artifact_id="artifact_"+hashlib.sha256(f"{context.snapshot_id}|{self.tool_name}|{digest}".encode()).hexdigest()[:26]
        prov=Provenance(category=ProvenanceCategory.TOOL_OBSERVATION,level=ProvenanceLevel.T2,collector=self.tool_name,method="secure_subprocess",source="stdout",observed_at=started,tool_execution_ref=run_id)
        artifact=Artifact(id=artifact_id,analysis_id=context.analysis_id,type=ArtifactType.TOOL_OUTPUT,name=raw_name,media_type="application/json",size_bytes=len(result.stdout),content_hash=ContentHash(digest=digest),snapshot_id=context.snapshot_id,provenance=(prov,),external_reference=str(raw_path),metadata={"tool":self.tool_name,"exit_code":str(result.returncode)})
        status="CANCELLED" if result.cancelled else "TIMEOUT" if result.timed_out else "TOOL_ERROR" if result.returncode not in (0,None) else "SUCCESS"
        if status!="SUCCESS": return CollectionBatch(artifacts=(artifact,),complete=False,skipped=0,warnings=(f"{self.name}: {status}",))
        observations=self.adapter.parse(result.stdout,context,raw_artifact_id=artifact_id,source_artifact_id=artifact_id)
        return CollectionBatch(artifacts=(artifact,),observations=observations,complete=not result.output_limited,warnings=("tool output was truncated",) if result.output_limited else ())
