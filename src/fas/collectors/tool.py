"""External security-tool collector with raw-artifact and adapter boundaries."""
from __future__ import annotations
import hashlib
from datetime import datetime,timezone
from pathlib import Path
from .base import CollectionBatch
from .executor import SecureExecutor
from .raw import ToolRun,environment_fingerprint,stable_run_id,raw_artifact_from_bytes
from fas.domain.analysis import Artifact
from fas.domain.common import ArtifactType,ContentHash,Provenance,ProvenanceCategory,ProvenanceLevel

class ToolCollector:
    def __init__(self,tool_name:str,argv:tuple[str,...],adapter,executor:SecureExecutor,raw_dir:Path):
        if not argv: raise ValueError("argv is required")
        if Path(argv[0]).name != tool_name: raise ValueError("argv executable must match tool_name")
        self.name=f"tool:{tool_name}"
        self.tool_name=tool_name
        self.argv=argv
        self.adapter=adapter
        self.executor=executor
        self.raw_dir=raw_dir

    def collect(self,context):
        started=datetime.now(timezone.utc)
        self.raw_dir.mkdir(parents=True,exist_ok=True)
        argv=tuple(context.root.as_posix() if item=="{target}" else item for item in self.argv)
        result=self.executor.run(argv,cwd=self.raw_dir,cancel=getattr(context,"cancel",None))
        run_id=stable_run_id(context,self.tool_name)
        raw_name=f"{run_id}-{self.tool_name}.stdout"
        raw_path=self.raw_dir/raw_name
        raw_path.write_bytes(result.stdout)
        stdout_hash=hashlib.sha256(result.stdout).hexdigest()
        stderr_hash=hashlib.sha256(result.stderr).hexdigest()
        artifact_id="artifact_"+hashlib.sha256(f"{context.snapshot_id}|{self.tool_name}|{stdout_hash}".encode()).hexdigest()[:26]
        prov=Provenance(category=ProvenanceCategory.TOOL_OBSERVATION,level=ProvenanceLevel.T2,collector=self.tool_name,method="secure_subprocess",source="stdout",observed_at=started,tool_execution_ref=run_id)
        artifact=Artifact(id=artifact_id,analysis_id=context.analysis_id,type=ArtifactType.TOOL_OUTPUT,name=raw_name,media_type="application/json",size_bytes=len(result.stdout),content_hash=ContentHash(digest=stdout_hash),snapshot_id=context.snapshot_id,provenance=(prov,),external_reference=str(raw_path),metadata={"tool":self.tool_name,"exit_code":str(result.returncode),"output_limited":str(result.output_limited).lower()})
        if result.cancelled:
            status="CANCELLED"
        elif result.timed_out:
            status="TIMED_OUT"
        elif result.output_limited:
            status="OUTPUT_LIMITED"
        elif result.returncode is None:
            status="FAILED"
        elif result.returncode not in (0, 1):
            status="FAILED"
        elif not result.stdout and not result.stderr and result.returncode == 0:
            status="NO_FINDINGS"
        else:
            status="SUCCESS"
        run=ToolRun(run_id,context.analysis_id,context.snapshot_id,self.tool_name,None,argv,str(self.raw_dir),environment_fingerprint(),started.isoformat(),datetime.now(timezone.utc).isoformat(),result.returncode,status,"sha256:"+stdout_hash,"sha256:"+stderr_hash,artifact_id,repository_revision=context.revision)
        raw=raw_artifact_from_bytes(artifact_id,result.stdout,"application/json",str(raw_path))
        if status not in {"SUCCESS","OUTPUT_LIMITED"}:
            return CollectionBatch(artifacts=(artifact,),complete=False,warnings=(f"{self.name}: {status}",),raw_artifacts=(raw,),tool_runs=(run,))
        try:
            observations=self.adapter.parse(result.stdout,context,raw_artifact_id=artifact_id,source_artifact_id=artifact_id)
        except (ValueError,TypeError,KeyError,UnicodeError) as exc:
            run=ToolRun(run.run_id,run.analysis_id,run.snapshot_id,run.tool_name,run.tool_version,run.argv,run.cwd,run.environment_fingerprint,run.started_at,run.completed_at,run.exit_code,"PARSE_FAILED",run.stdout_hash,run.stderr_hash,run.raw_artifact_id,run.configuration_hash,run.repository_revision)
            return CollectionBatch(artifacts=(artifact,),complete=False,warnings=(f"{self.name}: PARSE_FAILED: {type(exc).__name__}",),raw_artifacts=(raw,),tool_runs=(run,))
        final_status="OUTPUT_LIMITED" if result.output_limited else ("NO_FINDINGS" if not observations else "FINDINGS")
        run=ToolRun(run.run_id,run.analysis_id,run.snapshot_id,run.tool_name,run.tool_version,run.argv,run.cwd,run.environment_fingerprint,run.started_at,run.completed_at,run.exit_code,final_status,run.stdout_hash,run.stderr_hash,run.raw_artifact_id,run.configuration_hash,run.repository_revision)
        return CollectionBatch(artifacts=(artifact,),observations=observations,complete=not result.output_limited,warnings=("tool output was truncated",) if result.output_limited else (),raw_artifacts=(raw,),tool_runs=(run,))
