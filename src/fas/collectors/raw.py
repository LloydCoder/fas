"""Raw tool-run and replay metadata with deterministic identity."""
from __future__ import annotations
import hashlib,json,platform,sys
from dataclasses import dataclass,asdict
from .base import CollectionContext
@dataclass(frozen=True,slots=True)
class ToolRun:
    run_id:str
    analysis_id:str
    snapshot_id:str
    tool_name:str
    tool_version:str|None
    argv:tuple[str,...]
    cwd:str
    environment_fingerprint:str
    started_at:str
    completed_at:str|None
    exit_code:int|None
    status:str
    stdout_hash:str|None
    stderr_hash:str|None
    raw_artifact_id:str|None=None
    configuration_hash:str|None=None
    repository_revision:str|None=None
    def canonical_json(self)->str: return json.dumps(asdict(self),sort_keys=True,separators=(",",":"))
@dataclass(frozen=True,slots=True)
class RawArtifact:
    artifact_id:str
    media_type:str
    size_bytes:int
    sha256:str
    storage_reference:str
    redacted:bool=False
def stable_run_id(context:CollectionContext, tool_name: str | None = None)->str:
    material=f"{context.analysis_id}|{context.snapshot_id}|{context.repository}|{context.revision or ''}|{tool_name or ''}"
    return "toolrun_"+hashlib.sha256(material.encode()).hexdigest()[:26]
def environment_fingerprint(env:dict[str,str]|None=None)->str:
    selected=env or {}
    material=json.dumps({"python":sys.version.split()[0],"platform":platform.platform(),"env_keys":sorted(selected)},sort_keys=True)
    return "sha256:"+hashlib.sha256(material.encode()).hexdigest()
def raw_artifact_from_bytes(artifact_id:str,data:bytes,media_type:str,storage_reference:str)->RawArtifact:
    return RawArtifact(artifact_id,media_type,len(data),hashlib.sha256(data).hexdigest(),storage_reference)
