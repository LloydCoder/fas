"""Deterministic discovery of agent/tool/MCP configuration metadata."""
from __future__ import annotations
import json
from pathlib import Path
from .base import _BatchBuilder
from .discovery import _stable_id,_provenance
from fas.domain.analysis import Artifact,Observation
from fas.domain.common import ArtifactType,SourceLocation

_AGENT_NAMES={"mcp.json","mcp.config.json","agent.json","agents.json","tools.json"}
class AgentConfigurationCollector:
    name="agent-configuration"
    def collect(self,context):
        b=_BatchBuilder()
        for path in sorted(context.root.rglob("*")):
            try:
                if not path.is_file() or path.is_symlink() or path.name.lower() not in _AGENT_NAMES: continue
                if path.stat().st_size>context.max_file_bytes: b.complete=False;b.skipped+=1;b.warnings.append(f"agent config too large: {path}");continue
                data=path.read_text(encoding="utf-8"); digest=__import__("hashlib").sha256(data.encode()).hexdigest()
                aid=_stable_id("artifact",f"{context.snapshot_id}|agent|{path.relative_to(context.root)}|{digest}")
                prov=_provenance("agent_config_hash",path.name)
                artifact=Artifact(id=aid,analysis_id=context.analysis_id,type=ArtifactType.CONFIGURATION,name=path.relative_to(context.root).as_posix(),size_bytes=len(data.encode()),content_hash=__import__("fas.domain.common",fromlist=["ContentHash"]).ContentHash(digest=digest),snapshot_id=context.snapshot_id,provenance=(prov,),external_reference=str(path))
                b.artifacts.append(artifact)
                try: parsed=json.loads(data)
                except json.JSONDecodeError: parsed={"parse_error":True}
                b.observations.append(Observation(id=_stable_id("observation",f"agent|{aid}"),analysis_id=context.analysis_id,snapshot_id=context.snapshot_id,source=self.name,category="agent_configuration",location=SourceLocation(artifact_id=aid,path=artifact.name),message=f"Discovered agent configuration {artifact.name}",observed_value=_safe_shape(parsed),provenance=(prov,),observed_at=prov.observed_at,metadata={"sensitive_values_omitted":"true"}))
            except (OSError,UnicodeError) as exc: b.complete=False;b.skipped+=1;b.warnings.append(f"agent config unreadable: {exc}")
        return b.build()

def _safe_shape(value):
    if isinstance(value,dict): return {str(k):_safe_shape(v) for k,v in value.items() if str(k).lower() not in {"token","password","secret","api_key","authorization","credential"}}
    if isinstance(value,list): return [_safe_shape(v) for v in value[:1000]]
    if isinstance(value,(str,int,float,bool)) or value is None: return value
    return str(type(value).__name__)
