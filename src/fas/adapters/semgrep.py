"""Semgrep JSON adapter."""
from __future__ import annotations
from datetime import datetime,timezone
from fas.domain.analysis import Observation
from fas.domain.common import Provenance,ProvenanceCategory,ProvenanceLevel,SourceLocation
from .util import load_json,stable_observation_id
class SemgrepAdapter:
    name="semgrep"
    def parse(self,payload,context,*,raw_artifact_id=None,source_artifact_id=None):
        raw=load_json(payload); results=raw.get("results",[]) if isinstance(raw,dict) else []; observations=[]; now=datetime.now(timezone.utc); version=raw.get("version") if isinstance(raw,dict) else None
        for index,item in enumerate(results):
            extra=item.get("extra") or {}; start=item.get("start") or {}; end=item.get("end") or {}; path=item.get("path"); location=None
            if path and source_artifact_id: location=SourceLocation(artifact_id=source_artifact_id,path=str(path),line_start=start.get("line"),line_end=end.get("line") or start.get("line"),column_start=start.get("col"),column_end=end.get("col"))
            rule=str(item.get("check_id") or "unknown"); message=str(extra.get("message") or rule); provenance=Provenance(category=ProvenanceCategory.TOOL_OBSERVATION,level=ProvenanceLevel.T2,collector=self.name,collector_version=str(version) if version else None,method="semgrep_json_parse",source=f"results[{index}]",observed_at=now)
            observations.append(Observation(id=stable_observation_id(context,f"{index}:{rule}:{path}:{start}"),analysis_id=context.analysis_id,snapshot_id=context.snapshot_id,source=self.name,category="static_analysis",location=location,message=message,raw_reference=f"results[{index}]",raw_artifact_id=raw_artifact_id,observed_value={"check_id":rule,"severity":extra.get("severity"),"metadata":extra.get("metadata") or {},"lines":{"start":start.get("line"),"end":end.get("line")}},provenance=(provenance,),observed_at=now))
        return tuple(observations)
