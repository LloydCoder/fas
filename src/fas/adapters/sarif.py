"""SARIF 2.1.x adapter."""
from __future__ import annotations
from datetime import datetime,timezone
from typing import Any
from urllib.parse import urlparse
from fas.domain.analysis import Observation
from fas.domain.common import Provenance,ProvenanceCategory,ProvenanceLevel,SourceLocation
from .util import load_json,stable_observation_id
class SarifAdapter:
    name="sarif"
    def parse(self,payload,context,*,raw_artifact_id=None,source_artifact_id=None):
        raw=load_json(payload)
        if raw.get("version") not in {"2.1.0","2.1.0-errata01"}:
            raise ValueError("unsupported SARIF version")
        observations=[]
        for run_index,run in enumerate(raw.get("runs",[])):
            driver=((run.get("tool") or {}).get("driver") or {})
            tool_name=str(driver.get("name") or "unknown")
            version=driver.get("semanticVersion") or driver.get("version")
            now=datetime.now(timezone.utc)
            provenance=Provenance(category=ProvenanceCategory.TOOL_OBSERVATION,level=ProvenanceLevel.T2,collector=f"sarif:{tool_name}",collector_version=str(version) if version else None,method="sarif_parse",source=f"runs[{run_index}]",observed_at=now)
            for result_index,result in enumerate(run.get("results",[])):
                message=((result.get("message") or {}).get("text") or (result.get("message") or {}).get("markdown") or "SARIF result")
                rule_id=result.get("ruleId") or "unknown"
                locations=result.get("locations") or [None]
                for location_index,location in enumerate(locations):
                    source=_sarif_location(location,source_artifact_id)
                    identity=f"{run_index}:{result_index}:{location_index}:{rule_id}:{message}"
                    observations.append(Observation(id=stable_observation_id(context,identity),analysis_id=context.analysis_id,snapshot_id=context.snapshot_id,source=tool_name,category="tool_result",location=source,message=str(message),raw_reference=f"sarif:/runs/{run_index}/results/{result_index}",raw_artifact_id=source_artifact_id,observed_value={"rule_id":rule_id,"level":result.get("level"),"kind":result.get("kind"),"fingerprints":result.get("fingerprints") or result.get("partialFingerprints") or {}},provenance=(provenance,),observed_at=now,metadata={"format":"SARIF","tool":tool_name}))
        return tuple(observations)
def _sarif_location(location:Any,raw_artifact_id):
    if not isinstance(location,dict):
        return None
    physical=location.get("physicalLocation") or {}
    artifact=physical.get("artifactLocation") or {}
    uri=artifact.get("uri")
    region=physical.get("region") or {}
    if not uri or not raw_artifact_id:
        return None
    parsed=urlparse(str(uri))
    path=parsed.path or str(uri)
    return SourceLocation(artifact_id=raw_artifact_id,path=path.lstrip("/"),line_start=region.get("startLine"),line_end=region.get("endLine"),column_start=region.get("startColumn"),column_end=region.get("endColumn"))
