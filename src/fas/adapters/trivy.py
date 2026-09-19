"""Trivy JSON adapter."""
from __future__ import annotations
from datetime import datetime,timezone
from fas.domain.analysis import Observation
from fas.domain.common import Provenance,ProvenanceCategory,ProvenanceLevel
from .util import load_json,stable_observation_id
class TrivyAdapter:
    name="trivy"
    def parse(self,payload,context,*,raw_artifact_id=None,source_artifact_id=None):
        raw=load_json(payload)
        results=raw.get("Results",[]) if isinstance(raw,dict) else []
        observations=[]
        now=datetime.now(timezone.utc)
        for result_index,result in enumerate(results):
            target=result.get("Target")
            for item_index,vuln in enumerate(result.get("Vulnerabilities") or []):
                vulnerability_id=str(vuln.get("VulnerabilityID") or "unknown")
                package=str(vuln.get("PkgName") or vuln.get("PkgID") or "unknown")
                provenance=Provenance(category=ProvenanceCategory.TOOL_OBSERVATION,level=ProvenanceLevel.T2,collector=self.name,method="trivy_json_parse",source=f"Results[{result_index}].Vulnerabilities[{item_index}]",observed_at=now)
                observations.append(Observation(id=stable_observation_id(context,f"{result_index}:{item_index}:{vulnerability_id}:{package}:{target}"),analysis_id=context.analysis_id,snapshot_id=context.snapshot_id,source=self.name,category="vulnerability",message=str(vuln.get("Title") or vulnerability_id),raw_reference=f"Results[{result_index}].Vulnerabilities[{item_index}]",raw_artifact_id=source_artifact_id,observed_value={"vulnerability_id":vulnerability_id,"package":package,"installed_version":vuln.get("InstalledVersion"),"fixed_version":vuln.get("FixedVersion"),"severity":vuln.get("Severity"),"target":target,"status":vuln.get("Status"),"references":vuln.get("References") or []},provenance=(provenance,),observed_at=now))
        return tuple(observations)
