"""Gitleaks JSON adapter with secret-safe normalization."""
from __future__ import annotations
from datetime import datetime,timezone
from fas.domain.analysis import Observation
from fas.domain.common import Provenance,ProvenanceCategory,ProvenanceLevel,SourceLocation
from .util import load_json,stable_observation_id
class GitleaksAdapter:
    name="gitleaks"
    def parse(self,payload,context,*,raw_artifact_id=None,source_artifact_id=None):
        raw=load_json(payload)
        if not isinstance(raw,list): raise TypeError("gitleaks JSON report must be an array")
        observations=[]; now=datetime.now(timezone.utc)
        for index,item in enumerate(raw):
            rule_id=str(item.get("RuleID") or "unknown"); path=item.get("File") or item.get("SymlinkFile"); fingerprint=item.get("Fingerprint"); provenance=Provenance(category=ProvenanceCategory.TOOL_OBSERVATION,level=ProvenanceLevel.T2,collector=self.name,method="gitleaks_json_parse",source=f"[{index}]",observed_at=now); location=None
            if path and raw_artifact_id: location=SourceLocation(artifact_id=source_artifact_id,path=str(path),line_start=item.get("StartLine") or item.get("EndLine"),line_end=item.get("EndLine") or item.get("StartLine"),column_start=item.get("StartColumn"),column_end=item.get("EndColumn"),commit=item.get("Commit"))
            observations.append(Observation(id=stable_observation_id(context,f"{index}:{rule_id}:{path}:{fingerprint}"),analysis_id=context.analysis_id,snapshot_id=context.snapshot_id,source=self.name,category="secret",location=location,message=str(item.get("Description") or rule_id),raw_reference=f"[{index}]",raw_artifact_id=raw_artifact_id,observed_value={"rule_id":rule_id,"fingerprint":fingerprint,"description":item.get("Description"),"entropy":item.get("Entropy"),"tags":item.get("Tags") or [],"redacted":True},provenance=(provenance,),observed_at=now,metadata={"secret_material_omitted":"true"}))
        return tuple(observations)
