"""Observation-to-evidence normalization with provenance preservation."""
from __future__ import annotations
import hashlib,json
from fas.domain.analysis import Observation
from fas.domain.common import EvidenceId,EvidenceType
from fas.domain.evidence import Evidence
from .base import CollectionContext
class NormalizationError(ValueError): pass
_CATEGORY_MAP={"code":EvidenceType.CODE,"code_artifact":EvidenceType.CODE_LOCATION,"dependency_manifest":EvidenceType.DEPENDENCY,"secret":EvidenceType.TOOL_OUTPUT,"vulnerability":EvidenceType.TOOL_OUTPUT,"misconfiguration":EvidenceType.CONFIGURATION,"tool_result":EvidenceType.TOOL_OUTPUT,"static_analysis":EvidenceType.CODE}
def _evidence_id(context,observation)->EvidenceId:
    material=json.dumps(observation.model_dump(mode="json"),sort_keys=True,separators=(",",":"),ensure_ascii=False); alphabet="0123456789ABCDEFGHJKMNPQRSTVWXYZ"; value=int.from_bytes(hashlib.sha256(f"{context.analysis_id}|{context.snapshot_id}|{material}".encode()).digest()[:16],"big"); chars=[]
    for _ in range(26): chars.append(alphabet[value&31]); value>>=5
    return f"evidence_{''.join(reversed(chars))}"
class ObservationNormalizer:
    def normalize(self,observation,context):
        if observation.analysis_id!=context.analysis_id or observation.snapshot_id!=context.snapshot_id: raise NormalizationError("observation is outside collection scope")
        return Evidence(id=_evidence_id(context,observation),analysis_id=context.analysis_id,snapshot_id=context.snapshot_id,type=_CATEGORY_MAP.get(observation.category.lower(),EvidenceType.TOOL_OUTPUT),claim=observation.message,source=observation.location,observed_value=observation.observed_value,provenance=observation.provenance,related_artifact_ids=((observation.location.artifact_id,) if observation.location else ()),related_observation_ids=(observation.id,),observed_at=observation.observed_at,metadata={"source":observation.source,"category":observation.category,**observation.metadata})
    def normalize_many(self,observations,context): return tuple(self.normalize(item,context) for item in observations)
