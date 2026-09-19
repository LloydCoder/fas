"""Deterministic replay manifests for Phase 3 collection."""
from __future__ import annotations
import hashlib,json
from dataclasses import dataclass
from .base import CollectionContext
from .contracts import CollectionPlan
@dataclass(frozen=True,slots=True)
class ReplayManifest:
    plan_hash:str
    analysis_id:str
    snapshot_id:str
    repository:str
    revision:str|None
    collectors:tuple[str,...]
    def canonical_json(self)->str:
        return json.dumps({"plan_hash":self.plan_hash,"analysis_id":self.analysis_id,"snapshot_id":self.snapshot_id,"repository":self.repository,"revision":self.revision,"collectors":self.collectors},sort_keys=True,separators=(",",":"))
def plan_hash(plan:CollectionPlan)->str:
    material=json.dumps({"analysis_id":plan.context.analysis_id,"snapshot_id":plan.context.snapshot_id,"repository":plan.context.repository,"revision":plan.context.revision,"collectors":[s.name for s in plan.specs]},sort_keys=True,separators=(",",":"))
    return "sha256:"+hashlib.sha256(material.encode()).hexdigest()
def manifest(plan:CollectionPlan)->ReplayManifest:
    return ReplayManifest(plan_hash(plan),plan.context.analysis_id,plan.context.snapshot_id,plan.context.repository,plan.context.revision,tuple(s.name for s in plan.specs))
def replay_compatible(context:CollectionContext,replay:ReplayManifest)->bool:
    return context.analysis_id==replay.analysis_id and context.snapshot_id==replay.snapshot_id and context.repository==replay.repository and context.revision==replay.revision

def replay(plan:CollectionPlan,replay:ReplayManifest,orchestrator=None):
    """Re-run the exact collector set only when snapshot/repository identity matches."""
    if not replay_compatible(plan.context,replay): raise ValueError("replay manifest is incompatible with collection context")
    if tuple(s.name for s in plan.specs)!=replay.collectors: raise ValueError("collector set differs from replay manifest")
    if plan_hash(plan)!=replay.plan_hash: raise ValueError("collection plan hash differs from replay manifest")
    if orchestrator is None:
        from .orchestrator import CollectionOrchestrator
        orchestrator=CollectionOrchestrator()
    return orchestrator.run(plan)
