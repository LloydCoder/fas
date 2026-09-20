"""Shared resource-bounded adapter helpers."""
from __future__ import annotations
import hashlib
from fas.domain.common import ObservationId
from fas.collectors.base import CollectionContext
from fas.collectors.parsing import ParseLimits,safe_json_loads
from fas.identity import stable_id
def load_json(payload,limits:ParseLimits|None=None):
    limits=limits or ParseLimits()
    if isinstance(payload,(dict,list)):
        return payload
    try: return safe_json_loads(payload,limits)
    except (TypeError,ValueError) as exc:
        raise ValueError("tool payload is not valid or safe JSON") from exc
def stable_observation_id(context:CollectionContext,material:str)->ObservationId:
    return stable_id("observation", f"{context.analysis_id}|{context.snapshot_id}|{material}")
