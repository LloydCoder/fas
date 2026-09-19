"""Shared resource-bounded adapter helpers."""
from __future__ import annotations
import hashlib
from fas.domain.common import ObservationId
from fas.collectors.base import CollectionContext
from fas.collectors.parsing import ParseLimits,safe_json_loads
def load_json(payload,limits:ParseLimits|None=None):
    limits=limits or ParseLimits()
    if isinstance(payload,(dict,list)):
        return payload
    try: return safe_json_loads(payload,limits)
    except (TypeError,ValueError) as exc:
        raise ValueError("tool payload is not valid or safe JSON") from exc
def stable_observation_id(context:CollectionContext,material:str)->ObservationId:
    alphabet="0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    value=int.from_bytes(hashlib.sha256(f"{context.analysis_id}|{context.snapshot_id}|{material}".encode()).digest()[:16],"big")
    chars=[]
    for _ in range(26):
        chars.append(alphabet[value&31])
    value>>=5
    return f"observation_{''.join(reversed(chars))}"
