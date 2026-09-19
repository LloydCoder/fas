"""Shared safe adapter helpers."""
from __future__ import annotations
import hashlib,json
from fas.domain.common import ObservationId
def load_json(payload):
    if isinstance(payload,(dict,list)): return payload
    try: return json.loads(payload)
    except (TypeError,json.JSONDecodeError) as exc: raise ValueError("tool payload is not valid JSON") from exc
def stable_observation_id(context:CollectionContext,material:str)->ObservationId:
    alphabet="0123456789ABCDEFGHJKMNPQRSTVWXYZ"; value=int.from_bytes(hashlib.sha256(f"{context.analysis_id}|{context.snapshot_id}|{material}".encode()).digest()[:16],"big"); chars=[]
    for _ in range(26): chars.append(alphabet[value&31]); value>>=5
    return f"observation_{''.join(reversed(chars))}"
