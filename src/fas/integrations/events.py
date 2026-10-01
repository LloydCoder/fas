"""Enterprise integration contracts and idempotent event normalization."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Mapping

@dataclass(frozen=True, slots=True)
class IntegrationEvent:
    provider:str
    event_type:str
    event_id:str
    tenant_id:str
    received_at:datetime
    payload:Mapping[str,object]
    delivery_id:str|None=None
    cursor:str|None=None
    @property
    def fingerprint(self)->str:
        body=json.dumps(self.payload,sort_keys=True,separators=(",",":"),default=str)
        return sha256(f"{self.provider}|{self.event_type}|{self.event_id}|{body}".encode()).hexdigest()

class EventNormalizer:
    """Normalize webhook or polling payloads without treating them as evidence."""
    def __init__(self,tenant_id:str):
        if not tenant_id or len(tenant_id)>128: raise ValueError("invalid tenant_id")
        self.tenant_id=tenant_id
    def normalize(self,provider:str,event_type:str,event_id:str,payload:Mapping[str,object],*,delivery_id:str|None=None,cursor:str|None=None)->IntegrationEvent:
        if not provider or not event_type or not event_id: raise ValueError("provider, event_type and event_id are required")
        return IntegrationEvent(provider,event_type,event_id,self.tenant_id,datetime.now(timezone.utc),dict(payload),delivery_id,cursor)

class IdempotencyLedger:
    """In-memory contract used by workers; durable deployments should persist fingerprints."""
    def __init__(self)->None: self._seen:set[tuple[str,str]]=set()
    def accept(self,event:IntegrationEvent)->bool:
        key=(event.tenant_id,event.fingerprint)
        if key in self._seen: return False
        self._seen.add(key); return True
