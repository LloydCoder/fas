"""Deterministic evidence bundle manifest and integrity verification."""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
import json
from collections.abc import Mapping

@dataclass(frozen=True, slots=True)
class BundleEntry:
    path:str
    digest:str
    size:int

@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    schema_version:str
    tenant_id:str
    analysis_id:str
    entries:tuple[BundleEntry,...]
    metadata:Mapping[str,str]
    manifest_digest:str
    def canonical(self)->bytes:
        value={
            "schema_version":self.schema_version,"tenant_id":self.tenant_id,
            "analysis_id":self.analysis_id,
            "entries":[{"path":e.path,"digest":e.digest,"size":e.size} for e in self.entries],
            "metadata":dict(sorted(self.metadata.items())),
        }
        return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
    def verify(self)->bool:
        return sha256(self.canonical()).hexdigest()==self.manifest_digest

def build_bundle(tenant_id:str,analysis_id:str,files:Mapping[str,bytes],metadata:Mapping[str,str]|None=None)->EvidenceBundle:
    if not tenant_id or not analysis_id: raise ValueError("tenant_id and analysis_id are required")
    entries=[]
    for path,data in sorted(files.items()):
        if not path or path.startswith("/") or ".." in path.split("/"): raise ValueError("unsafe bundle path")
        entries.append(BundleEntry(path,"sha256:"+sha256(data).hexdigest(),len(data)))
    provisional=EvidenceBundle("1",tenant_id,analysis_id,tuple(entries),dict(metadata or {}),"")
    digest=sha256(provisional.canonical()).hexdigest()
    return EvidenceBundle(provisional.schema_version,tenant_id,analysis_id,provisional.entries,provisional.metadata,digest)
