"""Resource-bounded parsing helpers for hostile tool output."""
from __future__ import annotations
import json
from dataclasses import dataclass

@dataclass(frozen=True,slots=True)
class ParseLimits:
    max_bytes:int=16*1024*1024
    max_depth:int=64
    max_items:int=200_000

class ParseLimitError(ValueError): pass

def safe_json_loads(payload:str|bytes,limits:ParseLimits|None=None):
    limits=limits or ParseLimits()
    data=payload.encode() if isinstance(payload,str) else payload
    if len(data)>limits.max_bytes:
        raise ParseLimitError("JSON payload exceeds max_bytes")
    try: value=json.loads(data)
    except (UnicodeDecodeError,json.JSONDecodeError) as exc: raise ValueError(f"invalid JSON:
        {exc}") from exc
    count=0
    def walk(node,depth):
        nonlocal count
        if depth>limits.max_depth:
            raise ParseLimitError("JSON nesting exceeds max_depth")
        count+=1
        if count>limits.max_items:
            raise ParseLimitError("JSON item limit exceeded")
        if isinstance(node,dict):
            for k,v in node.items():
                walk(k,depth+1)
            walk(v,depth+1)
        elif isinstance(node,list):
            for item in node:
                walk(item,depth+1)
    walk(value,0)
    return value
