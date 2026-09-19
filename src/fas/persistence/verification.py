"""Append-only Phase 5 JSONL persistence seam."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Protocol, TypeVar, Any

T=TypeVar("T")


class VerificationRepository(Protocol):
    def append(self, kind: str, value: Any) -> None: ...
    def latest(self, kind: str, identifier: str) -> dict[str, Any]: ...


class JsonlVerificationRepository:
    def __init__(self, path: Path):
        self.path=path
        self.path.parent.mkdir(parents=True,exist_ok=True)

    def append(self, kind: str, value: Any) -> None:
        payload=value.model_dump(mode="json") if hasattr(value,"model_dump") else value
        with self.path.open("a",encoding="utf-8") as f:
            f.write(json.dumps({"kind":kind,"payload":payload},sort_keys=True,separators=(",",":"))+"\n")

    def latest(self, kind: str, identifier: str) -> dict[str, Any]:
        latest=None
        if not self.path.exists():
            raise KeyError(identifier)
        for line in self.path.read_text(encoding="utf-8").splitlines():
            item=json.loads(line)
            payload=item["payload"]
            if item["kind"]==kind and payload.get("id",payload.get("verification_id"))==identifier:
                latest=payload
        if latest is None:
            raise KeyError(identifier)
        return latest
