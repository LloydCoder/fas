"""Durable bounded job execution with idempotency and cancellation."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor, Future
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Event, Lock
from fas.domain import new_id
from .storage import SQLiteStore

@dataclass(slots=True)
class JobHandle:
    id: str
    future: Future[object]
    cancel_event: Event

class JobManager:
    def __init__(self, store: SQLiteStore, max_workers: int = 2):
        self.store=store
        self.pool=ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="fas-worker")
        self._handles: dict[str,JobHandle]={}
        self._lock=Lock()
        self.store.recover_running_jobs()

    def submit(self, *, kind: str, operation_key: str, payload: dict[str,object], fn) -> dict[str,object]:
        existing=self.store.job_by_key(operation_key)
        if existing and existing["status"] in {"QUEUED","RUNNING","COMPLETED"}:
            return jsonable(existing)
        now=datetime.now(timezone.utc).isoformat()
        job_id=existing["id"] if existing else new_id("tool_run")
        self.store.job_upsert(job_id,operation_key,kind,"QUEUED",payload,now,now)
        cancel=Event()
        def run():
            started=datetime.now(timezone.utc).isoformat()
            self.store.job_upsert(job_id,operation_key,kind,"RUNNING",payload,now,started)
            try:
                result=fn(cancel)
                status="CANCELLED" if cancel.is_set() else "COMPLETED"
                finished=datetime.now(timezone.utc).isoformat()
                self.store.job_upsert(job_id,operation_key,kind,status,{"request":payload,"result":result},now,finished)
                return result
            except TimeoutError as exc:
                finished=datetime.now(timezone.utc).isoformat()
                self.store.job_upsert(job_id,operation_key,kind,"TIMEOUT",payload,now,finished,str(exc))
                raise
            except Exception as exc:
                finished=datetime.now(timezone.utc).isoformat()
                self.store.job_upsert(job_id,operation_key,kind,"FAILED",payload,now,finished,f"{type(exc).__name__}: {exc}")
                raise
        future=self.pool.submit(run)
        with self._lock: self._handles[job_id]=JobHandle(job_id,future,cancel)
        return {"id":job_id,"operation_key":operation_key,"kind":kind,"status":"QUEUED","payload":payload}

    def cancel(self, job_id: str) -> bool:
        with self._lock: handle=self._handles.get(job_id)
        return bool(handle and handle.cancel_event.set() is None)

def jsonable(row: dict[str,object]) -> dict[str,object]:
    out=dict(row)
    out["payload"]=__import__("json").loads(out["payload"]) if isinstance(out.get("payload"),str) else out.get("payload")
    return out
