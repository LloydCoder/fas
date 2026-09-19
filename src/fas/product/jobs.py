"""Durable bounded job execution with atomic idempotency and cancellation."""
from __future__ import annotations
import json
import socket
from concurrent.futures import ThreadPoolExecutor, Future
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from threading import Event, Lock
from fas.domain import new_id
from .storage import SQLiteStore

@dataclass(slots=True)
class JobHandle:
    id: str
    future: Future[object]
    cancel_event: Event

class JobManager:
    def __init__(self,store:SQLiteStore,max_workers:int=2):
        if max_workers<1: raise ValueError("max_workers must be positive")
        self.store=store
        self.pool=ThreadPoolExecutor(max_workers=max_workers,thread_name_prefix="fas-worker")
        self._handles={}
        self._lock=Lock()
        self.worker_id=f"{socket.gethostname()}:{new_id('worker')}"
        self.store.recover_running_jobs()

    def submit(self,*,kind:str,operation_key:str,payload:dict[str,object],fn)->dict[str,object]:
        now=datetime.now(timezone.utc)
        existing=self.store.job_by_key(operation_key)
        if existing and existing["status"] in {"QUEUED","RUNNING","COMPLETED"}:
            return jsonable(existing)
        job_id=existing["id"] if existing else new_id("tool_run")
        lease=(now+timedelta(minutes=5)).isoformat()
        claimed=self.store.job_claim(job_id,operation_key,kind,payload,now.isoformat(),self.worker_id,lease)
        if claimed["id"]!=job_id or claimed["status"] not in {"QUEUED","FAILED","TIMEOUT","CANCELLED"}:
            return jsonable(claimed)
        cancel=Event()
        def run():
            started=datetime.now(timezone.utc).isoformat()
            self.store.job_upsert(job_id,operation_key,kind,"RUNNING",payload,now.isoformat(),started)
            try:
                result=fn(cancel)
                status="CANCELLED" if cancel.is_set() else "COMPLETED"
                finished=datetime.now(timezone.utc).isoformat()
                self.store.job_upsert(job_id,operation_key,kind,status,{"request":payload,"result":result},now.isoformat(),finished)
                return result
            except TimeoutError as exc:
                finished=datetime.now(timezone.utc).isoformat()
                self.store.job_upsert(job_id,operation_key,kind,"TIMEOUT",payload,now.isoformat(),finished,str(exc))
                raise
            except Exception as exc:
                finished=datetime.now(timezone.utc).isoformat()
                self.store.job_upsert(job_id,operation_key,kind,"FAILED",payload,now.isoformat(),finished,f"{type(exc).__name__}: {exc}")
                raise
        future=self.pool.submit(run)
        with self._lock: self._handles[job_id]=JobHandle(job_id,future,cancel)
        return {"id":job_id,"operation_key":operation_key,"kind":kind,"status":"QUEUED","payload":payload}

    def cancel(self,job_id:str)->bool:
        with self._lock: handle=self._handles.get(job_id)
        if not handle: return False
        handle.cancel_event.set()
        return True

def jsonable(row:dict[str,object])->dict[str,object]:
    out=dict(row)
    out["payload"]=json.loads(out["payload"]) if isinstance(out.get("payload"),str) else out.get("payload")
    return out
