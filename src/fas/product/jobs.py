"""Durable bounded job execution with atomic idempotency and crash recovery."""
from __future__ import annotations

import json
import socket
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from collections.abc import Callable
from threading import Event, Lock, Thread
from typing import Any

from fas.domain import new_id

from .storage import SQLiteStore


@dataclass(slots=True)
class JobHandle:
    id: str
    future: Future[object]
    cancel_event: Event


class JobManager:
    def __init__(self, store: SQLiteStore, max_workers: int = 2):
        if max_workers < 1:
            raise ValueError("max_workers must be positive")
        self.store = store
        self.pool = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="fas-worker"
        )
        self._handles: dict[str, JobHandle] = {}
        self._lock = Lock()
        self.worker_id = f"{socket.gethostname()}:{new_id('worker')}"
        self.store.recover_stale_jobs()

    def submit(
        self,
        *,
        kind: str,
        operation_key: str,
        payload: dict[str, object],
        fn: Callable[[Event], object],
    ) -> dict[str, object]:
        claim_token = f"{self.worker_id}:{new_id('claim')}"
        now = datetime.now(timezone.utc)
        job_id = (
            (self.store.job_by_key(operation_key) or {}).get("id")
            or new_id("job")
        )
        lease = (now + timedelta(minutes=5)).isoformat()
        claimed = self.store.job_claim(
            job_id,
            operation_key,
            kind,
            payload,
            now.isoformat(),
            claim_token,
            lease,
        )
        if claimed["status"] in {"RUNNING", "COMPLETED", "QUEUED"} and claimed.get(
            "worker_id"
        ) != claim_token:
            return jsonable(claimed)
        if claimed["status"] != "QUEUED":
            return jsonable(claimed)

        cancel = Event()

        def run() -> object:
            started = datetime.now(timezone.utc)
            started_iso = started.isoformat()
            lease_until = (started + timedelta(minutes=5)).isoformat()
            if not self.store.job_start(job_id, claim_token, started_iso, lease_until):
                return None
            stop_heartbeat = Event()

            def heartbeat() -> None:
                while not stop_heartbeat.wait(30):
                    stamp = datetime.now(timezone.utc)
                    requested = self.store.job_heartbeat(
                        job_id,
                        claim_token,
                        (stamp + timedelta(minutes=5)).isoformat(),
                        stamp.isoformat(),
                    )
                    if requested:
                        cancel.set()

            heartbeat_thread = Thread(
                target=heartbeat,
                name=f"fas-heartbeat-{job_id}",
                daemon=True,
            )
            heartbeat_thread.start()
            try:
                if self.store.job_cancel_requested(job_id, claim_token):
                    cancel.set()
                result = fn(cancel)
                status = "CANCELLED" if cancel.is_set() else "COMPLETED"
                finished = datetime.now(timezone.utc).isoformat()
                self.store.job_upsert(
                    job_id,
                    operation_key,
                    kind,
                    status,
                    {"request": payload, "result": result},
                    started_iso,
                    finished,
                )
                return result
            except TimeoutError as exc:
                finished = datetime.now(timezone.utc).isoformat()
                self.store.job_upsert(
                    job_id,
                    operation_key,
                    kind,
                    "TIMEOUT",
                    payload,
                    started_iso,
                    finished,
                    str(exc),
                )
                raise
            except Exception as exc:
                finished = datetime.now(timezone.utc).isoformat()
                self.store.job_upsert(
                    job_id,
                    operation_key,
                    kind,
                    "FAILED",
                    payload,
                    started_iso,
                    finished,
                    f"{type(exc).__name__}: {exc}",
                )
                raise
            finally:
                stop_heartbeat.set()
                heartbeat_thread.join(timeout=1)

        future = self.pool.submit(run)
        with self._lock:
            self._handles[job_id] = JobHandle(job_id, future, cancel)
        return {
            "id": job_id,
            "operation_key": operation_key,
            "kind": kind,
            "status": "QUEUED",
            "payload": payload,
        }

    def cancel(self, job_id: str) -> bool:
        with self._lock:
            handle = self._handles.get(job_id)
        if handle is not None:
            handle.cancel_event.set()
        return self.store.job_request_cancel(job_id, self.worker_id) or handle is not None

    def close(self) -> None:
        self.pool.shutdown(wait=True, cancel_futures=True)


def jsonable(row: dict[str, Any]) -> dict[str, object]:
    out = dict(row)
    out["payload"] = (
        json.loads(out["payload"])
        if isinstance(out.get("payload"), str)
        else out.get("payload")
    )
    return out
