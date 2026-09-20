"""Local production-shaped persistence and content-addressed object storage.

SQLite is the supported local/system-test backend. The interface is intentionally small so
PostgreSQL/S3 implementations can be added without changing domain semantics.
"""
from __future__ import annotations
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects(id TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS analyses(id TEXT PRIMARY KEY, project_id TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS snapshots(id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS artifacts(id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS observations(id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS evidence(id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS graph_nodes(id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS graph_edges(id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS remediations(id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS verifications(id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reports(id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_events(id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, operation_key TEXT NOT NULL UNIQUE, kind TEXT NOT NULL, status TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, error TEXT, worker_id TEXT, lease_until TEXT, heartbeat_at TEXT, retry_count INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_analyses_project ON analyses(project_id, created_at);
CREATE INDEX IF NOT EXISTS idx_snapshots_analysis ON snapshots(analysis_id, created_at);
CREATE INDEX IF NOT EXISTS idx_artifacts_snapshot ON artifacts(snapshot_id, created_at);
CREATE INDEX IF NOT EXISTS idx_observations_snapshot ON observations(snapshot_id, created_at);
CREATE INDEX IF NOT EXISTS idx_evidence_snapshot ON evidence(snapshot_id, created_at);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_snapshot ON graph_nodes(snapshot_id, created_at);
CREATE INDEX IF NOT EXISTS idx_graph_edges_snapshot ON graph_edges(snapshot_id, created_at);
CREATE INDEX IF NOT EXISTS idx_remediations_analysis ON remediations(analysis_id, created_at);
CREATE INDEX IF NOT EXISTS idx_verifications_analysis ON verifications(analysis_id, created_at);
CREATE INDEX IF NOT EXISTS idx_findings_snapshot ON findings(snapshot_id, created_at);
CREATE INDEX IF NOT EXISTS idx_reports_analysis ON reports(analysis_id, created_at);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status, updated_at);
"""

class SQLiteStore:
    def __init__(self, database_url: str):
        if not database_url.startswith("sqlite:///"):
            raise ValueError("local product store currently supports sqlite:/// URLs only; PostgreSQL requires a dedicated adapter")
        raw = database_url.removeprefix("sqlite:///")
        self.path = Path(raw)
        if raw != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()
        if raw != ":memory:":
            try: self.path.chmod(0o600)
            except OSError: pass

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path.as_posix(), timeout=30, check_same_thread=False)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("PRAGMA journal_mode=WAL")
        return con

    def _init(self) -> None:
        with self._connect() as con:
            con.executescript(SCHEMA)
            columns = {row["name"] for row in con.execute("PRAGMA table_info(jobs)").fetchall()}
            for name, definition in (
                ("worker_id", "TEXT"),
                ("lease_until", "TEXT"),
                ("heartbeat_at", "TEXT"),
                ("retry_count", "INTEGER NOT NULL DEFAULT 0"),
            ):
                if name not in columns:
                    con.execute(f"ALTER TABLE jobs ADD COLUMN {name} {definition}")

    def put(self, table: str, identifier: str, foreign_key: str, payload: dict[str, Any], created_at: str) -> None:
        allowed = {"projects","analyses","snapshots","artifacts","observations","evidence","graph_nodes","graph_edges","remediations","verifications","findings","reports","audit_events"}
        if table not in allowed:
            raise ValueError("unsupported table")
        key_col = "id"
        serialized = json.dumps(payload, sort_keys=True, separators=(",",":"))
        with self._connect() as con:
            if table == "projects":
                con.execute("INSERT INTO projects(id,payload,created_at) VALUES(?,?,?)", (identifier, serialized, created_at))
            else:
                fk_col = {"analyses":"project_id","snapshots":"analysis_id","artifacts":"snapshot_id","observations":"snapshot_id","evidence":"snapshot_id","graph_nodes":"snapshot_id","graph_edges":"snapshot_id","remediations":"analysis_id","verifications":"analysis_id","findings":"snapshot_id","reports":"analysis_id","audit_events":"analysis_id"}[table]
                con.execute(f"INSERT INTO {table}({key_col},{fk_col},payload,created_at) VALUES(?,?,?,?)", (identifier, foreign_key, serialized, created_at))

    def get(self, table: str, identifier: str) -> dict[str, Any]:
        if table not in {"projects","analyses","snapshots","artifacts","observations","evidence","graph_nodes","graph_edges","remediations","verifications","findings","reports","audit_events","jobs"}:
            raise ValueError("unsupported table")
        with self._connect() as con:
            row = con.execute(f"SELECT payload FROM {table} WHERE id=?", (identifier,)).fetchone()
        if row is None:
            raise KeyError(identifier)
        return json.loads(row["payload"])

    def list(self, table: str, foreign_col: str, foreign_value: str, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        allowed = {"analyses":{"project_id"},"snapshots":{"analysis_id"},"artifacts":{"snapshot_id"},"observations":{"snapshot_id"},"evidence":{"snapshot_id"},"graph_nodes":{"snapshot_id"},"graph_edges":{"snapshot_id"},"remediations":{"analysis_id"},"verifications":{"analysis_id"},"findings":{"snapshot_id"},"reports":{"analysis_id"},"audit_events":{"analysis_id"}}
        if table not in allowed or foreign_col not in allowed[table]: raise ValueError("unsupported table/foreign key")
        if limit < 0 or offset < 0: raise ValueError("limit and offset must be non-negative")
        with self._connect() as con:
            rows=con.execute(f"SELECT payload FROM {table} WHERE {foreign_col}=? ORDER BY created_at ASC,id ASC LIMIT ? OFFSET ?",(foreign_value,limit,offset)).fetchall()
        return [json.loads(r["payload"]) for r in rows]

    def append_audit(self, payload: dict[str, Any]) -> None:
        with self._connect() as con:
            rows=con.execute("SELECT payload FROM audit_events WHERE analysis_id=? ORDER BY created_at ASC, id ASC",(payload["analysis_id"],)).fetchall()
            previous=None
            if rows:
                previous=json.loads(rows[-1]["payload"]).get("_audit_event_hash")
            canonical=json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=False)
            payload_hash=hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            chain_material=f"{previous or 'GENESIS'}|{payload_hash}".encode()
            event_hash=hashlib.sha256(chain_material).hexdigest()
            chained=dict(payload)
            chained["_audit_previous_hash"]=previous
            chained["_audit_payload_hash"]=payload_hash
            chained["_audit_event_hash"]=event_hash
            con.execute(
                "INSERT INTO audit_events(id,analysis_id,payload,created_at) VALUES(?,?,?,?)",
                (payload["id"],payload["analysis_id"],json.dumps(chained,sort_keys=True,separators=(",",":")),payload["created_at"]),
            )

    def verify_audit_chain(self, analysis_id: str) -> dict[str, Any]:
        with self._connect() as con:
            rows=con.execute("SELECT id,payload FROM audit_events WHERE analysis_id=? ORDER BY created_at ASC,id ASC",(analysis_id,)).fetchall()
        previous=None
        errors=[]
        for row in rows:
            item=json.loads(row["payload"])
            stored_payload_hash=item.get("_audit_payload_hash")
            stored_event_hash=item.get("_audit_event_hash")
            declared_previous=item.get("_audit_previous_hash")
            unsigned={k:v for k,v in item.items() if not k.startswith("_audit_")}
            payload_hash=hashlib.sha256(json.dumps(unsigned,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")).hexdigest()
            expected=hashlib.sha256(f"{previous or 'GENESIS'}|{payload_hash}".encode()).hexdigest()
            if declared_previous!=previous or stored_payload_hash!=payload_hash or stored_event_hash!=expected:
                errors.append(row["id"])
            previous=stored_event_hash
        return {"valid":not errors,"events":len(rows),"invalid_event_ids":tuple(errors)}

    def job_upsert(self, job_id: str, operation_key: str, kind: str, status: str, payload: dict[str, Any], created_at: str, updated_at: str, error: str | None = None) -> None:
        with self._connect() as con:
            con.execute("""INSERT INTO jobs(id,operation_key,kind,status,payload,created_at,updated_at,error)
                           VALUES(?,?,?,?,?,?,?,?)
                           ON CONFLICT(operation_key) DO UPDATE SET status=excluded.status,payload=excluded.payload,updated_at=excluded.updated_at,error=excluded.error""",
                        (job_id,operation_key,kind,status,json.dumps(payload,sort_keys=True),created_at,updated_at,error))

    def job_claim(self, job_id: str, operation_key: str, kind: str, payload: dict[str, Any], created_at: str, worker_id: str, lease_until: str) -> dict[str, Any]:
        with self._connect() as con:
            con.execute(
                """INSERT OR IGNORE INTO jobs(
                    id,operation_key,kind,status,payload,created_at,updated_at,error,worker_id,lease_until,heartbeat_at,retry_count
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,0)""",
                (job_id,operation_key,kind,"QUEUED",json.dumps(payload,sort_keys=True),created_at,created_at,None,worker_id,lease_until,created_at),
            )
            row = con.execute("SELECT * FROM jobs WHERE operation_key=?", (operation_key,)).fetchone()
        if row is None:
            raise RuntimeError("job claim failed")
        return dict(row)

    def job_by_key(self, operation_key: str) -> dict[str, Any] | None:
        with self._connect() as con:
            row=con.execute("SELECT * FROM jobs WHERE operation_key=?", (operation_key,)).fetchone()
        return dict(row) if row else None

    def job_heartbeat(self, job_id: str, worker_id: str, lease_until: str, heartbeat_at: str) -> bool:
        with self._connect() as con:
            cur=con.execute("UPDATE jobs SET heartbeat_at=?,lease_until=?,updated_at=? WHERE id=? AND status='RUNNING' AND worker_id=?",(heartbeat_at,lease_until,heartbeat_at,job_id,worker_id))
            return cur.rowcount == 1

    def recover_running_jobs(self, now: str | None = None) -> int:
        now=now or datetime.now(timezone.utc).isoformat()
        with self._connect() as con:
            cur=con.execute("UPDATE jobs SET status='FAILED',error='worker lease expired',updated_at=?,lease_until=NULL WHERE status='RUNNING' AND lease_until IS NOT NULL AND lease_until < ?",(now,now))
            return cur.rowcount

class LocalObjectStore:
    def __init__(self, root: str | Path):
        self.root=Path(root).resolve()
        self.root.mkdir(parents=True,exist_ok=True)
        try: self.root.chmod(0o700)
        except OSError: pass

    def put(self, data: bytes, *, media_type: str, snapshot_id: str, source: str) -> dict[str, Any]:
        digest=hashlib.sha256(data).hexdigest()
        directory=self.root/digest[:2]
        directory.mkdir(parents=True,exist_ok=True)
        target=directory/digest
        if not target.exists():
            import os
            import tempfile
            with tempfile.NamedTemporaryFile(dir=directory, prefix=f".{digest}.", suffix=".tmp", delete=False) as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
                tmp = Path(handle.name)
            if hashlib.sha256(tmp.read_bytes()).hexdigest() != digest:
                tmp.unlink(missing_ok=True)
                raise OSError("content-addressed object integrity check failed before commit")
            try:
                tmp.replace(target)
            finally:
                tmp.unlink(missing_ok=True)
        return {"artifact_id":f"sha256:{digest}","content_hash":f"sha256:{digest}","media_type":media_type,"size":len(data),"snapshot_id":snapshot_id,"source":source,"storage_reference":str(target)}

    def get(self, content_hash: str) -> bytes:
        digest=content_hash.removeprefix("sha256:")
        if len(digest)!=64 or any(c not in "0123456789abcdef" for c in digest.lower()):
            raise ValueError("invalid sha256 content hash")
        target = self.root / digest[:2] / digest
        data = target.read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise OSError("content-addressed object integrity check failed")
        return data
