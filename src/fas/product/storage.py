"""Local production-shaped persistence and content-addressed object storage.

SQLite is the supported local/system-test backend. The interface is intentionally small so
PostgreSQL/S3 implementations can be added without changing domain semantics.
"""
from __future__ import annotations
import hashlib, json, sqlite3
from pathlib import Path
from typing import Any
from fas.domain import Analysis, Artifact, Finding, Project, Report, Snapshot

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects(id TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS analyses(id TEXT PRIMARY KEY, project_id TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS snapshots(id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS artifacts(id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reports(id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_events(id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, operation_key TEXT NOT NULL UNIQUE, kind TEXT NOT NULL, status TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, error TEXT);
CREATE INDEX IF NOT EXISTS idx_analyses_project ON analyses(project_id, created_at);
CREATE INDEX IF NOT EXISTS idx_snapshots_analysis ON snapshots(analysis_id, created_at);
CREATE INDEX IF NOT EXISTS idx_artifacts_snapshot ON artifacts(snapshot_id, created_at);
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

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path.as_posix(), timeout=30, check_same_thread=False)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("PRAGMA journal_mode=WAL")
        return con

    def _init(self) -> None:
        with self._connect() as con:
            con.executescript(SCHEMA)

    def put(self, table: str, identifier: str, foreign_key: str, payload: dict[str, Any], created_at: str) -> None:
        allowed = {"projects","analyses","snapshots","artifacts","findings","reports","audit_events"}
        if table not in allowed:
            raise ValueError("unsupported table")
        key_col = {"projects":"id","analyses":"id","snapshots":"id","artifacts":"id","findings":"id","reports":"id","audit_events":"id"}[table]
        fk_col = {"projects":"id","analyses":"project_id","snapshots":"analysis_id","artifacts":"snapshot_id","findings":"snapshot_id","reports":"analysis_id","audit_events":"analysis_id"}[table]
        with self._connect() as con:
            con.execute(f"INSERT INTO {table}({key_col},{fk_col},payload,created_at) VALUES(?,?,?,?)",
                        (identifier, foreign_key, json.dumps(payload, sort_keys=True, separators=(",",":")), created_at))

    def get(self, table: str, identifier: str) -> dict[str, Any]:
        if table not in {"projects","analyses","snapshots","artifacts","findings","reports","audit_events","jobs"}:
            raise ValueError("unsupported table")
        with self._connect() as con:
            row = con.execute(f"SELECT payload FROM {table} WHERE id=?", (identifier,)).fetchone()
        if row is None:
            raise KeyError(identifier)
        return json.loads(row["payload"])

    def list(self, table: str, foreign_col: str, foreign_value: str, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        if table not in {"analyses","snapshots","artifacts","findings","reports","audit_events"}:
            raise ValueError("unsupported table")
        with self._connect() as con:
            rows = con.execute(f"SELECT payload FROM {table} WHERE {foreign_col}=? ORDER BY created_at ASC, id ASC LIMIT ? OFFSET ?",
                               (foreign_value, limit, offset)).fetchall()
        return [json.loads(r["payload"]) for r in rows]

    def append_audit(self, payload: dict[str, Any]) -> None:
        self.put("audit_events", payload["id"], payload["analysis_id"], payload, payload["created_at"])

    def job_upsert(self, job_id: str, operation_key: str, kind: str, status: str, payload: dict[str, Any], created_at: str, updated_at: str, error: str | None = None) -> None:
        with self._connect() as con:
            con.execute("""INSERT INTO jobs(id,operation_key,kind,status,payload,created_at,updated_at,error)
                           VALUES(?,?,?,?,?,?,?,?)
                           ON CONFLICT(operation_key) DO UPDATE SET status=excluded.status,payload=excluded.payload,updated_at=excluded.updated_at,error=excluded.error""",
                        (job_id,operation_key,kind,status,json.dumps(payload,sort_keys=True),created_at,updated_at,error))

    def job_by_key(self, operation_key: str) -> dict[str, Any] | None:
        with self._connect() as con:
            row=con.execute("SELECT * FROM jobs WHERE operation_key=?", (operation_key,)).fetchone()
        return dict(row) if row else None

    def recover_running_jobs(self) -> int:
        with self._connect() as con:
            cur=con.execute("UPDATE jobs SET status='FAILED', error='worker restarted while job was running', updated_at=datetime('now') WHERE status='RUNNING'")
            return cur.rowcount

class LocalObjectStore:
    def __init__(self, root: str | Path):
        self.root=Path(root).resolve()
        self.root.mkdir(parents=True,exist_ok=True)

    def put(self, data: bytes, *, media_type: str, snapshot_id: str, source: str) -> dict[str, Any]:
        digest=hashlib.sha256(data).hexdigest()
        directory=self.root/digest[:2]
        directory.mkdir(parents=True,exist_ok=True)
        target=directory/digest
        if not target.exists():
            tmp=target.with_suffix(".tmp")
            tmp.write_bytes(data)
            tmp.replace(target)
        return {"artifact_id":f"sha256:{digest}","content_hash":f"sha256:{digest}","media_type":media_type,"size":len(data),"snapshot_id":snapshot_id,"source":source,"storage_reference":str(target)}

    def get(self, content_hash: str) -> bytes:
        digest=content_hash.removeprefix("sha256:")
        if len(digest)!=64 or any(c not in "0123456789abcdef" for c in digest.lower()):
            raise ValueError("invalid sha256 content hash")
        target=self.root/digest[:2]/digest
        return target.read_bytes()
