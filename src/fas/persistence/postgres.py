"""PostgreSQL production persistence adapter."""
from __future__ import annotations
import hashlib, json
from datetime import datetime, timezone
from typing import Any

TABLES={
"projects":("id",None),"analyses":("id","project_id"),"snapshots":("id","analysis_id"),
"artifacts":("id","snapshot_id"),"observations":("id","snapshot_id"),"evidence":("id","snapshot_id"),
"graph_nodes":("id","snapshot_id"),"graph_edges":("id","snapshot_id"),"remediations":("id","analysis_id"),
"verifications":("id","analysis_id"),"findings":("id","snapshot_id"),"reports":("id","analysis_id"),
"audit_events":("id","analysis_id"),"tool_runs":("id","snapshot_id")}

class PostgresStore:
    def __init__(self,database_url:str,*,connect_factory:Any=None)->None:
        if not database_url.startswith(("postgresql://","postgres://")): raise ValueError("PostgreSQL store requires a PostgreSQL URL")
        if connect_factory is None:
            try:
                import psycopg
                from psycopg.rows import dict_row
            except ImportError as exc: raise RuntimeError("PostgreSQL support requires the production dependency set") from exc
            connect_factory=lambda:psycopg.connect(database_url,row_factory=dict_row)
        self._connect_factory=connect_factory
        self._init()

    def _connect(self): return self._connect_factory()
    @staticmethod
    def _ts(value:str)->datetime: return datetime.fromisoformat(value)

    def _init(self)->None:
        with self._connect() as con:
            con.execute("CREATE TABLE IF NOT EXISTS fas_tenants(tenant_id text PRIMARY KEY,created_at timestamptz NOT NULL DEFAULT now())")
            con.execute("CREATE TABLE IF NOT EXISTS fas_memberships(tenant_id text NOT NULL REFERENCES fas_tenants(tenant_id),subject text NOT NULL,role text NOT NULL CHECK(role IN ('reader','analyst','admin')),created_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(tenant_id,subject))")
            for table,(pk,fk) in TABLES.items():
                columns=f"{pk} text PRIMARY KEY,"
                if fk: columns+=f"{fk} text NOT NULL,"
                columns+="tenant_id text NOT NULL,payload jsonb NOT NULL,created_at timestamptz NOT NULL"
                con.execute(f"CREATE TABLE IF NOT EXISTS {table}({columns})")
                con.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_tenant_created ON {table}(tenant_id,created_at,{pk})")
            con.execute("""CREATE TABLE IF NOT EXISTS fas_jobs(
                id text PRIMARY KEY,operation_key text NOT NULL,kind text NOT NULL,status text NOT NULL,
                tenant_id text NOT NULL,payload jsonb NOT NULL,created_at timestamptz NOT NULL,updated_at timestamptz NOT NULL,
                error text,worker_id text,lease_until timestamptz,heartbeat_at timestamptz,
                retry_count integer NOT NULL DEFAULT 0,cancel_requested boolean NOT NULL DEFAULT false)""")
            con.execute("CREATE INDEX IF NOT EXISTS idx_fas_jobs_tenant_status ON fas_jobs(tenant_id,status,updated_at)")
            con.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_fas_jobs_tenant_operation ON fas_jobs(tenant_id,operation_key)")
            con.commit()

    def ensure_tenant(self,tenant_id:str,subject:str,role:str="admin")->None:
        if role not in {"reader","analyst","admin"}: raise ValueError("invalid role")
        with self._connect() as con:
            con.execute("INSERT INTO fas_tenants(tenant_id) VALUES(%s) ON CONFLICT DO NOTHING",(tenant_id,))
            con.execute("INSERT INTO fas_memberships(tenant_id,subject,role) VALUES(%s,%s,%s) ON CONFLICT(tenant_id,subject) DO UPDATE SET role=excluded.role",(tenant_id,subject,role))
            con.commit()

    def authorize(self,tenant_id:str,subject:str,minimum_role:str="reader")->bool:
        order={"reader":0,"analyst":1,"admin":2}
        with self._connect() as con:
            row=con.execute("SELECT role FROM fas_memberships WHERE tenant_id=%s AND subject=%s",(tenant_id,subject)).fetchone()
        return bool(row and order.get(row["role"],-1)>=order.get(minimum_role,99))

    def put(self,table:str,identifier:str,foreign_key:str,payload:dict[str,Any],created_at:str,*,tenant_id:str="local")->None:
        if table not in TABLES: raise ValueError("unsupported table")
        pk,fk=TABLES[table]
        if fk:
            columns=f"{pk},{fk},tenant_id,payload,created_at"; values=(identifier,foreign_key,tenant_id,json.dumps(payload),self._ts(created_at))
        else:
            columns=f"{pk},tenant_id,payload,created_at"; values=(identifier,tenant_id,json.dumps(payload),self._ts(created_at))
        with self._connect() as con:
            con.execute(f"INSERT INTO {table}({columns}) VALUES({','.join(['%s']*len(values))})",values); con.commit()

    def replace(self,table:str,identifier:str,payload:dict[str,Any],*,tenant_id:str="local")->None:
        if table not in TABLES: raise ValueError("unsupported table")
        with self._connect() as con:
            cur=con.execute(f"UPDATE {table} SET payload=%s WHERE id=%s AND tenant_id=%s",(json.dumps(payload),identifier,tenant_id));
            if cur.rowcount!=1: raise KeyError(identifier)
            con.commit()
    def get(self,table:str,identifier:str,*,tenant_id:str="local")->dict[str,Any]:
        if table not in TABLES: raise ValueError("unsupported table")
        with self._connect() as con:
            row=con.execute(f"SELECT payload FROM {table} WHERE id=%s AND tenant_id=%s",(identifier,tenant_id)).fetchone()
        if row is None: raise KeyError(identifier)
        return row["payload"]

    def list(self,table:str,foreign_col:str,foreign_value:str,limit:int=100,offset:int=0,*,tenant_id:str="local")->list[dict[str,Any]]:
        if table not in TABLES or foreign_col not in {"project_id","analysis_id","snapshot_id"}: raise ValueError("unsupported table/foreign key")
        if limit<0 or offset<0: raise ValueError("limit and offset must be non-negative")
        with self._connect() as con:
            rows=con.execute(f"SELECT payload FROM {table} WHERE {foreign_col}=%s AND tenant_id=%s ORDER BY created_at ASC,id ASC LIMIT %s OFFSET %s",(foreign_value,tenant_id,limit,offset)).fetchall()
        return [row["payload"] for row in rows]

    def append_audit(self,payload:dict[str,Any],*,tenant_id:str="local")->None:
        with self._connect() as con:
            rows=con.execute("SELECT payload FROM audit_events WHERE analysis_id=%s AND tenant_id=%s ORDER BY created_at ASC,id ASC",(payload["analysis_id"],tenant_id)).fetchall()
            previous=rows[-1]["payload"].get("_audit_event_hash") if rows else None
            canonical=json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=False)
            payload_hash=hashlib.sha256(canonical.encode()).hexdigest()
            event_hash=hashlib.sha256(f"{previous or 'GENESIS'}|{payload_hash}".encode()).hexdigest()
            chained={**payload,"_audit_previous_hash":previous,"_audit_payload_hash":payload_hash,"_audit_event_hash":event_hash}
            con.execute("INSERT INTO audit_events(id,analysis_id,tenant_id,payload,created_at) VALUES(%s,%s,%s,%s,%s)",(payload["id"],payload["analysis_id"],tenant_id,json.dumps(chained),self._ts(payload["created_at"])))
            con.commit()

    def verify_audit_chain(self,analysis_id:str,*,tenant_id:str="local")->dict[str,Any]:
        with self._connect() as con:
            rows=con.execute("SELECT id,payload FROM audit_events WHERE analysis_id=%s AND tenant_id=%s ORDER BY created_at ASC,id ASC",(analysis_id,tenant_id)).fetchall()
        previous=None; errors=[]
        for row in rows:
            item=row["payload"]; unsigned={k:v for k,v in item.items() if not k.startswith("_audit_")}
            ph=hashlib.sha256(json.dumps(unsigned,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
            expected=hashlib.sha256(f"{previous or 'GENESIS'}|{ph}".encode()).hexdigest()
            if item.get("_audit_previous_hash")!=previous or item.get("_audit_payload_hash")!=ph or item.get("_audit_event_hash")!=expected: errors.append(row["id"])
            previous=item.get("_audit_event_hash")
        return {"valid":not errors,"events":len(rows),"invalid_event_ids":tuple(errors)}

    def job_by_key(self,operation_key:str,*,tenant_id:str="local")->dict[str,Any]|None:
        with self._connect() as con:
            row=con.execute("SELECT * FROM fas_jobs WHERE operation_key=%s AND tenant_id=%s",(operation_key,tenant_id)).fetchone()
        return dict(row) if row else None

    def job_claim(self,job_id:str,operation_key:str,kind:str,payload:dict[str,Any],created_at:str,claim_token:str,lease_until:str,*,tenant_id:str="local")->dict[str,Any]:
        now=self._ts(created_at); lease=self._ts(lease_until)
        with self._connect() as con:
            con.execute("INSERT INTO fas_jobs(id,operation_key,kind,status,tenant_id,payload,created_at,updated_at,worker_id,lease_until,heartbeat_at) VALUES(%s,%s,%s,'QUEUED',%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(tenant_id,operation_key) DO NOTHING",(job_id,operation_key,kind,tenant_id,json.dumps(payload),now,now,claim_token,lease,now))
            con.execute("UPDATE fas_jobs SET status='QUEUED',kind=%s,payload=%s,updated_at=%s,worker_id=%s,lease_until=%s,heartbeat_at=%s,error=NULL,retry_count=retry_count+1,cancel_requested=false WHERE operation_key=%s AND tenant_id=%s AND status IN ('FAILED','TIMEOUT','CANCELLED')",(kind,json.dumps(payload),now,claim_token,lease,now,operation_key,tenant_id))
            row=con.execute("SELECT * FROM fas_jobs WHERE operation_key=%s AND tenant_id=%s FOR UPDATE",(operation_key,tenant_id)).fetchone(); con.commit()
        if row is None: raise RuntimeError("job claim failed")
        return dict(row)

    def job_start(self,job_id:str,worker_id:str,started_at:str,lease_until:str,*,tenant_id:str="local")->bool:
        with self._connect() as con:
            cur=con.execute("UPDATE fas_jobs SET status='RUNNING',worker_id=%s,lease_until=%s,heartbeat_at=%s,updated_at=%s WHERE id=%s AND tenant_id=%s AND status='QUEUED' AND worker_id=%s",(worker_id,self._ts(lease_until),self._ts(started_at),self._ts(started_at),job_id,tenant_id,worker_id)); con.commit()
            return cur.rowcount==1

    def job_heartbeat(self,job_id:str,worker_id:str,lease_until:str,heartbeat_at:str,*,tenant_id:str="local")->bool:
        with self._connect() as con:
            cur=con.execute("UPDATE fas_jobs SET heartbeat_at=%s,lease_until=%s,updated_at=%s WHERE id=%s AND tenant_id=%s AND status='RUNNING' AND worker_id=%s",(self._ts(heartbeat_at),self._ts(lease_until),self._ts(heartbeat_at),job_id,tenant_id,worker_id))
            row=con.execute("SELECT cancel_requested FROM fas_jobs WHERE id=%s AND tenant_id=%s",(job_id,tenant_id)).fetchone(); con.commit()
        if cur.rowcount!=1:return True
        return bool(row and row["cancel_requested"])

    def job_request_cancel(self,job_id:str,worker_id:str,*,tenant_id:str="local")->bool:
        with self._connect() as con:
            cur=con.execute("UPDATE fas_jobs SET cancel_requested=true,updated_at=%s WHERE id=%s AND tenant_id=%s AND status IN ('QUEUED','RUNNING') AND (worker_id=%s OR status='QUEUED')",(datetime.now(timezone.utc),job_id,tenant_id,worker_id)); con.commit()
            return cur.rowcount==1

    def job_cancel_requested(self,job_id:str,worker_id:str,*,tenant_id:str="local")->bool:
        with self._connect() as con:
            row=con.execute("SELECT cancel_requested FROM fas_jobs WHERE id=%s AND tenant_id=%s AND worker_id=%s AND status='RUNNING'",(job_id,tenant_id,worker_id)).fetchone()
        return bool(row and row["cancel_requested"])

    def job_upsert(self,job_id:str,operation_key:str,kind:str,status:str,payload:dict[str,Any],created_at:str,updated_at:str,error:str|None=None,*,tenant_id:str="local")->None:
        with self._connect() as con:
            con.execute("INSERT INTO fas_jobs(id,operation_key,kind,status,tenant_id,payload,created_at,updated_at,error) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(tenant_id,operation_key) DO UPDATE SET status=excluded.status,payload=excluded.payload,updated_at=excluded.updated_at,error=excluded.error",(job_id,operation_key,kind,status,tenant_id,json.dumps(payload),self._ts(created_at),self._ts(updated_at),error)); con.commit()

    def recover_stale_jobs(self,now:str|None=None,*,tenant_id:str="local")->int:
        stamp=self._ts(now or datetime.now(timezone.utc).isoformat())
        with self._connect() as con:
            cur=con.execute("UPDATE fas_jobs SET status='FAILED',error='worker lease expired',updated_at=%s,lease_until=NULL,worker_id=NULL WHERE tenant_id=%s AND status IN ('RUNNING','QUEUED') AND lease_until IS NOT NULL AND lease_until < %s",(stamp,tenant_id,stamp)); con.commit(); return cur.rowcount

    def recover_running_jobs(self,now:str|None=None,*,tenant_id:str="local")->int:
        return self.recover_stale_jobs(now,tenant_id=tenant_id)
