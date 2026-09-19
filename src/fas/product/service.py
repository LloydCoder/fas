"""Application service shared by CLI and HTTP API."""
from __future__ import annotations
import hashlib, json, os, subprocess
from datetime import datetime, timezone
from pathlib import Path
from fas.domain import Analysis, AnalysisStatus, ContentHash, Project, RepositoryReference, Snapshot, new_id
from .config import Settings
from .storage import SQLiteStore, LocalObjectStore
from .reports import ReportService
from .jobs import JobManager

class ProductService:
    def __init__(self, settings: Settings):
        self.settings=settings
        self.store=SQLiteStore(settings.database_url)
        self.objects=LocalObjectStore(settings.object_store_path)
        self.jobs=JobManager(self.store,settings.max_workers)
        self.reports=ReportService(self.store)

    def create_project(self, name: str, repository: str, owner: str="local") -> Project:
        p=Project(id=new_id("project"),name=name,repository=repository,owner=owner,created_at=datetime.now(timezone.utc))
        self.store.put("projects",p.id,p.id,p.model_dump(mode="json"),p.created_at.isoformat())
        return p

    def get_project(self, project_id: str) -> Project:
        return Project.model_validate(self.store.get("projects",project_id))

    def create_analysis(self, project_id: str, source: str) -> Analysis:
        self.get_project(project_id)
        a=Analysis(id=new_id("analysis"),project=project_id,status=AnalysisStatus.CREATED,
                   metadata={"source":source,"coverage":"collection_only"})
        self.store.put("analyses",a.id,project_id,a.model_dump(mode="json"),a.created_at.isoformat())
        return a

    def snapshot(self, analysis: Analysis, root: Path) -> Snapshot:
        root=root.resolve()
        if not root.is_dir(): raise ValueError("analysis source must be a directory")
        digest=hashlib.sha256()
        files=[]
        for path in sorted(p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts):
            if path.is_symlink():
                continue
            try:
                resolved=path.resolve(strict=True)
                resolved.relative_to(root)
                rel=resolved.relative_to(root).as_posix()
                data=resolved.read_bytes()
            except (OSError, ValueError):
                continue
            if len(files)>=10000: break
            if len(data)>self.settings.max_artifact_bytes: continue
            digest.update(rel.encode()); digest.update(b"\0"); digest.update(hashlib.sha256(data).digest())
            files.append(rel)
        now=datetime.now(timezone.utc)
        snap=Snapshot(id=new_id("snapshot"),repository=RepositoryReference(repository=str(root),revision=_git_revision(root)),
                      captured_at=now,content_hash=ContentHash(digest=digest.hexdigest()),
                      source_reference=str(root),environment_identity=f"python:{__import__('sys').version_info.major}.{__import__('sys').version_info.minor}",
                      configuration_identity="local-defaults",immutable=True)
        self.store.put("snapshots",snap.id,analysis.id,snap.model_dump(mode="json"),now.isoformat())
        return snap

    def analyze_sync(self, project_id: str, root: Path, cancel=None) -> dict[str,object]:
        analysis=self.create_analysis(project_id,str(root))
        analysis=analysis.model_copy(update={"status":AnalysisStatus.DISCOVERING,"started_at":datetime.now(timezone.utc)})
        self._replace_analysis(analysis,project_id)
        snap=self.snapshot(analysis,root)
        if cancel is not None and getattr(cancel,"is_set",lambda:False)():
            cancelled=analysis.model_copy(update={"snapshot_ids":(snap.id,),"status":AnalysisStatus.CANCELLED,
                "completed_at":datetime.now(timezone.utc),"failure_reason":"analysis cancelled"})
            self._replace_analysis(cancelled,project_id)
            return {"analysis":cancelled.model_dump(mode="json"),"snapshot":snap.model_dump(mode="json"),"findings":[]}
        analysis=analysis.model_copy(update={"snapshot_ids":(snap.id,),"status":AnalysisStatus.PARTIAL,
            "completed_at":datetime.now(timezone.utc),
            "metadata":{**analysis.metadata,"limitations":"Core product pipeline records an immutable source snapshot and collection metadata. Deterministic verdicts require normalized security evidence; no evidence is fabricated."}})
        fixture=root/".fas-fixture.json"
        if fixture.exists():
            data=json.loads(fixture.read_text(encoding="utf-8"))
            analysis=analysis.model_copy(update={"metadata":{**analysis.metadata,"fixture":data.get("name","unknown"),"expected_verdict":data.get("expected_verdict","UNKNOWN")}})
        self._replace_analysis(analysis,project_id)
        return {"analysis":analysis.model_dump(mode="json"),"snapshot":snap.model_dump(mode="json"),"findings":[]}

    def _replace_analysis(self, analysis: Analysis, project_id: str) -> None:
        with self.store._connect() as con:
            con.execute("UPDATE analyses SET payload=? WHERE id=?", (json.dumps(analysis.model_dump(mode="json"),sort_keys=True),analysis.id))

    def get_analysis(self, analysis_id: str) -> Analysis:
        return Analysis.model_validate(self.store.get("analyses",analysis_id))

    def findings(self, analysis_id: str, snapshot_id: str|None=None, limit:int=100, offset:int=0):
        self.get_analysis(analysis_id)
        sid=snapshot_id or self.get_analysis(analysis_id).snapshot_ids[0]
        return self.store.list("findings","snapshot_id",sid,limit,offset)

    def report(self, analysis_id: str) -> dict[str,object]:
        a=self.get_analysis(analysis_id)
        if not a.snapshot_ids: raise ValueError("analysis has no snapshot")
        return self.reports.generate(analysis_id,a.snapshot_ids[-1]).model_dump(mode="json")

    def doctor(self) -> dict[str,object]:
        checks=[]
        checks.append({"name":"python","ok":__import__("sys").version_info >= (3,11),"detail":__import__("sys").version.split()[0]})
        checks.append({"name":"database","ok":True,"detail":str(self.store.path)})
        checks.append({"name":"object_store","ok":self.objects.root.is_dir(),"detail":str(self.objects.root)})
        checks.append({"name":"api_auth","ok":(not self.settings.auth_required) or bool(self.settings.api_token),"detail":"configured" if self.settings.api_token else "not configured"})
        return {"ok":all(c["ok"] for c in checks),"checks":checks}

def _git_revision(root: Path) -> str|None:
    git=root/".git"
    if not git.exists(): return None
    try:
        p=subprocess.run(["git","-C",str(root),"rev-parse","HEAD"],capture_output=True,text=True,timeout=5,check=True)
        return p.stdout.strip()
    except (OSError,subprocess.SubprocessError):
        return None
