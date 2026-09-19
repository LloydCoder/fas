"""Application service shared by CLI and HTTP API."""
from __future__ import annotations
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from fas.domain import Analysis, AnalysisStatus, AuditEvent, ContentHash, Project, RepositoryReference, Snapshot, new_id
from fas.collectors import CollectionContext, CollectionPlan, CollectionOrchestrator, CodeDiscoveryCollector, DependencyDiscoveryCollector, ConfigurationCollector, CICDCollector, AgentConfigurationCollector
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
        if not root.is_dir():
            raise ValueError("analysis source must be a directory")
        digest=hashlib.sha256()
        manifest=[]
        omitted=[]
        file_count=0
        byte_count=0
        max_files=10000
        for path in sorted(root.rglob("*")):
            if path.is_dir() or ".git" in path.parts or ".fas" in path.parts:
                continue
            rel=path.relative_to(root).as_posix()
            if path.is_symlink():
                omitted.append({"path":rel,"reason":"SYMLINK"})
                continue
            try:
                resolved=path.resolve(strict=True)
                resolved.relative_to(root)
                data=resolved.read_bytes()
            except (OSError,ValueError):
                omitted.append({"path":rel,"reason":"UNREADABLE"})
                continue
            if file_count>=max_files:
                omitted.append({"path":rel,"reason":"FILE_LIMIT"})
                continue
            if len(data)>self.settings.max_artifact_bytes:
                omitted.append({"path":rel,"reason":"FILE_SIZE_LIMIT","size_bytes":len(data)})
                continue
            file_hash=hashlib.sha256(data).hexdigest()
            digest.update(rel.encode("utf-8"))
            digest.update(b"\0")
            digest.update(file_hash.encode("ascii"))
            manifest.append({"path":rel,"sha256":file_hash,"size_bytes":len(data)})
            file_count+=1
            byte_count+=len(data)
        completeness="COMPLETE" if not omitted else "PARTIAL"
        manifest_payload={"files":manifest,"omitted":omitted,"file_count":file_count,"byte_count":byte_count,
                          "max_files":max_files,"max_file_bytes":self.settings.max_artifact_bytes,
                          "completeness":completeness}
        manifest_hash=hashlib.sha256(json.dumps(manifest_payload,sort_keys=True,separators=(",",":")).encode()).hexdigest()
        now=datetime.now(timezone.utc)
        snap=Snapshot(id=new_id("snapshot"),repository=RepositoryReference(repository=str(root),revision=_git_revision(root)),
                      captured_at=now,content_hash=ContentHash(digest=digest.hexdigest()),
                      source_reference=str(root),environment_identity=f"python:{__import__('sys').version_info.major}.{__import__('sys').version_info.minor}",
                      configuration_identity="local-defaults",immutable=True,
                      metadata={"manifest_sha256":manifest_hash,"file_count":str(file_count),"byte_count":str(byte_count),
                                "completeness":completeness,"omitted_count":str(len(omitted))})
        self.store.put("snapshots",snap.id,analysis.id,snap.model_dump(mode="json"),now.isoformat())
        self._audit(analysis.id,snap.id,"SNAPSHOT_CREATED",snap.id,{"source":str(root),"content_hash":snap.content_hash.value if snap.content_hash else None,
                                                                    "manifest_sha256":manifest_hash,"completeness":completeness})
        return snap

    def analyze_sync(self, project_id: str, root: Path, cancel=None) -> dict[str,object]:
        analysis=self.create_analysis(project_id,str(root))
        analysis=analysis.model_copy(update={"status":AnalysisStatus.DISCOVERING,"started_at":datetime.now(timezone.utc)})
        self._replace_analysis(analysis,project_id)
        snap=self.snapshot(analysis,root)
        analysis=analysis.model_copy(update={"snapshot_ids":(snap.id,),"status":AnalysisStatus.COLLECTING})
        self._replace_analysis(analysis,project_id)
        context=CollectionContext(analysis_id=analysis.id,snapshot_id=snap.id,root=root,repository=str(root),
                                  revision=snap.repository.revision,max_files=10000,max_file_bytes=self.settings.max_artifact_bytes)
        collectors = [CodeDiscoveryCollector(), DependencyDiscoveryCollector(), ConfigurationCollector(), CICDCollector(), AgentConfigurationCollector()]
        plan = CollectionPlan(context=context, collectors=tuple(collectors))
        collection = CollectionOrchestrator().run(plan, cancel=cancel)
        for artifact in collection.batch.artifacts:
            self.store.put("artifacts",artifact.id,snap.id,artifact.model_dump(mode="json"),artifact.provenance[0].observed_at.isoformat())
        for observation in collection.batch.observations:
            self.store.put("observations",observation.id,snap.id,observation.model_dump(mode="json"),observation.observed_at.isoformat())
        analysis=analysis.model_copy(update={"status":AnalysisStatus.NORMALIZING,
            "metadata":{**analysis.metadata,"collection_status":collection.summary.status.value,
                        "artifact_count":str(collection.summary.artifacts),
                        "observation_count":str(collection.summary.observations)}})
        self._replace_analysis(analysis,project_id)
        if cancel is not None and getattr(cancel,"is_set",lambda:False)():
            cancelled=analysis.model_copy(update={"snapshot_ids":(snap.id,),"status":AnalysisStatus.CANCELLED,
                "completed_at":datetime.now(timezone.utc),"failure_reason":"analysis cancelled"})
            self._replace_analysis(cancelled,project_id)
            return {"analysis":cancelled.model_dump(mode="json"),"snapshot":snap.model_dump(mode="json"),"findings":[]}
        terminal_status = AnalysisStatus.COMPLETED if collection.summary.status.value == "SUCCESS" else AnalysisStatus.PARTIAL
        analysis=analysis.model_copy(update={"snapshot_ids":(snap.id,),"status":terminal_status,
            "completed_at":datetime.now(timezone.utc),
            "metadata":{**analysis.metadata,
                        "limitations":"Product collection is deterministic and bounded; downstream verdicts require normalized security evidence and are never fabricated.",
                        "analysis_completeness":"COMPLETE" if terminal_status == AnalysisStatus.COMPLETED else "PARTIAL"}})
        # Benchmark/test oracle files are never read by production analysis.
        # A target repository must not be able to manufacture an expected verdict.
        self._replace_analysis(analysis,project_id)
        return {"analysis":analysis.model_dump(mode="json"),"snapshot":snap.model_dump(mode="json"),"findings":[]}

    def _audit(self, analysis_id: str, snapshot_id: str, event_type: str, subject_id: str, payload: dict[str,object]) -> None:
        event=AuditEvent(id=new_id("audit_event"),analysis_id=analysis_id,snapshot_id=snapshot_id,
                         event_type=event_type,actor="fas",subject_id=subject_id,payload=payload)
        self.store.append_audit(event.model_dump(mode="json"))

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
        if not a.snapshot_ids:
            raise ValueError("analysis has no snapshot")
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
    if not git.exists():
        return None
    try:
        p=subprocess.run(["git","-C",str(root),"rev-parse","HEAD"],capture_output=True,text=True,timeout=5,check=True)
        return p.stdout.strip()
    except (OSError,subprocess.SubprocessError):
        return None
