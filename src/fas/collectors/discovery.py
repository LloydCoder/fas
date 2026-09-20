"""Repository, code, and dependency discovery collectors."""
from __future__ import annotations
import hashlib,json,os,re,tomllib
from datetime import datetime,timezone
from pathlib import Path
from fas.domain.analysis import Artifact,Observation
from fas.identity import stable_id
from fas.domain.common import ArtifactType,ContentHash,Provenance,ProvenanceCategory,ProvenanceLevel,SourceLocation
from .base import _BatchBuilder
from .filesystem import safe_read_bytes,ResourceLimitError

_SKIP_DIRS=frozenset({".git",".fas",".hg",".svn",".venv","venv","node_modules","__pycache__",".mypy_cache",".pytest_cache",".ruff_cache","dist","build","coverage",".tox",".idea",".vscode"})
_SOURCE_SUFFIXES=frozenset({".py",".pyi",".js",".jsx",".ts",".tsx",".java",".kt",".go",".rs",".c",".h",".cc",".cpp",".hpp",".cs",".php",".rb",".swift",".scala",".sh",".bash",".zsh",".sql",".yaml",".yml",".json",".toml",".ini"})
_MANIFEST_NAMES=frozenset({"Dockerfile","docker-compose.yml","docker-compose.yaml",".env","pyproject.toml","requirements.txt","requirements-dev.txt","Pipfile","Pipfile.lock","poetry.lock","package.json","package-lock.json","npm-shrinkwrap.json","yarn.lock","pnpm-lock.yaml","go.mod","go.sum","Cargo.toml","Cargo.lock","Gemfile","Gemfile.lock","composer.json","composer.lock","pom.xml","build.gradle","build.gradle.kts"})

def _stable_id(prefix,material):
    return stable_id(prefix, material)

def _provenance(method,source):
    return Provenance(category=ProvenanceCategory.VERIFIED_ARTIFACT,level=ProvenanceLevel.T3,collector="repository-discovery",collector_version="1",method=method,source=source,observed_at=datetime.now(timezone.utc))

def _artifact_type(path):
    name=path.name
    if name in _MANIFEST_NAMES or name.endswith((".lock",".sum")):
        return ArtifactType.DEPENDENCY_METADATA
    if name == "Dockerfile" or path.suffix.lower() in {".yaml",".yml",".toml",".ini",".env",".tf",".tfvars"}:
        return ArtifactType.CONFIGURATION
    if path.suffix.lower() in {".sarif",".json"} and any(x in name.lower() for x in ("report","result","scan")):
        return ArtifactType.TOOL_OUTPUT
    if path.suffix.lower() in _SOURCE_SUFFIXES:
        return ArtifactType.SOURCE_FILE
    return ArtifactType.BINARY

class RepositoryDiscoveryCollector:
    name="repository-discovery"
    def collect(self,context):
        builder,count=_BatchBuilder(),0
        for root,dirs,files in os.walk(context.root,followlinks=False):
            dirs[:]=sorted(d for d in dirs if d not in _SKIP_DIRS)
            for filename in sorted(files):
                if count>=context.max_files:
                    builder.complete=False
                    builder.warnings.append("max_files reached")
                    return builder.build()
                path=Path(root)/filename
                try:
                    if path.is_symlink() or not path.is_file():
                        builder.skipped+=1
                        continue
                    relative=path.relative_to(context.root).as_posix()
                    size=path.stat().st_size
                    if size>context.max_file_bytes:
                        builder.skipped+=1
                        builder.warnings.append(f"file exceeds max_file_bytes: {relative}")
                        continue
                    data=safe_read_bytes(path,context.root,context.max_file_bytes)
                except (OSError,ValueError,ResourceLimitError) as exc:
                    builder.skipped+=1
                    builder.complete=False
                    builder.warnings.append(f"unreadable file {path}: {exc}")
                    continue
                digest=hashlib.sha256(data).hexdigest()
                aid=_stable_id("artifact",f"{context.snapshot_id}|{relative}|{digest}")
                prov=_provenance("filesystem_hash",relative)
                builder.artifacts.append(Artifact(id=aid,analysis_id=context.analysis_id,type=_artifact_type(path),name=relative,size_bytes=size,content_hash=ContentHash(digest=digest),snapshot_id=context.snapshot_id,provenance=(prov,),external_reference=str(path),metadata={"repository":context.repository,**({"revision":context.revision} if context.revision else {})}))
                count+=1
        return builder.build()

class CodeDiscoveryCollector:
    name="code-discovery"
    def collect(self,context):
        discovered=RepositoryDiscoveryCollector().collect(context)
        observations=[]
        for artifact in discovered.artifacts:
            if artifact.type!=ArtifactType.SOURCE_FILE:
                continue
            observations.append(Observation(id=_stable_id("observation",f"code|{context.snapshot_id}|{artifact.id}"),analysis_id=context.analysis_id,snapshot_id=context.snapshot_id,source=self.name,category="code_artifact",location=SourceLocation(artifact_id=artifact.id,path=artifact.name),message=f"Discovered source artifact {artifact.name}",observed_value={"path":artifact.name,"size_bytes":artifact.size_bytes,"content_hash":artifact.content_hash.value if artifact.content_hash else None},provenance=artifact.provenance,observed_at=artifact.provenance[0].observed_at,metadata={"artifact_type":artifact.type.value}))
        return discovered.__class__(artifacts=discovered.artifacts,observations=tuple(observations),complete=discovered.complete,skipped=discovered.skipped,warnings=discovered.warnings)

class DependencyDiscoveryCollector:
    name="dependency-discovery"
    def collect(self,context):
        discovered=RepositoryDiscoveryCollector().collect(context)
        observations=[]
        for artifact in discovered.artifacts:
            if artifact.type!=ArtifactType.DEPENDENCY_METADATA:
                continue
            path=context.root/artifact.name
            try: data=path.read_text(encoding="utf-8")
            except (OSError,UnicodeError) as exc:
                return discovered.__class__(artifacts=discovered.artifacts,observations=tuple(observations),complete=False,skipped=discovered.skipped,warnings=(*discovered.warnings,f"dependency manifest unreadable {artifact.name}: {exc}"))
            observations.append(Observation(id=_stable_id("observation",f"dependency|{context.snapshot_id}|{artifact.id}"),analysis_id=context.analysis_id,snapshot_id=context.snapshot_id,source=self.name,category="dependency_manifest",location=SourceLocation(artifact_id=artifact.id,path=artifact.name),message=f"Discovered dependency metadata in {artifact.name}",observed_value=_parse_dependency_manifest(artifact.name,data),provenance=artifact.provenance,observed_at=artifact.provenance[0].observed_at,metadata={"format":Path(artifact.name).name}))
        return discovered.__class__(artifacts=discovered.artifacts,observations=tuple(observations),complete=discovered.complete,skipped=discovered.skipped,warnings=discovered.warnings)

def _parse_dependency_manifest(name,data):
    lower=name.lower()
    if lower=="pyproject.toml":
        raw=tomllib.loads(data)
        project=raw.get("project",{})
        return {"format":"pyproject.toml","dependencies":project.get("dependencies",[]) if isinstance(project,dict) else [],"optional_dependencies":project.get("optional-dependencies",{}) if isinstance(project,dict) else {}}
    if lower.endswith(".json"):
        raw=json.loads(data)
        return {"format":Path(name).name,"dependencies":raw.get("dependencies",{}) if isinstance(raw,dict) else {},"dev_dependencies":raw.get("devDependencies",{}) if isinstance(raw,dict) else {}}
    if lower.endswith("requirements.txt"):
        return {"format":"requirements.txt","dependencies":[re.split(r"\s+#",line.strip(),maxsplit=1)[0].strip() for line in data.splitlines() if line.strip() and not line.lstrip().startswith(("#","-"))]}
    if lower=="go.mod":
        deps=[]
        block=False
        for line in data.splitlines():
            stripped=line.strip()
            if stripped.startswith("require ("):
                block=True
                continue
            if block and stripped==")":
                block=False
                continue
            if block and stripped and not stripped.startswith("//"):
                deps.append(stripped)
            elif stripped.startswith("require "): deps.append(stripped.removeprefix("require ").strip())
        return {"format":"go.mod","dependencies":deps}
    return {"format":Path(name).name,"sha256":hashlib.sha256(data.encode()).hexdigest(),"parsed":False}
