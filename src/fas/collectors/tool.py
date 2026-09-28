"""External security-tool collector with evidence-preserving execution metadata."""
from __future__ import annotations

import dataclasses
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from fas.domain.analysis import Artifact
from fas.domain.common import (
    ArtifactType,
    ContentHash,
    Provenance,
    ProvenanceCategory,
    ProvenanceLevel,
)

from .base import CollectionBatch
from .executor import SecureExecutor
from .raw import (
    ToolRun,
    environment_fingerprint,
    raw_artifact_from_bytes,
    stable_run_id,
)


class ToolCollector:
    def __init__(
        self,
        tool_name: str,
        argv: tuple[str, ...],
        adapter,
        executor: SecureExecutor,
        raw_dir: Path,
        *,
        tool_version: str | None = None,
    ):
        if not argv:
            raise ValueError("argv is required")
        if Path(argv[0]).name != tool_name:
            raise ValueError("argv executable must match tool_name")
        self.name = f"tool:{tool_name}"
        self.tool_name = tool_name
        self.argv = argv
        self.adapter = adapter
        self.executor = executor
        self.raw_dir = raw_dir
        self.tool_version = tool_version

    def _configuration_hash(self, argv: tuple[str, ...]) -> str:
        material = {
            "tool": self.tool_name,
            "argv": argv,
            "policy": dataclasses.asdict(self.executor.policy),
        }
        canonical = json.dumps(material, sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def collect(self, context):
        started = datetime.now(timezone.utc)
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        target_arg = (
            "/target"
            if self.executor.policy.isolation_mode != "STATIC_ONLY"
            else context.root.as_posix()
        )
        argv = tuple(target_arg if item == "{target}" else item for item in self.argv)
        configuration_hash = self._configuration_hash(argv)
        run_id = stable_run_id(
            context,
            self.tool_name,
            argv=argv,
            configuration_hash=configuration_hash,
        )
        try:
            result = self.executor.run(
                argv, cwd=self.raw_dir, cancel=getattr(context, "cancel", None)
            )
        except FileNotFoundError:
            return CollectionBatch(
                complete=False, warnings=(f"{self.name}: TOOL_UNAVAILABLE",)
            )
        except PermissionError as exc:
            return CollectionBatch(
                complete=False,
                warnings=(
                    f"{self.name}: EXECUTION_POLICY_DENIED: {type(exc).__name__}",
                ),
            )

        stdout_hash = hashlib.sha256(result.stdout).hexdigest()
        stderr_hash = hashlib.sha256(result.stderr).hexdigest()
        stdout_name = f"{run_id}-{self.tool_name}.stdout"
        stderr_name = f"{run_id}-{self.tool_name}.stderr"
        stdout_path = self.raw_dir / stdout_name
        stderr_path = self.raw_dir / stderr_name
        stdout_path.write_bytes(result.stdout)
        stderr_path.write_bytes(result.stderr)

        stdout_artifact_id = (
            "artifact_"
            + hashlib.sha256(
                f"{context.analysis_id}|{context.snapshot_id}|{self.tool_name}|stdout|"
                f"{stdout_hash}|{configuration_hash}".encode()
            ).hexdigest()[:26]
        )
        stderr_artifact_id = (
            "artifact_"
            + hashlib.sha256(
                f"{context.analysis_id}|{context.snapshot_id}|{self.tool_name}|stderr|"
                f"{stderr_hash}|{configuration_hash}".encode()
            ).hexdigest()[:26]
        )
        prov = Provenance(
            category=ProvenanceCategory.TOOL_OBSERVATION,
            level=ProvenanceLevel.T2,
            collector=self.tool_name,
            method="secure_subprocess",
            source="stdout",
            observed_at=started,
            tool_execution_ref=run_id,
        )
        stdout_artifact = Artifact(
            id=stdout_artifact_id,
            analysis_id=context.analysis_id,
            type=ArtifactType.TOOL_OUTPUT,
            name=stdout_name,
            media_type="application/json",
            size_bytes=len(result.stdout),
            content_hash=ContentHash(digest=stdout_hash),
            snapshot_id=context.snapshot_id,
            provenance=(prov,),
            external_reference=str(stdout_path),
            metadata={
                "tool": self.tool_name,
                "stream": "stdout",
                "exit_code": str(result.returncode),
                "output_limited": str(result.output_limited).lower(),
                "configuration_hash": configuration_hash,
            },
        )
        stderr_artifact = Artifact(
            id=stderr_artifact_id,
            analysis_id=context.analysis_id,
            type=ArtifactType.TOOL_OUTPUT,
            name=stderr_name,
            media_type="text/plain",
            size_bytes=len(result.stderr),
            content_hash=ContentHash(digest=stderr_hash),
            snapshot_id=context.snapshot_id,
            provenance=(
                Provenance(
                    category=ProvenanceCategory.TOOL_OBSERVATION,
                    level=ProvenanceLevel.T2,
                    collector=self.tool_name,
                    method="secure_subprocess",
                    source="stderr",
                    observed_at=started,
                    tool_execution_ref=run_id,
                ),
            ),
            external_reference=str(stderr_path),
            metadata={
                "tool": self.tool_name,
                "stream": "stderr",
                "exit_code": str(result.returncode),
                "output_limited": str(result.output_limited).lower(),
                "configuration_hash": configuration_hash,
            },
        )

        if result.cancelled:
            status = "CANCELLED"
        elif result.timed_out:
            status = "TIMED_OUT"
        elif result.output_limited:
            status = "OUTPUT_LIMITED"
        elif result.returncode is None:
            status = "FAILED"
        elif result.returncode not in (0, 1):
            status = "FAILED"
        elif not result.stdout and not result.stderr and result.returncode == 0:
            status = "NO_FINDINGS"
        else:
            status = "SUCCESS"

        run = ToolRun(
            run_id,
            context.analysis_id,
            context.snapshot_id,
            self.tool_name,
            self.tool_version,
            argv,
            str(self.raw_dir),
            environment_fingerprint(),
            started.isoformat(),
            datetime.now(timezone.utc).isoformat(),
            result.returncode,
            status,
            "sha256:" + stdout_hash,
            "sha256:" + stderr_hash,
            stdout_artifact_id,
            configuration_hash,
            repository_revision=context.revision,
        )
        stdout_raw = raw_artifact_from_bytes(
            stdout_artifact_id,
            result.stdout,
            "application/json",
            str(stdout_path),
        )
        stderr_raw = raw_artifact_from_bytes(
            stderr_artifact_id,
            result.stderr,
            "text/plain",
            str(stderr_path),
        )
        artifacts = (stdout_artifact, stderr_artifact)
        raw_artifacts = (stdout_raw, stderr_raw)

        if status not in {"SUCCESS", "OUTPUT_LIMITED"}:
            return CollectionBatch(
                artifacts=artifacts,
                complete=False,
                warnings=(f"{self.name}: {status}",),
                raw_artifacts=raw_artifacts,
                tool_runs=(run,),
            )
        try:
            observations = self.adapter.parse(
                result.stdout,
                context,
                raw_artifact_id=stdout_artifact_id,
                source_artifact_id=stdout_artifact_id,
            )
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            run = ToolRun(
                run.run_id,
                run.analysis_id,
                run.snapshot_id,
                run.tool_name,
                run.tool_version,
                run.argv,
                run.cwd,
                run.environment_fingerprint,
                run.started_at,
                run.completed_at,
                run.exit_code,
                "PARSE_FAILED",
                run.stdout_hash,
                run.stderr_hash,
                run.raw_artifact_id,
                run.configuration_hash,
                run.repository_revision,
            )
            return CollectionBatch(
                artifacts=artifacts,
                complete=False,
                warnings=(f"{self.name}: PARSE_FAILED: {type(exc).__name__}",),
                raw_artifacts=raw_artifacts,
                tool_runs=(run,),
            )
        final_status = (
            "OUTPUT_LIMITED"
            if result.output_limited
            else ("NO_FINDINGS" if not observations else "FINDINGS")
        )
        run = ToolRun(
            run.run_id,
            run.analysis_id,
            run.snapshot_id,
            run.tool_name,
            run.tool_version,
            run.argv,
            run.cwd,
            run.environment_fingerprint,
            run.started_at,
            run.completed_at,
            run.exit_code,
            final_status,
            run.stdout_hash,
            run.stderr_hash,
            run.raw_artifact_id,
            run.configuration_hash,
            run.repository_revision,
        )
        return CollectionBatch(
            artifacts=artifacts,
            observations=observations,
            complete=not result.output_limited,
            warnings=("tool output was truncated",) if result.output_limited else (),
            raw_artifacts=raw_artifacts,
            tool_runs=(run,),
        )


class UnavailableToolCollector:
    def __init__(self, tool_name: str, reason: str):
        self.name = f"tool:{tool_name}"
        self.reason = reason

    def collect(self, context):
        return CollectionBatch(
            complete=False,
            warnings=(f"{self.name}: TOOL_UNAVAILABLE: {self.reason}",),
        )
