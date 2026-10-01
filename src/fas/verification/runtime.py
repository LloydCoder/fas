"""Controlled runtime verification adapter."""
from __future__ import annotations
import hashlib, shlex
from pathlib import Path
from datetime import datetime, timezone
from fas.collectors.executor import ExecutionPolicy, SecureExecutor
from fas.domain.verification import SecurityTestDefinition, SecurityTestResult

class SandboxedSecurityTestExecutor:
    name="sandboxed-runtime"
    version="1.0"
    def __init__(self,root:Path,allowed_executables:frozenset[str])->None:
        self.root=Path(root).resolve()
        if not self.root.is_dir(): raise ValueError("runtime root must be a directory")
        self.executor=SecureExecutor(ExecutionPolicy(
            allowed_executables=allowed_executables,isolation_mode="SANDBOXED_RUNTIME",
            network_policy="DENY_ALL",require_non_root=True))
    def execute(self,definition:SecurityTestDefinition)->SecurityTestResult:
        if definition.network_policy!="DENY_ALL" or definition.secret_policy!="DENY_ALL":
            raise PermissionError("runtime policy is broader than the controlled executor")
        command=shlex.split(definition.target,posix=True)
        if not command or any("\x00" in item for item in command): raise ValueError("invalid security test target")
        started=datetime.now(timezone.utc)
        result=self.executor.run(command,cwd=self.root)
        completed=datetime.now(timezone.utc)
        output_digest=hashlib.sha256(result.stdout+result.stderr).hexdigest()
        if result.timed_out: actual="TIMEOUT"
        elif result.cancelled: actual="CANCELLED"
        elif result.output_limited: actual="OUTPUT_LIMIT"
        else: actual=f"exit_code:{result.returncode}"
        return SecurityTestResult(
            test_id=definition.test_id,test_version=definition.version,snapshot_id=definition.snapshot_id,
            executor=self.name,executor_version=self.version,expected_result=definition.expected_result,
            actual_result=actual,passed=actual==definition.expected_result,exit_code=result.returncode,
            input_digest=definition.input_digest,started_at=started,completed_at=completed,
            output_digest=output_digest,
            environment={"network":"DENY_ALL","filesystem":definition.filesystem_policy,"secrets":"DENY_ALL","sandbox":"controlled"},
        )
