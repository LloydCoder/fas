"""Security boundary for external analysis processes.

The executor treats tool output as hostile and avoids pipe buffering by spooling
stdout/stderr to private temporary files. It also resolves allowlisted tools to
canonical executable paths and polls for timeout/cancellation so a worker is
not blocked in an unbounded communicate() call.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from threading import Event


class CancellationToken:
    def __init__(self) -> None:
        self._event = Event()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def cancel(self) -> None:
        self._event.set()


@dataclass(frozen=True, slots=True)
class ExecutionPolicy:
    allowed_executables: frozenset[str] = frozenset()
    timeout_seconds: float = 120.0
    max_output_bytes: int = 4 * 1024 * 1024
    max_stderr_bytes: int = 4 * 1024 * 1024
    max_combined_output_bytes: int = 8 * 1024 * 1024
    max_args: int = 128
    clean_environment: bool = True
    allowed_environment: frozenset[str] = frozenset()
    require_non_root: bool = True

    def __post_init__(self) -> None:
        if (
            self.timeout_seconds <= 0
            or self.max_output_bytes < 1
            or self.max_stderr_bytes < 1
            or self.max_combined_output_bytes < 1
            or self.max_args < 1
        ):
            raise ValueError("invalid execution policy")
        if self.max_combined_output_bytes < min(self.max_output_bytes, self.max_stderr_bytes):
            raise ValueError("combined output limit is too small")


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    argv: tuple[str, ...]
    returncode: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    cancelled: bool = False
    output_limited: bool = False


class SecureExecutor:
    def __init__(self, policy: ExecutionPolicy) -> None:
        self.policy = policy

    def _resolve_executable(self, value: str) -> str:
        if not value or value in {".", ".."} or "\x00" in value:
            raise ValueError("invalid executable")
        candidate = Path(value)
        if candidate.is_absolute():
            resolved = candidate.resolve(strict=True)
        else:
            if len(candidate.parts) != 1 or candidate.name != value:
                raise PermissionError("executable path must be a bare approved tool name")
            resolved_path = shutil.which(value)
            if not resolved_path:
                raise FileNotFoundError(value)
            resolved = Path(resolved_path).resolve(strict=True)
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            raise PermissionError("approved executable is not executable")
        if self.policy.allowed_executables:
            approved = set()
            for item in self.policy.allowed_executables:
                if Path(item).is_absolute():
                    approved.add(str(Path(item).resolve(strict=True)))
                else:
                    resolved_item = shutil.which(item)
                    if resolved_item:
                        approved.add(str(Path(resolved_item).resolve(strict=True)))
            if str(resolved) not in approved:
                raise PermissionError("executable is not allowlisted")
        return str(resolved)

    def _environment(self, env: Mapping[str, str] | None) -> dict[str, str]:
        if not self.policy.clean_environment:
            raise PermissionError("ambient environment inheritance is disabled by policy")
        source = env or {}
        if any(key not in self.policy.allowed_environment for key in source):
            denied = sorted(key for key in source if key not in self.policy.allowed_environment)
            raise PermissionError(f"environment variable is not allowlisted: {denied[0]}")
        child = {"PATH": "/usr/bin:/bin"}
        child.update({str(key): str(value) for key, value in source.items()})
        return child

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str] | None = None,
        cancel: CancellationToken | None = None,
    ) -> ExecutionResult:
        args = tuple(str(x) for x in argv)
        if not args or len(args) > self.policy.max_args:
            raise ValueError("invalid argv")
        if any("\x00" in x for x in args):
            raise ValueError("NUL in argv")
        root = Path(cwd).resolve()
        if not root.is_dir():
            raise ValueError("cwd must be a directory")
        if self.policy.require_non_root and hasattr(os, "geteuid") and os.geteuid() == 0:
            raise PermissionError("analysis tools must not execute as root")
        executable = self._resolve_executable(args[0])
        safe_args = (executable, *args[1:])
        child_env = self._environment(env)

        with tempfile.TemporaryFile(mode="w+b") as stdout_file, tempfile.TemporaryFile(mode="w+b") as stderr_file:
            process = subprocess.Popen(
                safe_args,
                cwd=root,
                env=child_env,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                start_new_session=True,
                close_fds=True,
                shell=False,
            )
            deadline = time.monotonic() + self.policy.timeout_seconds
            while process.poll() is None:
                if cancel is not None and cancel.cancelled:
                    self._terminate(process)
                    return ExecutionResult(safe_args, process.returncode, b"", b"", cancelled=True)
                if time.monotonic() >= deadline:
                    self._terminate(process)
                    return ExecutionResult(safe_args, process.returncode, b"", b"", timed_out=True)
                time.sleep(0.02)
            stdout_file.seek(0)
            stdout = stdout_file.read(self.policy.max_output_bytes)
            stdout_file.seek(0, os.SEEK_END)
            stdout_total = stdout_file.tell()
            stderr_budget = min(self.policy.max_stderr_bytes, max(0, self.policy.max_combined_output_bytes - len(stdout)))
            stderr_file.seek(0)
            stderr = stderr_file.read(stderr_budget)
            stderr_file.seek(0, os.SEEK_END)
            stderr_total = stderr_file.tell()
            output_limited = (stdout_total > self.policy.max_output_bytes or stderr_total > self.policy.max_stderr_bytes or stdout_total + stderr_total > self.policy.max_combined_output_bytes)
            return ExecutionResult(
                safe_args,
                process.returncode,
                stdout,
                stderr,
                output_limited=output_limited,
            )

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
