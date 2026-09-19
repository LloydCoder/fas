"""Security boundary for external analysis processes."""
from __future__ import annotations
import os,signal,subprocess
from dataclasses import dataclass
from pathlib import Path
from threading import Event
from typing import Mapping, Sequence

class CancellationToken:
    def __init__(self): self._event=Event()
    @property
    def cancelled(self)->bool: return self._event.is_set()
    def cancel(self)->None: self._event.set()

@dataclass(frozen=True,slots=True)
class ExecutionPolicy:
    allowed_executables:frozenset[str]=frozenset()
    timeout_seconds:float=120.0
    max_output_bytes:int=4*1024*1024
    max_stderr_bytes:int=4*1024*1024
    max_args:int=128
    clean_environment:bool=True
    def __post_init__(self):
        if self.timeout_seconds<=0 or self.max_output_bytes<1 or self.max_stderr_bytes<1 or self.max_args<1: raise ValueError("invalid execution policy")

@dataclass(frozen=True,slots=True)
class ExecutionResult:
    argv:tuple[str,...]
    returncode:int|None
    stdout:bytes
    stderr:bytes
    timed_out:bool=False
    cancelled:bool=False
    output_limited:bool=False

class SecureExecutor:
    def __init__(self,policy:ExecutionPolicy): self.policy=policy
    def run(self,argv:Sequence[str],*,cwd:Path,env:Mapping[str,str]|None=None,cancel:CancellationToken|None=None)->ExecutionResult:
        args=tuple(str(x) for x in argv)
        if not args or len(args)>self.policy.max_args: raise ValueError("invalid argv")
        if any("\x00" in x for x in args): raise ValueError("NUL in argv")
        executable=Path(args[0]).name
        if self.policy.allowed_executables and executable not in self.policy.allowed_executables and args[0] not in self.policy.allowed_executables: raise PermissionError("executable is not allowlisted")
        root=Path(cwd).resolve()
        if not root.is_dir(): raise ValueError("cwd must be a directory")
        if any(x in {".."} for x in Path(args[0]).parts): raise ValueError("unsafe executable path")
        child_env={"PATH":"/usr/bin:/bin"} if self.policy.clean_environment else dict(os.environ)
        if env:
            for key,value in env.items():
                if key.upper() in {"LD_PRELOAD","LD_LIBRARY_PATH","PYTHONPATH","PYTHONINSPECT"}: continue
                child_env[str(key)]=str(value)
        process=subprocess.Popen(args,cwd=root,env=child_env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        try:
            stdout,stderr=process.communicate(timeout=self.policy.timeout_seconds)
        except subprocess.TimeoutExpired:
            self._terminate(process); return ExecutionResult(args,None,b"",b"",timed_out=True)
        if cancel and cancel.cancelled:
            self._terminate(process); return ExecutionResult(args,None,b"",b"",cancelled=True)
        limited=len(stdout)>self.policy.max_output_bytes or len(stderr)>self.policy.max_stderr_bytes
        return ExecutionResult(args,process.returncode,stdout[:self.policy.max_output_bytes],stderr[:self.policy.max_stderr_bytes],output_limited=limited)
    @staticmethod
    def _terminate(process):
        try: os.killpg(process.pid,signal.SIGTERM)
        except ProcessLookupError: return
        try: process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try: os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError: pass
