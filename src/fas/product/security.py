"""Execution policy primitives. Repository code is never executed by the product API."""
from __future__ import annotations
from dataclasses import dataclass
from enum import StrEnum

class SandboxPolicy(StrEnum):
    NO_EXECUTION="NO_EXECUTION"
    STATIC_ONLY="STATIC_ONLY"
    SANDBOXED_TEST="SANDBOXED_TEST"
    SANDBOXED_RUNTIME="SANDBOXED_RUNTIME"
    CONTROLLED_NETWORK="CONTROLLED_NETWORK"

@dataclass(frozen=True, slots=True)
class ExecutionLimits:
    timeout_seconds:int=120
    stdout_bytes:int=2_000_000
    stderr_bytes:int=2_000_000
    network:str="DENY_ALL"
    secrets:str="DENY_ALL"
    non_root:bool=True

def validate_argv(argv: list[str]) -> tuple[str,...]:
    if not argv or any("\x00" in x for x in argv): raise ValueError("invalid argv")
    return tuple(argv)

def safe_environment(allow: dict[str,str]|None=None) -> dict[str,str]:
    allowed=allow or {}
    return {k:v for k,v in allowed.items() if k not in {"PATH","HOME","USER","SHELL","SSH_AUTH_SOCK","AWS_SECRET_ACCESS_KEY","AWS_ACCESS_KEY_ID"}}
