"""Single-source runtime configuration with explicit precedence and secret-safe diagnostics."""
from __future__ import annotations
import json
import os
from dataclasses import dataclass, fields
from typing import get_type_hints
from pathlib import Path

@dataclass(frozen=True, slots=True)
class Settings:
    database_url: str = "sqlite:///./.fas/fas.db"
    object_store_path: str = ".fas/objects"
    api_host: str = "127.0.0.1"
    api_port: int = 8765
    api_token: str | None = None
    auth_required: bool = False
    max_workers: int = 2
    analysis_timeout_seconds: int = 900
    subprocess_timeout_seconds: int = 120
    max_stdout_bytes: int = 2_000_000
    max_stderr_bytes: int = 2_000_000
    max_artifact_bytes: int = 50_000_000
    max_graph_nodes: int = 200_000
    max_graph_edges: int = 500_000
    log_level: str = "INFO"
    network_policy: str = "DENY_ALL"
    retention_days: int = 90

    def __post_init__(self) -> None:
        positive = {
            "api_port": self.api_port,
            "max_workers": self.max_workers,
            "analysis_timeout_seconds": self.analysis_timeout_seconds,
            "subprocess_timeout_seconds": self.subprocess_timeout_seconds,
            "max_stdout_bytes": self.max_stdout_bytes,
            "max_stderr_bytes": self.max_stderr_bytes,
            "max_artifact_bytes": self.max_artifact_bytes,
            "max_graph_nodes": self.max_graph_nodes,
            "max_graph_edges": self.max_graph_edges,
            "retention_days": self.retention_days,
        }
        if any(value <= 0 for value in positive.values()):
            raise ValueError("numeric configuration limits must be positive")
        if self.api_port > 65535:
            raise ValueError("api_port must be <= 65535")
        if self.network_policy not in {"DENY_ALL", "ALLOWLIST"}:
            raise ValueError("network_policy must be DENY_ALL or ALLOWLIST")

    @classmethod
    def from_sources(cls, *, path: Path | None = None, cli: dict[str, object] | None = None) -> "Settings":
        values: dict[str, object] = {}
        types = get_type_hints(cls)
        if path and path.exists():
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("configuration file must contain a JSON object")
            values.update(raw)
        prefix = "FAS_"
        for f in fields(cls):
            env = os.getenv(prefix + f.name.upper())
            if env is not None:
                values[f.name] = _coerce(env, types[f.name])
        values.update(cli or {})
        return cls(**values)

    def redacted(self) -> dict[str, object]:
        out = {f.name: getattr(self, f.name) for f in fields(self)}
        if out["api_token"]:
            out["api_token"] = "***REDACTED***"
        return out

def _coerce(value: str, typ: object) -> object:
    if typ is bool:
        return value.lower() in {"1", "true", "yes", "on"}
    if typ is int:
        return int(value)
    return value

def load_settings(path: str | None = None, cli: dict[str, object] | None = None) -> Settings:
    return Settings.from_sources(path=Path(path) if path else None, cli=cli)
