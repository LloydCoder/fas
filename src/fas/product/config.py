"""Single-source runtime configuration with explicit precedence and secret-safe diagnostics."""
from __future__ import annotations
import json, os
from dataclasses import dataclass, fields
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

    @classmethod
    def from_sources(cls, *, path: Path | None = None, cli: dict[str, object] | None = None) -> "Settings":
        values: dict[str, object] = {}
        if path and path.exists():
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("configuration file must contain a JSON object")
            values.update(raw)
        prefix = "FAS_"
        for f in fields(cls):
            env = os.getenv(prefix + f.name.upper())
            if env is not None:
                values[f.name] = _coerce(env, f.type)
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
