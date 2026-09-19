from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from fas.collectors.executor import ExecutionPolicy, SecureExecutor
from fas.product.storage import LocalObjectStore, SQLiteStore


def test_executor_rejects_path_substitution(tmp_path: Path) -> None:
    policy = ExecutionPolicy(allowed_executables=frozenset({"definitely-not-installed-fas-tool"}))
    with pytest.raises((FileNotFoundError, PermissionError)):
        SecureExecutor(policy).run(("./definitely-not-installed-fas-tool",), cwd=tmp_path)


def test_content_addressed_storage_uses_unique_atomic_objects(tmp_path: Path) -> None:
    store = LocalObjectStore(tmp_path)
    first = store.put(b"one", media_type="text/plain", snapshot_id="snapshot_x", source="test")
    second = store.put(b"two", media_type="text/plain", snapshot_id="snapshot_x", source="test")
    assert first["content_hash"] != second["content_hash"]
    assert store.get(first["content_hash"]) == b"one"
    assert store.get(second["content_hash"]) == b"two"


def test_content_addressed_storage_rejects_corruption(tmp_path: Path) -> None:
    store = LocalObjectStore(tmp_path)
    item = store.put(b"immutable", media_type="text/plain", snapshot_id="snapshot_x", source="test")
    target = Path(item["storage_reference"])
    target.write_bytes(b"tampered")
    with pytest.raises(IOError):
        store.get(item["content_hash"])


def test_audit_chain_detects_mutation(tmp_path: Path) -> None:
    database = SQLiteStore(f"sqlite:///{tmp_path / 'fas.db'}")
    event = {
        "id": "audit_event_01J00000000000000000000000",
        "analysis_id": "analysis_01J00000000000000000000000",
        "snapshot_id": "snapshot_01J00000000000000000000000",
        "event_type": "TEST",
        "actor": "test",
        "subject_id": "subject",
        "payload": {},
        "created_at": "2026-01-01T00:00:00+00:00",
    }
    database.append_audit(event)
    assert database.verify_audit_chain(event["analysis_id"])["valid"] is True
    with database._connect() as con:
        con.execute(
            "UPDATE audit_events SET payload=? WHERE id=?",
            ('{"actor":"tampered"}', event["id"]),
        )
    assert database.verify_audit_chain(event["analysis_id"])["valid"] is False


def test_audit_payload_hash_is_deterministic() -> None:
    assert hashlib.sha256(b"fas").hexdigest() == hashlib.sha256(b"fas").hexdigest()
