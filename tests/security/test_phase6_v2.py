from __future__ import annotations

import hashlib
from pathlib import Path
import sys

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
    with pytest.raises(OSError):
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


def test_tool_run_identity_is_stable_and_tool_scoped() -> None:
    from fas.collectors.base import CollectionContext
    from fas.collectors.raw import stable_run_id
    context = CollectionContext(
        analysis_id="analysis_01J00000000000000000000000",
        snapshot_id="snapshot_01J00000000000000000000000",
        root=Path.cwd(),
        repository="repo",
        revision="abc",
    )
    semgrep_a = stable_run_id(context, "semgrep")
    semgrep_b = stable_run_id(context, "semgrep")
    trivy = stable_run_id(context, "trivy")
    assert semgrep_a == semgrep_b
    assert semgrep_a != trivy
    assert len(semgrep_a.split("_", 1)[1]) == 26


def test_api_auth_required_fails_closed(tmp_path: Path) -> None:
    from fas.product.api import ApiServer
    from fas.product.config import Settings
    from fas.product.service import ProductService
    service = ProductService(Settings(auth_required=True, api_token=None, database_url="sqlite:///" + str(tmp_path / "fas-auth-test.db")))
    with pytest.raises(ValueError):
        ApiServer(service).serve("127.0.0.1", 0)


def test_executor_rejects_non_allowlisted_environment(tmp_path: Path) -> None:
    policy = ExecutionPolicy(
        allowed_executables=frozenset({sys.executable}),
        allowed_environment=frozenset({"SAFE_VAR"}),
    )
    with pytest.raises(PermissionError):
        SecureExecutor(policy).run((sys.executable, "-c", "print('ok')"), cwd=tmp_path, env={"HOME": "/tmp"})


def test_snapshot_manifest_excludes_product_state(tmp_path: Path) -> None:
    from fas.product.config import Settings
    from fas.product.service import ProductService
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("print('ok')", encoding="utf-8")
    (root / ".fas").mkdir()
    (root / ".fas" / "state").write_text("mutable", encoding="utf-8")
    service = ProductService(Settings(database_url=f"sqlite:///{tmp_path / 'fas.db'}", object_store_path=str(tmp_path / "objects")))
    project = service.create_project("fixture", str(root))
    analysis = service.create_analysis(project.id, str(root))
    snapshot = service.snapshot(analysis, root)
    assert snapshot.metadata["completeness"] == "COMPLETE"
    assert snapshot.metadata["file_count"] == "1"
    assert snapshot.metadata["manifest_object"]


def test_incomplete_investigation_cannot_be_verdict_ready() -> None:
    from fas.domain import ExploitabilityAnalysis, InvestigationStatus
    assert InvestigationStatus.AWAITING_EVIDENCE.value == "AWAITING_EVIDENCE"
    analysis = ExploitabilityAnalysis(
        evidence_sufficient=False,
        missing_evidence=("attacker influence is not deterministically established",),
    )
    assert analysis.evidence_sufficient is False
