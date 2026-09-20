from pathlib import Path

import pytest

from fas.collectors.executor import ExecutionPolicy, SecureExecutor


def test_empty_executable_allowlist_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    executor = SecureExecutor(ExecutionPolicy())
    monkeypatch.setattr("fas.collectors.executor.shutil.which", lambda name: "/usr/bin/true")
    with pytest.raises(PermissionError, match="no executable"):
        executor.run(("true",), cwd=tmp_path)


def test_sandbox_mode_fails_closed_when_backend_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    policy = ExecutionPolicy(
        allowed_executables=frozenset({"/usr/bin/true"}),
        isolation_mode="SANDBOXED_TEST",
        network_policy="DENY_ALL",
    )
    executor = SecureExecutor(policy)
    monkeypatch.setattr("fas.collectors.executor.shutil.which", lambda name: None if name == "bwrap" else "/usr/bin/true")
    with pytest.raises(PermissionError, match="sandbox backend"):
        executor.run(("true",), cwd=tmp_path)


def test_non_root_policy_is_explicit():
    policy = ExecutionPolicy(allowed_executables=frozenset({"/usr/bin/true"}))
    assert policy.require_non_root is True


def test_executable_hash_mismatch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    target = tmp_path / "tool"
    target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    target.chmod(0o700)
    policy = ExecutionPolicy(
        allowed_executables=frozenset({str(target)}),
        executable_hashes=((str(target), "0" * 64),),
    )
    executor = SecureExecutor(policy)
    with pytest.raises(PermissionError, match="content changed"):
        executor.run((str(target),), cwd=tmp_path)
