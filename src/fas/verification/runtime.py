"""Safe security-test execution boundary.

This module intentionally has no shell/process execution backend. Core Phase 5 CI uses a
deterministic executor over registered fixture results. A future runtime backend must implement
the protocol under an explicit sandbox policy rather than accepting arbitrary commands.
"""
from __future__ import annotations
from typing import Protocol
from fas.domain.verification import SecurityTestDefinition, SecurityTestResult
from datetime import datetime, timezone


class SecurityTestExecutor(Protocol):
    name: str
    version: str
    def execute(self, definition: SecurityTestDefinition) -> SecurityTestResult: ...


class DeterministicSecurityTestExecutor:
    name="fixture-executor"
    version="1.0"
    def __init__(self, outcomes: dict[str, bool] | None = None):
        self._outcomes=dict(outcomes or {})
    def execute(self, definition: SecurityTestDefinition) -> SecurityTestResult:
        passed=self._outcomes.get(definition.test_id, False)
        now=datetime.now(timezone.utc)
        actual=definition.expected_result if passed else "UNEXPECTED_RESULT"
        return SecurityTestResult(
            test_id=definition.test_id,
            test_version=definition.version,
            snapshot_id=definition.snapshot_id,
            executor=self.name,
            executor_version=self.version,
            expected_result=definition.expected_result,
            actual_result=actual,
            passed=passed,
            exit_code=0 if passed else 1,
            input_digest=definition.input_digest,
            started_at=now,
            completed_at=now,
            environment={"network":"DENY_ALL","filesystem":definition.filesystem_policy,"secrets":"DENY_ALL"},
        )
