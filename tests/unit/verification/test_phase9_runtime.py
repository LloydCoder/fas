from types import SimpleNamespace
from pathlib import Path
from fas.domain.common import new_id
from fas.domain.verification import SecurityTestDefinition
from fas.verification.runtime import SandboxedSecurityTestExecutor

def definition(**updates):
    values=dict(test_id="runtime-1",version="1",snapshot_id=new_id("snapshot"),
        security_property="controlled runtime",target="true",expected_result="exit_code:0",
        network_policy="DENY_ALL",filesystem_policy="FIXTURE_ONLY",secret_policy="DENY_ALL")
    values.update(updates)
    return SecurityTestDefinition(**values)

def test_runtime_executor_maps_controlled_result(tmp_path:Path):
    executor=SandboxedSecurityTestExecutor(tmp_path,frozenset({"/bin/true"}))
    executor.executor=SimpleNamespace(run=lambda command,cwd: SimpleNamespace(
        stdout=b"ok",stderr=b"",returncode=0,timed_out=False,cancelled=False,output_limited=False))
    result=executor.execute(definition())
    assert result.passed
    assert result.actual_result=="exit_code:0"
    assert result.output_digest

def test_runtime_executor_rejects_network_expansion(tmp_path:Path):
    executor=SandboxedSecurityTestExecutor(tmp_path,frozenset({"/bin/true"}))
    try:
        executor.execute(definition(network_policy="LOOPBACK_ONLY"))
    except PermissionError:
        pass
    else:
        raise AssertionError("runtime executor accepted broader network policy")
