from pathlib import Path
import sys
import pytest
from fas.collectors import CollectionContext,CollectionPlan,CollectionOrchestrator,CollectorSpec,ExecutionPolicy,SecureExecutor,ParseLimitError,safe_json_loads
from fas.collectors.executor import CancellationToken
from fas.collectors.raw import ToolRun
from fas.domain.common import new_id

def ctx(tmp_path:Path):
    return CollectionContext(analysis_id=new_id("analysis"),snapshot_id=new_id("snapshot"),root=tmp_path,repository="fixture",revision="deadbeef")

def test_safe_json_limits():
    assert safe_json_loads('{"a":[1,2]}')["a"]==[1,2]
    with pytest.raises(ParseLimitError):
        safe_json_loads('{"a":{"b":{"c":1}}}', limits=__import__("fas.collectors",fromlist=["ParseLimits"]).ParseLimits(max_depth=2))

def test_secure_executor_argv_only_and_output_bound(tmp_path):
    policy=ExecutionPolicy(allowed_executables=frozenset({Path(sys.executable).name}),max_output_bytes=8,max_stderr_bytes=8)
    result=SecureExecutor(policy).run([sys.executable,"-c","print('0123456789abcdef')"],cwd=tmp_path)
    assert result.returncode==0
    assert result.output_limited
    assert len(result.stdout)<=8

def test_secure_executor_rejects_unallowlisted(tmp_path):
    with pytest.raises(PermissionError):
        SecureExecutor(ExecutionPolicy(allowed_executables=frozenset({"definitely-not-python"}))).run([sys.executable,"-c","print(1)"],cwd=tmp_path)

def test_toolrun_is_canonical_and_slots_safe():
    run=ToolRun("toolrun_x","analysis_x","snapshot_x","fake",None,("fake",)," /tmp","sha256:x","2026-01-01T00:00:00Z",None,0,"SUCCESS",None,None)
    assert '"tool_name":"fake"' in run.canonical_json()

def test_orchestrator_produces_explicit_summary(tmp_path):
    class Empty:
        name="empty"
        def collect(self,context):
            from fas.collectors import CollectionBatch
            return CollectionBatch()
    c=ctx(tmp_path)
    result=CollectionOrchestrator().run(CollectionPlan(c,(Empty(),),(CollectorSpec("empty"),)))
    assert result.summary.status.value=="SUCCESS"
    assert result.replayable
