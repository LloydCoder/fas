from pathlib import Path
import pytest
from fas.collectors import PathPolicy,CollectionContext,CollectionPlan,CollectorSpec,plan_hash,manifest,replay_compatible
from fas.domain.common import new_id
def test_path_policy_blocks_traversal(tmp_path):
    policy=PathPolicy(tmp_path)
    with pytest.raises(ValueError): policy.validate_relative("../secret")
    assert policy.resolve("ok.txt").is_relative_to(tmp_path.resolve())
def test_replay_manifest_is_deterministic(tmp_path):
    c=CollectionContext(new_id("analysis"),new_id("snapshot"),tmp_path,"repo","rev")
    class C:
        name="fixture"
        def collect(self,context):
            from fas.collectors import CollectionBatch
            return CollectionBatch()
    p=CollectionPlan(c,(C(),),(CollectorSpec("fixture"),))
    assert plan_hash(p)==plan_hash(p)
    assert replay_compatible(c,manifest(p))
