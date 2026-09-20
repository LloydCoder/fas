from fas.identity import stable_id, stable_ulid_suffix
from fas.adapters.util import stable_observation_id
from fas.collectors.base import CollectionContext
from pathlib import Path

def test_stable_ulid_is_26_chars_and_deterministic():
    values=[stable_ulid_suffix(f"material-{i}") for i in range(1000)]
    assert all(len(v)==26 for v in values)
    assert len(set(values))==1000
    assert stable_ulid_suffix("same") == stable_ulid_suffix("same")

def test_stable_ids_are_not_prefix_only_collisions():
    ids={stable_id("artifact", f"material-{i}") for i in range(10000)}
    assert len(ids)==10000

def test_observation_ids_scope_analysis_and_snapshot():
    base=CollectionContext("analysis_01J00000000000000000000000","snapshot_01J00000000000000000000000",Path.cwd(),"repo")
    a=stable_observation_id(base,"tool-output")
    b=stable_observation_id(base,"tool-output")
    c=stable_observation_id(base.__class__("analysis_01J00000000000000000000001",base.snapshot_id,base.root,base.repository),"tool-output")
    assert a==b
    assert a!=c
