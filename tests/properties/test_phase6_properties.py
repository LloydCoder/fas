from hypothesis import given, strategies as st

from fas.collectors.base import CollectionContext
from fas.collectors.raw import stable_run_id


@given(st.text(min_size=0, max_size=128))
def test_stable_tool_run_identity_is_reproducible(tool_name: str) -> None:
    context = CollectionContext(
        analysis_id="analysis_01J00000000000000000000000",
        snapshot_id="snapshot_01J00000000000000000000000",
        root=__import__("pathlib").Path.cwd(),
        repository="fixture",
        revision="abc123",
    )
    first = stable_run_id(context, tool_name)
    second = stable_run_id(context, tool_name)
    assert first == second
    assert first.startswith("toolrun_")
    assert len(first) == len("toolrun_") + 26
