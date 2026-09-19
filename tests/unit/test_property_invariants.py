from hypothesis import given, strategies as st
from fas.domain.common import ContentHash, SourceLocation, new_id

@given(st.sampled_from(["evidence", "finding", "node", "edge", "snapshot"]))
def test_generated_ids_match_contract(prefix):
    value = new_id(prefix)
    assert value.startswith(prefix + "_")
    assert len(value) == len(prefix) + 27

@given(st.binary(min_size=32, max_size=32))
def test_sha256_hex_digest_shape(data):
    digest = data.hex()
    assert ContentHash(digest=digest).value == "sha256:" + digest

@given(st.integers(min_value=1, max_value=10000), st.integers(min_value=0, max_value=10000))
def test_location_range_is_ordered(start, delta):
    location = SourceLocation(
        artifact_id=new_id("artifact"), path="x.py", line_start=start, line_end=start + delta
    )
    assert location.line_end >= location.line_start
