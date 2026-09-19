from hypothesis import given, strategies as st

from fas.collectors.parsing import ParseLimitError, ParseLimits, safe_json_loads


@given(st.binary(min_size=0, max_size=2048))
def test_arbitrary_bytes_never_escape_parser(data):
    try:
        safe_json_loads(data, ParseLimits(max_bytes=2048, max_depth=16, max_items=1000))
    except (ValueError, ParseLimitError):
        pass


@given(st.lists(st.integers(), max_size=100))
def test_valid_arrays_parse(values):
    import json

    assert safe_json_loads(json.dumps(values)) == values
