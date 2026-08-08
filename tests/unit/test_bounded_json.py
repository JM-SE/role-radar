"""Hostile JSON is rejected before provider mapping."""

import json

import pytest

from role_radar.collectors.bounded_json import BoundedJsonError, loads_bounded


def test_json_rejects_duplicate_nonfinite_and_trailing_data() -> None:
    for payload in (b'{"a": 1, "a": 2}', b"NaN", b"{} garbage"):
        with pytest.raises(BoundedJsonError):
            loads_bounded(payload)


def test_json_rejects_invalid_utf8_and_nested_duplicate() -> None:
    with pytest.raises(BoundedJsonError):
        loads_bounded(b"\xff")
    with pytest.raises(BoundedJsonError):
        loads_bounded(b'{"outer": [{"x": 1, "x": 2}]}')


def test_json_depth_and_nodes_are_exact_caps() -> None:
    value: object = 0
    for _ in range(32):
        value = [value]
    loads_bounded(json.dumps(value).encode(), max_depth=32)
    with pytest.raises(BoundedJsonError):
        loads_bounded(json.dumps([value]).encode(), max_depth=32)

    exact = {str(index): index for index in range(49_999)}
    loads_bounded(json.dumps(exact).encode(), max_nodes=100_000)
    too_many = {str(index): index for index in range(50_000)}
    with pytest.raises(BoundedJsonError):
        loads_bounded(json.dumps(too_many).encode(), max_nodes=100_000)
