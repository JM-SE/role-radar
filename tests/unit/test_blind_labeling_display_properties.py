"""Bounded deterministic property checks for display-v2 totality and limits."""

from __future__ import annotations

import builtins
import os
import socket
import subprocess
import unicodedata
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from role_radar.evaluation.blind_labeling.contracts import PilotItem
from role_radar.evaluation.blind_labeling.display import (
    DisplayError,
    render_evidence,
    render_pilot_item,
)
from role_radar.evaluation.blind_labeling.display_policy import DISPLAY_ERROR_CODES

_SAFE_CHARACTERS = st.characters(
    blacklist_categories=("Cc", "Cs"),
    blacklist_characters="&<>\u061c\u200e\u200f\u2028\u2029",
)
_SAFE_TEXT = st.text(_SAFE_CHARACTERS, min_size=1, max_size=4096).filter(
    lambda value: any(not char.isspace() for char in value)
)
_FORBIDDEN_CONTROLS = st.sampled_from(
    (("\x00", "&#0;"), ("\x1b", "&#27;"), ("\u2028", "&#8232;"), ("\u2029", "&#8233;"))
)
_ARBITRARY_LEAF = st.one_of(
    st.none(),
    st.binary(max_size=256),
    st.integers(),
    st.floats(allow_nan=True, allow_infinity=True),
    st.booleans(),
    st.text(max_size=4096),
    st.sampled_from(("\ud800", "\udfff")),
)
_ARBITRARY_VALUE = st.recursive(
    _ARBITRARY_LEAF,
    lambda children: st.one_of(
        st.lists(children, max_size=8),
        st.lists(children, max_size=8).map(tuple),
        st.sets(_ARBITRARY_LEAF, max_size=8),
        st.dictionaries(st.text(max_size=16), children, max_size=8),
    ),
    max_leaves=32,
)


@settings(max_examples=500, deadline=None, database=None, derandomize=True)
@given(_SAFE_TEXT)
def test_safe_plain_text_is_nfc_and_tab_stable(value: str) -> None:
    original = value
    rendered = render_evidence(value)
    assert rendered == unicodedata.normalize("NFC", value).replace("\t", r"\t")
    assert value == original


@settings(max_examples=500, deadline=None, database=None, derandomize=True)
@given(_FORBIDDEN_CONTROLS, st.integers(min_value=0, max_value=3))
def test_encoded_forbidden_controls_fail_at_their_decode_depth(
    control_pair: tuple[str, str], depth: int
) -> None:
    raw_control, encoded_control = control_pair
    value = raw_control if depth == 0 else encoded_control
    for _ in range(max(0, depth - 1)):
        value = value.replace("&", "&amp;")
    expected = (
        "display_unsafe_control"
        if depth < 3
        else "display_decode_depth_exceeded"
    )
    try:
        render_evidence(value)
    except DisplayError as exc:
        assert exc.code == expected
    else:
        raise AssertionError("forbidden control was accepted")


@settings(max_examples=500, deadline=None, database=None, derandomize=True)
@given(_ARBITRARY_VALUE)
def test_arbitrary_field_inputs_are_total_and_sanitized(value: object) -> None:
    outcomes: list[tuple[str, object]] = []
    for _ in range(2):
        try:
            result = render_evidence(value)  # type: ignore[arg-type]
        except DisplayError as exc:
            assert exc.code in DISPLAY_ERROR_CODES
            assert exc.args == (exc.code,)
            assert exc.__cause__ is None
            assert exc.__context__ is None
            outcomes.append(("error", exc.code))
        else:
            assert isinstance(result, str)
            assert result == unicodedata.normalize("NFC", result)
            outcomes.append(("result", result))
    assert outcomes[0] == outcomes[1]


@settings(max_examples=500, deadline=None, database=None, derandomize=True)
@given(_SAFE_TEXT, _SAFE_TEXT, _SAFE_TEXT, st.one_of(st.none(), _SAFE_TEXT))
def test_factory_result_is_deterministic_for_safe_synthetic_items(
    title: str, company: str, description: str, location: str | None
) -> None:
    item = PilotItem("e" * 24, title, company, location, description)
    first = render_pilot_item(item)
    second = render_pilot_item(item)
    assert first == second
    for value in (first.title, first.company, first.description, first.location):
        if value is not None:
            assert value == unicodedata.normalize("NFC", value)
            assert "\x1b" not in value


def test_public_rendering_has_no_runtime_io_side_effects(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("display rendering attempted runtime IO")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr(os, "getenv", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    assert render_evidence("offline safe text") == "offline safe text"
