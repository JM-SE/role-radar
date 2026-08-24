"""Bounded deterministic property checks for display-v2 totality and limits."""

from __future__ import annotations

import unicodedata

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
_SAFE_TEXT = st.text(_SAFE_CHARACTERS, min_size=1, max_size=128).filter(
    lambda value: any(not char.isspace() for char in value)
)


@settings(max_examples=500, deadline=None, database=None, derandomize=True)
@given(_SAFE_TEXT)
def test_safe_plain_text_is_nfc_and_tab_stable(value: str) -> None:
    rendered = render_evidence(value)
    assert rendered == unicodedata.normalize("NFC", value).replace("\t", r"\t")
    assert value == value


@settings(max_examples=500, deadline=None, database=None, derandomize=True)
@given(
    st.one_of(
        st.none(), st.binary(max_size=256), st.integers(), st.booleans(), st.text(max_size=256)
    )
)
def test_arbitrary_field_inputs_are_total_and_sanitized(value: object) -> None:
    outcomes: list[tuple[str, object]] = []
    for _ in range(2):
        try:
            result = render_evidence(value)  # type: ignore[arg-type]
        except DisplayError as exc:
            assert exc.code in DISPLAY_ERROR_CODES
            assert exc.args == (exc.code,)
            assert exc.__cause__ is None
            outcomes.append(("error", exc.code))
        else:
            assert isinstance(result, str)
            assert result == unicodedata.normalize("NFC", result)
            outcomes.append(("result", result))
    assert outcomes[0] == outcomes[1]


@settings(max_examples=100, deadline=None, database=None, derandomize=True)
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
