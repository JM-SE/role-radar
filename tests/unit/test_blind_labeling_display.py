"""Table-driven tests for the F10.2 blind-evidence display v2 contract."""

from __future__ import annotations

import hashlib
import html.entities
import unicodedata
from collections.abc import Mapping
from dataclasses import FrozenInstanceError
from typing import cast

import pytest

from role_radar.evaluation.blind_labeling.contracts import PilotItem, PilotSnapshot
from role_radar.evaluation.blind_labeling.display import (
    DisplayError,
    RenderedEvidence,
    display_contract_identity,
    render_evidence,
    render_pilot_item,
)
from role_radar.evaluation.blind_labeling.display_policy import (
    DISPLAY_CONTRACT_SHA256,
    DISPLAY_CONTRACT_VERSION,
    DISPLAY_ERROR_CODES,
    DISPLAY_ERROR_DECODE_DEPTH_EXCEEDED,
    DISPLAY_ERROR_EMPTY,
    DISPLAY_ERROR_ENTITY_INVALID,
    DISPLAY_ERROR_ENTITY_TABLE_MISMATCH,
    DISPLAY_ERROR_HTML_DEPTH_EXCEEDED,
    DISPLAY_ERROR_HTML_MALFORMED,
    DISPLAY_ERROR_INPUT_TOO_LARGE,
    DISPLAY_ERROR_OUTPUT_TOO_LARGE,
    DISPLAY_ERROR_PARSE_LIMIT_EXCEEDED,
    DISPLAY_ERROR_UNSAFE_CONTROL,
    DISPLAY_ERROR_VISIBLE_EMAIL_FORBIDDEN,
    DISPLAY_ERROR_VISIBLE_URL_FORBIDDEN,
    DISPLAY_MAX_FIELD_INPUT_BYTES,
    DISPLAY_MAX_FIELD_OUTPUT_BYTES,
    DISPLAY_MAX_HTML_DEPTH,
    DISPLAY_MAX_PARSE_EVENTS,
    DISPLAY_MAX_RENDERED_VISIBLE_EVIDENCE_BYTES,
    DISPLAY_POLICY_PAYLOAD,
)
from role_radar.evaluation.blind_labeling.interaction import compose_rendered_item
from role_radar.evaluation.blind_labeling.validation import canonical_line, parse_pilot_line


def _error(value: object) -> str:
    with pytest.raises(DisplayError) as raised:
        render_evidence(value)  # type: ignore[arg-type]
    return raised.value.code


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        ("Plain text", "Plain text"),
        ("Cafe\u0301", "Café"),
        ("emoji 🐍 / 日本語", "emoji 🐍 / 日本語"),
        ("left\tright", r"left\tright"),
        ("line one\nline two", "line one\nline two"),
        ("safe & ordinary &name", "safe & ordinary &name"),
        ("&lt;div&gt;one&lt;br&gt;two&lt;/div&gt;", "one\ntwo"),
        ("&amp;lt;div&amp;gt;one&amp;lt;br&amp;gt;two&amp;lt;/div&amp;gt;", "one\ntwo"),
        ("&amp;copy; &amp;NotEqualTilde;", "© ≂̸"),
        ("Node.js Next.js ASP.NET example.com", "Node.js Next.js ASP.NET example.com"),
        ("<unknown data-secret=\"value\">visible</unknown>", "visible"),
        ("<!-- hidden --><!DOCTYPE html>visible", "visible"),
        ("<h1>one</h1><section>two</section><article>three</article>", "one\n\ntwo\n\nthree"),
        ("<p>one</p><p>two</p><div>three</div>", "one\n\ntwo\n\nthree"),
        ("one<br><br>two", "one\n\ntwo"),
        (
            "<ul><li>one</li><li>two<ul><li>nested<br>line</li></ul></li></ul>",
            "- one\n- two\n  - nested\n    line",
        ),
    ),
)
def test_render_evidence_has_deterministic_plain_text_layout(source: str, expected: str) -> None:
    assert render_evidence(source) == expected
    assert render_evidence(source) == expected
    assert render_evidence(unicodedata.normalize("NFC", source)) == expected


@pytest.mark.parametrize(
    ("source", "code"),
    (
        ("", DISPLAY_ERROR_EMPTY),
        ("   \u2003", DISPLAY_ERROR_EMPTY),
        ("<script>hidden</script>", DISPLAY_ERROR_EMPTY),
        ("<div>", DISPLAY_ERROR_HTML_MALFORMED),
        ("<div", DISPLAY_ERROR_HTML_MALFORMED),
        ("<div><span></div>", DISPLAY_ERROR_HTML_MALFORMED),
        ("&amp", DISPLAY_ERROR_ENTITY_INVALID),
        ("&copy", DISPLAY_ERROR_ENTITY_INVALID),
        ("&unknown;", DISPLAY_ERROR_ENTITY_INVALID),
        ("&amp;amp;amp;", DISPLAY_ERROR_DECODE_DEPTH_EXCEEDED),
        ("&#xD800;", DISPLAY_ERROR_ENTITY_INVALID),
        ("&#10;", DISPLAY_ERROR_UNSAFE_CONTROL),
        ("\x1b[31mred", DISPLAY_ERROR_UNSAFE_CONTROL),
        ("http://example.com/jobs", DISPLAY_ERROR_VISIBLE_URL_FORBIDDEN),
        ("person@example.com", DISPLAY_ERROR_VISIBLE_EMAIL_FORBIDDEN),
        ("mailto:person@example.com", DISPLAY_ERROR_VISIBLE_URL_FORBIDDEN),
        ("example.com/path", DISPLAY_ERROR_VISIBLE_URL_FORBIDDEN),
        ("safe</>", DISPLAY_ERROR_HTML_MALFORMED),
        ("safe<!bogus>", DISPLAY_ERROR_HTML_MALFORMED),
        ("safe</div junk>", DISPLAY_ERROR_HTML_MALFORMED),
        ("safe<?pi?>", DISPLAY_ERROR_HTML_MALFORMED),
    ),
)
def test_render_evidence_fails_closed_with_stable_codes(source: str, code: str) -> None:
    assert _error(source) == code
    assert _error(source) == code
    assert code in DISPLAY_ERROR_CODES


def test_attributes_are_discarded_without_emitting_external_references() -> None:
    assert render_evidence('<a href="https://example.com/x" title="a@b.test">safe</a>') == "safe"


@pytest.mark.parametrize("tag", ("script", "style", "noscript", "iframe", "object", "embed"))
def test_every_suppressed_tag_hides_its_complete_subtree(tag: str) -> None:
    assert render_evidence(f"visible<{tag}>hidden<span>nested</span></{tag}>tail") == "visibletail"
    assert _error(f"<{tag}>hidden</{tag}>") == DISPLAY_ERROR_EMPTY


def test_encoded_inline_external_references_are_checked_after_layout() -> None:
    assert _error("https&#58;//example.com/<span>jobs</span>") == (
        DISPLAY_ERROR_VISIBLE_URL_FORBIDDEN
    )
    assert _error("person<span>@</span>example.com") == DISPLAY_ERROR_VISIBLE_EMAIL_FORBIDDEN


def test_field_input_output_and_tab_boundaries_are_utf8_bytes() -> None:
    assert len(render_evidence("a" * DISPLAY_MAX_FIELD_INPUT_BYTES).encode("utf-8")) == (
        DISPLAY_MAX_FIELD_OUTPUT_BYTES
    )
    assert len(render_evidence("é" * (DISPLAY_MAX_FIELD_INPUT_BYTES // 2)).encode("utf-8")) == (
        DISPLAY_MAX_FIELD_OUTPUT_BYTES
    )
    assert _error("a" * (DISPLAY_MAX_FIELD_INPUT_BYTES + 1)) == DISPLAY_ERROR_INPUT_TOO_LARGE
    assert _error("a" * (DISPLAY_MAX_FIELD_OUTPUT_BYTES - 1) + "\t") == (
        DISPLAY_ERROR_OUTPUT_TOO_LARGE
    )


def test_html_depth_and_parser_event_limits_fail_on_the_first_excess_event() -> None:
    nested = "<i>" * DISPLAY_MAX_HTML_DEPTH + "x" + "</i>" * DISPLAY_MAX_HTML_DEPTH
    assert render_evidence(nested) == "x"
    too_deep = "<i>" * (DISPLAY_MAX_HTML_DEPTH + 1) + "x" + "</i>" * (DISPLAY_MAX_HTML_DEPTH + 1)
    assert _error(too_deep) == DISPLAY_ERROR_HTML_DEPTH_EXCEEDED

    exact_events = "<i></i>" * ((DISPLAY_MAX_PARSE_EVENTS - 2) // 2) + "<!--x-->x"
    assert render_evidence(exact_events) == "x"
    over_events = exact_events + "<i>"
    assert _error(over_events) == DISPLAY_ERROR_PARSE_LIMIT_EXCEEDED


def test_factory_result_is_immutable_and_composer_has_only_visible_fields() -> None:
    item = PilotItem("a" * 24, "Role", "Acme", None, "Description")
    rendered = render_pilot_item(item)
    assert isinstance(rendered, RenderedEvidence)
    assert compose_rendered_item(rendered, index=1, total=2) == (
        "\n[1/2]\nTitle: Role\nCompany: Acme\nLocation: (not provided)\n\nDescription\n"
    )
    with pytest.raises(TypeError):
        RenderedEvidence("a" * 24, "Role", "Acme", None, "Description", "x", "y", "z", "h")
    with pytest.raises(TypeError):
        RenderedEvidence(
            "a" * 24,
            "Role",
            "Acme",
            None,
            "Description",
            "x",
            "y",
            "z",
            "h",
            _token=object(),
        )
    with pytest.raises(TypeError):
        type("ForgedEvidence", (RenderedEvidence,), {})
    with pytest.raises(FrozenInstanceError):
        rendered.title = "changed"  # type: ignore[misc]


def test_render_pilot_item_preserves_source_values_and_maps_blank_location_to_none() -> None:
    location = "Cafe\u0301"
    item = PilotItem("b" * 24, "Role", "Acme", " \t", location)
    before = (item.opaque_id, item.title, item.company, item.location, item.description)
    rendered = render_pilot_item(item)
    assert rendered.location is None
    assert rendered.description == "Café"
    assert (item.opaque_id, item.title, item.company, item.location, item.description) == before


def test_authoritative_pilot_bytes_remain_unchanged() -> None:
    source = canonical_line(
        {
            "opaque_id": "f" * 24,
            "title": "Café role",
            "company": "Acme",
            "location": None,
            "description": "&lt;div&gt;Build&lt;/div&gt;",
        }
    )
    before = (source, hashlib.sha256(source).hexdigest())
    item = parse_pilot_line(source)
    rendered = render_pilot_item(item)
    assert rendered.title == "Café role"
    assert rendered.description == "Build"
    assert (source, hashlib.sha256(source).hexdigest()) == before


def test_pilot_snapshot_and_item_authority_remain_unchanged() -> None:
    item = PilotItem("h" * 24, "Cafe\u0301 role", "Acme", None, "Safe description")
    snapshot = PilotSnapshot((item,), "d" * 64, "p" * 64, "v" * 64)
    before = (snapshot, item)
    rendered = render_pilot_item(item)
    assert rendered.title == "Café role"
    assert (snapshot, item) == before


def test_rendered_hash_is_reproducible_and_contract_identity_is_bound() -> None:
    item = PilotItem("c" * 24, "Role", "Acme", "Remote", "Description")
    first = render_pilot_item(item)
    second = render_pilot_item(item)
    assert first == second
    assert display_contract_identity() == (DISPLAY_CONTRACT_VERSION, DISPLAY_CONTRACT_SHA256)
    assert len(first.rendered_evidence_sha256) == 64
    assert hashlib.sha256(first.rendered_evidence_sha256.encode()).hexdigest()


def test_rendered_item_aggregate_size_is_enforced() -> None:
    item = PilotItem(
        "d" * 24,
        "a" * (DISPLAY_MAX_RENDERED_VISIBLE_EVIDENCE_BYTES - 1),
        "b",
        None,
        "c",
    )
    with pytest.raises(DisplayError, match=DISPLAY_ERROR_OUTPUT_TOO_LARGE):
        render_pilot_item(item)


def test_rendered_item_aggregate_exact_limit_and_optional_location_mapping() -> None:
    exact = PilotItem(
        "e" * 24,
        "a" * (DISPLAY_MAX_RENDERED_VISIBLE_EVIDENCE_BYTES - 2),
        "b",
        None,
        "c",
    )
    assert len(render_pilot_item(exact).title.encode("utf-8")) + 2 == (
        DISPLAY_MAX_RENDERED_VISIBLE_EVIDENCE_BYTES
    )
    with_location = PilotItem(
        "j" * 24,
        "a",
        "b",
        "d" * (DISPLAY_MAX_RENDERED_VISIBLE_EVIDENCE_BYTES - 3),
        "c",
    )
    assert len(render_pilot_item(with_location).location or "") == (
        DISPLAY_MAX_RENDERED_VISIBLE_EVIDENCE_BYTES - 3
    )
    rendered = render_pilot_item(
        PilotItem("f" * 24, "Role", "Acme", "\u2003", "Description")
    )
    assert rendered.location is None
    assert render_pilot_item(
        PilotItem("g" * 24, "Role", "Acme", "<embed>hidden</embed>", "Description")
    ).location is None


def test_policy_payload_is_recursively_immutable() -> None:
    with pytest.raises(TypeError):
        DISPLAY_POLICY_PAYLOAD["limits"] = {}  # type: ignore[index]
    limits = cast(Mapping[str, object], DISPLAY_POLICY_PAYLOAD["limits"])
    assert isinstance(limits, dict) is False
    with pytest.raises(TypeError):
        limits["accounting"] = {}  # type: ignore[index]


def test_display_error_does_not_expose_source_or_internal_cause() -> None:
    secret = "secret-visible-https://example.com/private"
    with pytest.raises(DisplayError) as raised:
        render_evidence(secret)
    assert raised.value.args == (DISPLAY_ERROR_VISIBLE_URL_FORBIDDEN,)
    assert secret not in str(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None

    with pytest.raises(DisplayError) as invalid:
        render_evidence("secret\ud800")
    assert invalid.value.args == ("display_unicode_invalid",)
    assert invalid.value.__cause__ is None
    assert invalid.value.__context__ is None


def test_entity_table_drift_fails_before_input_processing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(html.entities, "html5", {"amp;": "&"})
    assert _error("not-a-str") == DISPLAY_ERROR_ENTITY_TABLE_MISMATCH
