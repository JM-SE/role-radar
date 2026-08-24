"""Table-driven tests for the F10.2 blind-evidence display v2 contract."""

from __future__ import annotations

import hashlib
import html.entities
import unicodedata
from dataclasses import FrozenInstanceError

import pytest

from role_radar.evaluation.blind_labeling.contracts import PilotItem
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
    DISPLAY_ERROR_EMPTY,
    DISPLAY_ERROR_ENTITY_INVALID,
    DISPLAY_ERROR_ENTITY_TABLE_MISMATCH,
    DISPLAY_ERROR_HTML_MALFORMED,
    DISPLAY_ERROR_OUTPUT_TOO_LARGE,
    DISPLAY_ERROR_UNSAFE_CONTROL,
    DISPLAY_ERROR_VISIBLE_EMAIL_FORBIDDEN,
    DISPLAY_ERROR_VISIBLE_URL_FORBIDDEN,
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
        ("&lt;div&gt;one&lt;br&gt;two&lt;/div&gt;", "one\ntwo"),
        ("&amp;lt;div&amp;gt;one&amp;lt;br&amp;gt;two&amp;lt;/div&amp;gt;", "one\ntwo"),
        ("&amp;copy; &amp;NotEqualTilde;", "© ≂̸"),
        ("Node.js Next.js ASP.NET example.com", "Node.js Next.js ASP.NET example.com"),
        ("<unknown data-secret=\"value\">visible</unknown>", "visible"),
        ("<!-- hidden --><!DOCTYPE html>visible", "visible"),
        ("<p>one</p><p>two</p><div>three</div>", "one\n\ntwo\n\nthree"),
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
        ("&unknown;", DISPLAY_ERROR_ENTITY_INVALID),
        ("&#xD800;", DISPLAY_ERROR_ENTITY_INVALID),
        ("&#10;", DISPLAY_ERROR_UNSAFE_CONTROL),
        ("\x1b[31mred", DISPLAY_ERROR_UNSAFE_CONTROL),
        ("http://example.com/jobs", DISPLAY_ERROR_VISIBLE_URL_FORBIDDEN),
        ("person@example.com", DISPLAY_ERROR_VISIBLE_EMAIL_FORBIDDEN),
        ("mailto:person@example.com", DISPLAY_ERROR_VISIBLE_URL_FORBIDDEN),
        ("example.com/path", DISPLAY_ERROR_VISIBLE_URL_FORBIDDEN),
    ),
)
def test_render_evidence_fails_closed_with_stable_codes(source: str, code: str) -> None:
    assert _error(source) == code
    assert _error(source) == code
    assert code in DISPLAY_ERROR_CODES


def test_attributes_are_discarded_without_emitting_external_references() -> None:
    assert render_evidence('<a href="https://example.com/x" title="a@b.test">safe</a>') == "safe"


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


def test_rendered_hash_is_reproducible_and_contract_identity_is_bound() -> None:
    item = PilotItem("c" * 24, "Role", "Acme", "Remote", "Description")
    first = render_pilot_item(item)
    second = render_pilot_item(item)
    assert first == second
    assert display_contract_identity() == (DISPLAY_CONTRACT_VERSION, DISPLAY_CONTRACT_SHA256)
    assert len(first.rendered_evidence_sha256) == 64
    assert hashlib.sha256(first.rendered_evidence_sha256.encode()).hexdigest()


def test_rendered_item_aggregate_size_is_enforced() -> None:
    from role_radar.evaluation.blind_labeling.display_policy import (
        DISPLAY_MAX_RENDERED_VISIBLE_EVIDENCE_BYTES,
    )

    item = PilotItem(
        "d" * 24,
        "a" * (DISPLAY_MAX_RENDERED_VISIBLE_EVIDENCE_BYTES // 2),
        "b" * (DISPLAY_MAX_RENDERED_VISIBLE_EVIDENCE_BYTES // 2),
        None,
        "c",
    )
    with pytest.raises(DisplayError, match=DISPLAY_ERROR_OUTPUT_TOO_LARGE):
        render_pilot_item(item)


def test_display_error_does_not_expose_source_or_internal_cause() -> None:
    secret = "secret-visible-https://example.com/private"
    with pytest.raises(DisplayError) as raised:
        render_evidence(secret)
    assert raised.value.args == (DISPLAY_ERROR_VISIBLE_URL_FORBIDDEN,)
    assert secret not in str(raised.value)
    assert raised.value.__cause__ is None


def test_entity_table_drift_fails_before_input_processing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(html.entities, "html5", {"amp;": "&"})
    assert _error("not-a-str") == DISPLAY_ERROR_ENTITY_TABLE_MISMATCH
