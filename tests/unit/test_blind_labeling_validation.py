"""Pure F10.2 validation tests."""

from __future__ import annotations

import json
import unicodedata

import pytest

from role_radar.evaluation.blind_labeling.contracts import Decision, Label
from role_radar.evaluation.blind_labeling.validation import (
    ValidationError,
    canonical_line,
    parse_pilot_line,
    validate_decision,
)


def test_decision_validation_enforces_label_specific_reasons_and_notes() -> None:
    assert validate_decision(Decision(Label.APPLY, "role_match")) == Decision(
        Label.APPLY, "role_match"
    )
    assert validate_decision(Decision(Label.MAYBE, "other_uncertainty", note="Missing scope"))
    with pytest.raises(ValidationError, match="note_required"):
        validate_decision(Decision(Label.REJECT, "other_negative"))
    with pytest.raises(ValidationError, match="primary_reason"):
        validate_decision(Decision(Label.APPLY, "role_mismatch"))
    with pytest.raises(ValidationError, match="note_forbidden_content"):
        validate_decision(Decision(Label.MAYBE, "description_incomplete", note="https://example.test"))


def test_pilot_line_rejects_duplicate_keys_and_requires_canonical_json() -> None:
    value = {
        "opaque_id": "a" * 24,
        "title": "Role",
        "company": "Acme",
        "location": None,
        "description": "Text",
    }
    assert parse_pilot_line(canonical_line(value)).opaque_id == "a" * 24
    duplicate = (
        b'{"opaque_id":"'
        + b"a" * 24
        + b'","opaque_id":"'
        + b"b" * 24
        + b'","title":"Role","company":"Acme","location":null,"description":"Text"}\n'
    )
    with pytest.raises(ValidationError, match="duplicate_json_key"):
        parse_pilot_line(duplicate)
    noncanonical = json.dumps(value, indent=2).encode() + b"\n"
    with pytest.raises(ValidationError, match="pilot_not_canonical"):
        parse_pilot_line(noncanonical)


def test_decision_notes_normalize_nfc_and_reject_directional_controls() -> None:
    note = "Cafe\u0301"
    normalized = validate_decision(Decision(Label.MAYBE, "description_incomplete", note=note))
    assert normalized.note == unicodedata.normalize("NFC", note)
    with pytest.raises(ValidationError, match="note_invalid"):
        validate_decision(Decision(Label.MAYBE, "description_incomplete", note="safe\u202evalue"))


def test_pilot_display_fields_reject_line_breaks_and_tabs() -> None:
    value = {
        "opaque_id": "a" * 24,
        "title": "Role\twith tab",
        "company": "Acme",
        "location": None,
        "description": "Text",
    }
    with pytest.raises(ValidationError, match="title_unsafe_control"):
        parse_pilot_line(canonical_line(value))
