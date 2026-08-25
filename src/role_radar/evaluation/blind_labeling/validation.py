"""Pure validation and canonical parsing for F10.2."""

from __future__ import annotations

import json
import math
import unicodedata
from typing import Any

from role_radar.evaluation.blind_labeling.contracts import Decision, Label, PilotItem
from role_radar.evaluation.blind_labeling.policy import (
    CANARY_PATTERNS,
    LABEL_DOMAINS,
    MAX_PILOT_LINE_BYTES,
    NOTE_MAX_CODEPOINTS,
    OPAQUE_ID,
)


class ValidationError(ValueError):
    """Stable, sanitized validation failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_line(value: Any) -> bytes:
    return canonical_json(value) + b"\n"


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError("duplicate_json_key")
        result[key] = value
    return result


def _safe_text(value: object, *, field: str, allow_lf: bool = True) -> str:
    if not isinstance(value, str) or value != unicodedata.normalize("NFC", value):
        raise ValidationError(f"{field}_invalid_unicode")
    for char in value:
        code = ord(char)
        if code == 0x0A and allow_lf:
            continue
        if code == 0x09 and allow_lf:
            continue
        if (
            code < 0x20
            or 0x7F <= code <= 0x9F
            or 0x202A <= code <= 0x202E
            or 0x2066 <= code <= 0x2069
        ):
            raise ValidationError(f"{field}_unsafe_control")
    return value


def parse_pilot_line(line: bytes) -> PilotItem:
    if len(line) > MAX_PILOT_LINE_BYTES or not line.endswith(b"\n"):
        raise ValidationError("pilot_line_invalid")
    try:
        value = json.loads(
            line.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValidationError("non_finite_json")),
        )
    except ValidationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ValidationError("pilot_json_invalid") from exc
    if not isinstance(value, dict) or set(value) != {
        "opaque_id",
        "title",
        "company",
        "location",
        "description",
    }:
        raise ValidationError("pilot_schema_invalid")
    if canonical_line(value) != line:
        raise ValidationError("pilot_not_canonical")
    opaque_id = value["opaque_id"]
    if not isinstance(opaque_id, str) or OPAQUE_ID.fullmatch(opaque_id) is None:
        raise ValidationError("opaque_id_invalid")
    title = _safe_text(value["title"], field="title", allow_lf=False)
    company = _safe_text(value["company"], field="company", allow_lf=False)
    description = _safe_text(value["description"], field="description")
    location = value["location"]
    if location is not None:
        location = _safe_text(location, field="location", allow_lf=False)
    if not title.strip() or not company.strip() or not description.strip():
        raise ValidationError("pilot_required_text_missing")
    return PilotItem(opaque_id, title, company, location, description)


def validate_decision(decision: Decision) -> Decision:
    if not isinstance(decision.label, Label):
        raise ValidationError("label_invalid")
    allowed = LABEL_DOMAINS[decision.label.value]
    reasons = (decision.primary_reason, *decision.secondary_reasons)
    if decision.primary_reason not in allowed:
        raise ValidationError("primary_reason_invalid")
    if len(decision.secondary_reasons) > 2 or len(set(decision.secondary_reasons)) != len(
        decision.secondary_reasons
    ):
        raise ValidationError("secondary_reason_invalid")
    if decision.primary_reason in decision.secondary_reasons or any(
        reason not in allowed for reason in reasons
    ):
        raise ValidationError("reason_label_mismatch")
    note = decision.note
    if note is not None:
        if not isinstance(note, str):
            raise ValidationError("note_unicode_invalid")
        note = unicodedata.normalize("NFC", note).strip()
        if not note:
            note = None
        elif len(note) > NOTE_MAX_CODEPOINTS or any(
            ord(char) < 0x20
            or 0x7F <= ord(char) <= 0x9F
            or 0x202A <= ord(char) <= 0x202E
            or 0x2066 <= ord(char) <= 0x2069
            for char in note
        ):
            raise ValidationError("note_invalid")
        elif any(pattern.search(note) for pattern in CANARY_PATTERNS):
            raise ValidationError("note_forbidden_content")
    uses_other = any(reason.startswith("other_") for reason in reasons)
    if uses_other and note is None:
        raise ValidationError("note_required_for_other")
    if not uses_other and note is not None and decision.label is not Label.MAYBE:
        raise ValidationError("note_forbidden")
    return Decision(
        decision.label, decision.primary_reason, tuple(sorted(decision.secondary_reasons)), note
    )


def decision_dict(decision: Decision) -> dict[str, Any]:
    validated = validate_decision(decision)
    return {
        "label": validated.label.value,
        "primary_reason": validated.primary_reason,
        "secondary_reasons": list(validated.secondary_reasons),
        "note": validated.note,
    }


def decision_from_dict(value: object) -> Decision:
    if not isinstance(value, dict) or set(value) != {
        "label",
        "primary_reason",
        "secondary_reasons",
        "note",
    }:
        raise ValidationError("decision_schema_invalid")
    try:
        decision = Decision(
            Label(str(value["label"])),
            str(value["primary_reason"]),
            tuple(str(item) for item in value["secondary_reasons"]),
            value["note"],
        )
    except (TypeError, ValueError) as exc:
        raise ValidationError("decision_schema_invalid") from exc
    return validate_decision(decision)


def validate_json_number(value: object) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValidationError("non_finite_json")


__all__ = [
    "ValidationError",
    "canonical_json",
    "canonical_line",
    "decision_dict",
    "decision_from_dict",
    "parse_pilot_line",
    "validate_decision",
]
