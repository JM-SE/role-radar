"""Pure public facade for the versioned F10.2 blind-evidence display."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import final

from role_radar.evaluation.blind_labeling._display_entities import (
    decode_entities,
    verified_entity_table,
)
from role_radar.evaluation.blind_labeling._display_html import layout_html
from role_radar.evaluation.blind_labeling._display_safety import (
    normalize_derived,
    validate_final,
    validate_source,
)
from role_radar.evaluation.blind_labeling.contracts import PilotItem
from role_radar.evaluation.blind_labeling.display_policy import (
    DISPLAY_CONTRACT_SHA256,
    DISPLAY_CONTRACT_VERSION,
    DISPLAY_ERROR_EMPTY,
    DISPLAY_ERROR_INPUT_INVALID,
    DISPLAY_ERROR_OUTPUT_TOO_LARGE,
    DISPLAY_HASH_DOMAIN_RENDERED_EVIDENCE,
    DISPLAY_MAX_RENDERED_VISIBLE_EVIDENCE_BYTES,
    DISPLAY_SCHEMA,
    DisplayError,
    canonical_json_bytes,
)

_CONSTRUCTOR_TOKEN = object()


def _render_field(value: object) -> str:
    source = validate_source(value)
    rendered = normalize_derived(layout_html(decode_entities(source)))
    return validate_final(rendered)


def _require_nonempty(value: str) -> str:
    if not value.strip():
        raise DisplayError(DISPLAY_ERROR_EMPTY)
    return value


def _run_public[ResultT](operation: Callable[[], ResultT]) -> ResultT:
    """Normalize failures after exception handling has fully unwound."""

    result: ResultT | None = None
    error_code: str | None = None
    try:
        result = operation()
    except DisplayError as exc:
        error_code = exc.code
    except (UnicodeError, TypeError, ValueError):
        error_code = DISPLAY_ERROR_INPUT_INVALID
    if error_code is not None:
        raise DisplayError(error_code)
    assert result is not None
    return result


def _rendered_payload(
    *,
    opaque_id: str,
    title: str,
    company: str,
    location: str | None,
    description: str,
) -> bytes:
    return canonical_json_bytes(
        {
            "company": company,
            "description": description,
            "display_contract_sha256": DISPLAY_CONTRACT_SHA256,
            "display_contract_version": DISPLAY_CONTRACT_VERSION,
            "display_schema": DISPLAY_SCHEMA,
            "location": location,
            "opaque_id": opaque_id,
            "title": title,
        }
    )


def _rendered_hash(payload: bytes) -> str:
    return hashlib.sha256(
        DISPLAY_HASH_DOMAIN_RENDERED_EVIDENCE.encode("ascii") + b"\x00" + payload
    ).hexdigest()


@final
@dataclass(frozen=True, slots=True, init=False)
class RenderedEvidence:
    opaque_id: str
    title: str
    company: str
    location: str | None
    description: str
    display_schema: str
    display_contract_version: str
    display_contract_sha256: str
    rendered_evidence_sha256: str

    def __init__(
        self,
        opaque_id: str,
        title: str,
        company: str,
        location: str | None,
        description: str,
        display_schema: str,
        display_contract_version: str,
        display_contract_sha256: str,
        rendered_evidence_sha256: str,
        *,
        _token: object | None = None,
    ) -> None:
        if _token is not _CONSTRUCTOR_TOKEN:
            raise TypeError("RenderedEvidence requires its private factory token")
        object.__setattr__(self, "opaque_id", opaque_id)
        object.__setattr__(self, "title", title)
        object.__setattr__(self, "company", company)
        object.__setattr__(self, "location", location)
        object.__setattr__(self, "description", description)
        object.__setattr__(self, "display_schema", display_schema)
        object.__setattr__(self, "display_contract_version", display_contract_version)
        object.__setattr__(self, "display_contract_sha256", display_contract_sha256)
        object.__setattr__(self, "rendered_evidence_sha256", rendered_evidence_sha256)

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("RenderedEvidence is final")


def display_contract_identity() -> tuple[str, str]:
    return DISPLAY_CONTRACT_VERSION, DISPLAY_CONTRACT_SHA256


def _render_evidence(value: str) -> str:
    verified_entity_table()
    rendered = _render_field(value)
    return _require_nonempty(rendered)


def render_evidence(value: str) -> str:
    """Render one required evidence field without exposing source markup."""

    return _run_public(lambda: _render_evidence(value))


def _render_pilot_item(
    item: PilotItem,
) -> tuple[str, str, str, str | None, str, str]:
    """Render all evidence fields and create the only supported v2 result."""

    verified_entity_table()
    if not isinstance(item, PilotItem) or not isinstance(item.opaque_id, str):
        raise DisplayError(DISPLAY_ERROR_INPUT_INVALID)
    title = _require_nonempty(_render_field(item.title))
    company = _require_nonempty(_render_field(item.company))
    description = _require_nonempty(_render_field(item.description))
    location: str | None
    if item.location is None:
        location = None
    else:
        derived_location = _render_field(item.location)
        location = (
            None if item.location.isspace() or not derived_location.strip() else derived_location
        )
    visible_bytes = sum(
        len(value.encode("utf-8"))
        for value in (title, company, description, location)
        if value is not None
    )
    if visible_bytes > DISPLAY_MAX_RENDERED_VISIBLE_EVIDENCE_BYTES:
        raise DisplayError(DISPLAY_ERROR_OUTPUT_TOO_LARGE)
    payload = _rendered_payload(
        opaque_id=item.opaque_id,
        title=title,
        company=company,
        location=location,
        description=description,
    )
    result_hash = _rendered_hash(payload)
    return (
        item.opaque_id,
        title,
        company,
        location,
        description,
        result_hash,
    )


def render_pilot_item(item: PilotItem) -> RenderedEvidence:
    """Render all evidence fields and create the only supported v2 result."""

    opaque_id, title, company, location, description, result_hash = _run_public(
        lambda: _render_pilot_item(item)
    )
    return RenderedEvidence(
        opaque_id,
        title,
        company,
        location,
        description,
        DISPLAY_SCHEMA,
        DISPLAY_CONTRACT_VERSION,
        DISPLAY_CONTRACT_SHA256,
        result_hash,
        _token=_CONSTRUCTOR_TOKEN,
    )


__all__ = [
    "DisplayError",
    "RenderedEvidence",
    "display_contract_identity",
    "render_evidence",
    "render_pilot_item",
]
