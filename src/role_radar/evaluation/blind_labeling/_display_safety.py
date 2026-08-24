"""Unicode, terminal-safety, size, and final-reference checks for display v2."""

from __future__ import annotations

import unicodedata

from role_radar.evaluation.blind_labeling.display_policy import (
    DISPLAY_ERROR_INPUT_INVALID,
    DISPLAY_ERROR_INPUT_TOO_LARGE,
    DISPLAY_ERROR_OUTPUT_TOO_LARGE,
    DISPLAY_ERROR_UNICODE_INVALID,
    DISPLAY_ERROR_UNSAFE_CONTROL,
    DISPLAY_ERROR_VISIBLE_EMAIL_FORBIDDEN,
    DISPLAY_ERROR_VISIBLE_URL_FORBIDDEN,
    DISPLAY_MAX_FIELD_INPUT_BYTES,
    DISPLAY_MAX_FIELD_OUTPUT_BYTES,
    DISPLAY_VISIBLE_EMAIL_PATTERN,
    DISPLAY_VISIBLE_URL_PATTERN,
    DisplayError,
)
from role_radar.evaluation.blind_labeling.display_policy import (
    validate_entity_replacement as _validate_entity_replacement,
)


def _is_noncharacter(codepoint: int) -> bool:
    return 0xFDD0 <= codepoint <= 0xFDEF or codepoint & 0xFFFF in {0xFFFE, 0xFFFF}


def _validate_scalars(value: str, *, error_code: str) -> None:
    for char in value:
        codepoint = ord(char)
        if codepoint > 0x10FFFF or 0xD800 <= codepoint <= 0xDFFF or _is_noncharacter(codepoint):
            raise DisplayError(error_code)


def _validate_controls(value: str, *, allow_lf_tab: bool) -> None:
    for char in value:
        codepoint = ord(char)
        if allow_lf_tab and codepoint in {0x09, 0x0A}:
            continue
        if (
            codepoint < 0x20
            or 0x7F <= codepoint <= 0x9F
            or codepoint in {0x2028, 0x2029, 0x061C}
            or 0x200E <= codepoint <= 0x200F
            or 0x202A <= codepoint <= 0x202E
            or 0x2066 <= codepoint <= 0x2069
        ):
            raise DisplayError(DISPLAY_ERROR_UNSAFE_CONTROL)


def validate_source(value: object) -> str:
    if not isinstance(value, str):
        raise DisplayError(DISPLAY_ERROR_INPUT_INVALID)
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        encoded = None
    if encoded is None:
        raise DisplayError(DISPLAY_ERROR_UNICODE_INVALID)
    if len(encoded) > DISPLAY_MAX_FIELD_INPUT_BYTES:
        raise DisplayError(DISPLAY_ERROR_INPUT_TOO_LARGE)
    _validate_scalars(value, error_code=DISPLAY_ERROR_UNICODE_INVALID)
    _validate_controls(value, allow_lf_tab=True)
    return value


def normalize_derived(value: str) -> str:
    normalized = unicodedata.normalize("NFC", value).replace("\t", r"\t")
    _validate_scalars(normalized, error_code=DISPLAY_ERROR_UNICODE_INVALID)
    _validate_controls(normalized, allow_lf_tab=True)
    if len(normalized.encode("utf-8")) > DISPLAY_MAX_FIELD_OUTPUT_BYTES:
        raise DisplayError(DISPLAY_ERROR_OUTPUT_TOO_LARGE)
    return normalized


def validate_final(value: str) -> str:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise DisplayError(DISPLAY_ERROR_UNICODE_INVALID) from None
    _validate_scalars(value, error_code=DISPLAY_ERROR_UNICODE_INVALID)
    _validate_controls(value, allow_lf_tab=True)
    if len(value.encode("utf-8")) > DISPLAY_MAX_FIELD_OUTPUT_BYTES:
        raise DisplayError(DISPLAY_ERROR_OUTPUT_TOO_LARGE)
    if DISPLAY_VISIBLE_URL_PATTERN.search(value) is not None:
        raise DisplayError(DISPLAY_ERROR_VISIBLE_URL_FORBIDDEN)
    if DISPLAY_VISIBLE_EMAIL_PATTERN.search(value) is not None:
        raise DisplayError(DISPLAY_ERROR_VISIBLE_EMAIL_FORBIDDEN)
    return value


def validate_entity_replacement(value: str) -> None:
    _validate_entity_replacement(value)


__all__ = [
    "normalize_derived",
    "validate_entity_replacement",
    "validate_final",
    "validate_source",
]
