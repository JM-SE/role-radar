"""Strict, bounded entity decoding for the display-v2 contract."""

from __future__ import annotations

import hashlib
import html.entities
import json
import re
from collections.abc import Mapping
from types import MappingProxyType

from role_radar.evaluation.blind_labeling.display_policy import (
    DISPLAY_ENTITY_DECODE_PASSES,
    DISPLAY_ERROR_DECODE_DEPTH_EXCEEDED,
    DISPLAY_ERROR_ENTITY_INVALID,
    DISPLAY_ERROR_ENTITY_TABLE_MISMATCH,
    DISPLAY_ERROR_OUTPUT_TOO_LARGE,
    DISPLAY_ERROR_UNSAFE_CONTROL,
    DISPLAY_HTML5_ENTITY_TABLE_SHA256,
    DISPLAY_MAX_FIELD_OUTPUT_BYTES,
    DisplayError,
)

_NAMED_REFERENCE = re.compile(r"&([A-Za-z][A-Za-z0-9]+);\Z")
_NUMERIC_REFERENCE = re.compile(r"&#(?:([0-9]+)|[xX]([0-9A-Fa-f]+));\Z")
_ASCII_ALNUM = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")


def _canonical_table_bytes(table: Mapping[str, str]) -> bytes:
    return json.dumps(
        {key: table[key] for key in sorted(table) if key.endswith(";")},
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def verified_entity_table() -> Mapping[str, str]:
    """Return the current selected stdlib table only when its contract digest matches."""

    table = html.entities.html5
    selected = {key: value for key, value in table.items() if key.endswith(";")}
    digest = hashlib.sha256(_canonical_table_bytes(selected)).hexdigest()
    if digest != DISPLAY_HTML5_ENTITY_TABLE_SHA256:
        raise DisplayError(DISPLAY_ERROR_ENTITY_TABLE_MISMATCH)
    return MappingProxyType(selected)


def _valid_scalar(codepoint: int) -> bool:
    return (
        0 <= codepoint <= 0x10FFFF
        and not 0xD800 <= codepoint <= 0xDFFF
        and not 0xFDD0 <= codepoint <= 0xFDEF
        and codepoint & 0xFFFF not in {0xFFFE, 0xFFFF}
    )


def _replacement_is_safe(value: str) -> bool:
    for char in value:
        codepoint = ord(char)
        if (
            codepoint < 0x20
            or 0x7F <= codepoint <= 0x9F
            or codepoint in {0x2028, 0x2029}
            or codepoint == 0x061C
            or 0x200E <= codepoint <= 0x200F
            or 0x202A <= codepoint <= 0x202E
            or 0x2066 <= codepoint <= 0x2069
        ):
            return False
    return True


def _numeric_replacement(token: str) -> str:
    match = _NUMERIC_REFERENCE.fullmatch(token)
    if match is None:
        raise DisplayError(DISPLAY_ERROR_ENTITY_INVALID)
    digits, hex_digits = match.groups()
    try:
        codepoint = int(digits or hex_digits, 16 if hex_digits is not None else 10)
    except ValueError as exc:
        raise DisplayError(DISPLAY_ERROR_ENTITY_INVALID) from exc
    if not _valid_scalar(codepoint):
        raise DisplayError(DISPLAY_ERROR_ENTITY_INVALID)
    return chr(codepoint)


def _reference_at(value: str, start: int, table: Mapping[str, str]) -> tuple[int, str] | None:
    if value[start] != "&" or start + 1 >= len(value):
        return None
    next_char = value[start + 1]
    if next_char == "#":
        end = value.find(";", start + 2)
        if end < 0:
            raise DisplayError(DISPLAY_ERROR_ENTITY_INVALID)
        token = value[start : end + 1]
        return end + 1, _numeric_replacement(token)
    if next_char not in _ASCII_ALNUM or not next_char.isalpha():
        return None
    end = value.find(";", start + 1)
    if end >= 0:
        token = value[start : end + 1]
        match = _NAMED_REFERENCE.fullmatch(token)
        if match is None:
            raise DisplayError(DISPLAY_ERROR_ENTITY_INVALID)
        replacement = table.get(match.group(1) + ";")
        if replacement is None:
            raise DisplayError(DISPLAY_ERROR_ENTITY_INVALID)
        return end + 1, replacement

    end = start + 1
    while end < len(value) and value[end] in _ASCII_ALNUM:
        end += 1
    candidate = value[start + 1 : end] + ";"
    if candidate in table:
        raise DisplayError(DISPLAY_ERROR_ENTITY_INVALID)
    return None


def _decode_pass(value: str, table: Mapping[str, str]) -> tuple[str, bool]:
    output: list[str] = []
    changed = False
    index = 0
    while index < len(value):
        if value[index] == "&":
            reference = _reference_at(value, index, table)
            if reference is not None:
                end, replacement = reference
                if not _replacement_is_safe(replacement):
                    raise DisplayError(DISPLAY_ERROR_UNSAFE_CONTROL)
                output.append(replacement)
                index = end
                changed = True
                continue
        output.append(value[index])
        index += 1
    decoded = "".join(output)
    if len(decoded.encode("utf-8")) > DISPLAY_MAX_FIELD_OUTPUT_BYTES:
        raise DisplayError(DISPLAY_ERROR_OUTPUT_TOO_LARGE)
    return decoded, changed


def _has_valid_reference(value: str, table: Mapping[str, str]) -> bool:
    index = 0
    while index < len(value):
        if value[index] == "&":
            reference = _reference_at(value, index, table)
            if reference is not None:
                return True
        index += 1
    return False


def decode_entities(value: str) -> str:
    """Decode only strict references, with a fixed two-pass depth bound."""

    table = verified_entity_table()
    current = value
    for _ in range(DISPLAY_ENTITY_DECODE_PASSES):
        current, changed = _decode_pass(current, table)
        if not changed:
            return current
    if _has_valid_reference(current, table):
        raise DisplayError(DISPLAY_ERROR_DECODE_DEPTH_EXCEEDED)
    return current


__all__ = ["decode_entities", "verified_entity_table"]
