"""Versioned, pure policy for the F10.2 blind-evidence display contract v2."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Final, cast

DISPLAY_CONTRACT_VERSION: Final = "f10.2-display-v2"
DISPLAY_SCHEMA: Final = "f10.2-rendered-evidence-v1"
DISPLAY_ALGORITHM_REVISION: Final = "strict-entity-html-terminal-v1"
DISPLAY_ENTITY_DECODE_PASSES: Final = 2
DISPLAY_MAX_FIELD_INPUT_BYTES: Final = 1_048_576
DISPLAY_MAX_FIELD_OUTPUT_BYTES: Final = 1_048_576
DISPLAY_MAX_RENDERED_VISIBLE_EVIDENCE_BYTES: Final = 1_048_576
DISPLAY_MAX_HTML_DEPTH: Final = 64
DISPLAY_MAX_PARSE_EVENTS: Final = 100_000
DISPLAY_HTML5_ENTITY_TABLE_SOURCE: Final = "python:html.entities.html5"
DISPLAY_HTML5_ENTITY_KEY_POLICY: Final = "semicolon-terminated-only"
DISPLAY_HTML5_ENTITY_TABLE_CANONICALIZATION: Final = (
    "sorted-compact-json-utf8-ensure-ascii-false-v1"
)
DISPLAY_HTML5_ENTITY_TABLE_SHA256: Final = (
    "47eca34bf835bd382855775e292362f1088a49a10a66ae45a0accb26d58dfff6"
)

DISPLAY_BLOCK_TAGS: Final = frozenset(
    {"p", "h1", "h2", "h3", "h4", "h5", "h6", "div", "section", "article"}
)
DISPLAY_BREAK_TAG: Final = "br"
DISPLAY_LIST_CONTAINER_TAGS: Final = frozenset({"ul", "ol"})
DISPLAY_LIST_ITEM_TAG: Final = "li"
DISPLAY_SUPPRESSED_TAGS: Final = frozenset(
    {"script", "style", "noscript", "iframe", "object", "embed"}
)
DISPLAY_HTML_VOID_TAGS: Final = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }
)

DISPLAY_EXTERNAL_REFERENCE_PATTERN_FLAGS: Final = re.ASCII | re.IGNORECASE
DISPLAY_VISIBLE_URL_PATTERN_SOURCE: Final = (
    r"(?:https?://|www\.|mailto:)|"
    r"(?<![a-z0-9_@-])"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}(?::[0-9]{1,5})?(?=[/?#])"
)
DISPLAY_VISIBLE_EMAIL_PATTERN_SOURCE: Final = (
    r"(?<![a-z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[a-z0-9!#$%&'*+/=?^_`{|}~-]+"
    r"(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}(?![a-z0-9-])"
)
DISPLAY_VISIBLE_URL_PATTERN: Final = re.compile(
    DISPLAY_VISIBLE_URL_PATTERN_SOURCE, DISPLAY_EXTERNAL_REFERENCE_PATTERN_FLAGS
)
DISPLAY_VISIBLE_EMAIL_PATTERN: Final = re.compile(
    DISPLAY_VISIBLE_EMAIL_PATTERN_SOURCE, DISPLAY_EXTERNAL_REFERENCE_PATTERN_FLAGS
)

DISPLAY_ERROR_INPUT_INVALID: Final = "display_input_invalid"
DISPLAY_ERROR_INPUT_TOO_LARGE: Final = "display_input_too_large"
DISPLAY_ERROR_UNICODE_INVALID: Final = "display_unicode_invalid"
DISPLAY_ERROR_ENTITY_INVALID: Final = "display_entity_invalid"
DISPLAY_ERROR_ENTITY_TABLE_MISMATCH: Final = "display_entity_table_mismatch"
DISPLAY_ERROR_DECODE_DEPTH_EXCEEDED: Final = "display_decode_depth_exceeded"
DISPLAY_ERROR_HTML_MALFORMED: Final = "display_html_malformed"
DISPLAY_ERROR_HTML_DEPTH_EXCEEDED: Final = "display_html_depth_exceeded"
DISPLAY_ERROR_PARSE_LIMIT_EXCEEDED: Final = "display_parse_limit_exceeded"
DISPLAY_ERROR_UNSAFE_CONTROL: Final = "display_unsafe_control"
DISPLAY_ERROR_VISIBLE_URL_FORBIDDEN: Final = "display_visible_url_forbidden"
DISPLAY_ERROR_VISIBLE_EMAIL_FORBIDDEN: Final = "display_visible_email_forbidden"
DISPLAY_ERROR_OUTPUT_TOO_LARGE: Final = "display_output_too_large"
DISPLAY_ERROR_EMPTY: Final = "display_empty"

DISPLAY_ERROR_CODES: Final = (
    DISPLAY_ERROR_INPUT_INVALID,
    DISPLAY_ERROR_INPUT_TOO_LARGE,
    DISPLAY_ERROR_UNICODE_INVALID,
    DISPLAY_ERROR_ENTITY_INVALID,
    DISPLAY_ERROR_ENTITY_TABLE_MISMATCH,
    DISPLAY_ERROR_DECODE_DEPTH_EXCEEDED,
    DISPLAY_ERROR_HTML_MALFORMED,
    DISPLAY_ERROR_HTML_DEPTH_EXCEEDED,
    DISPLAY_ERROR_PARSE_LIMIT_EXCEEDED,
    DISPLAY_ERROR_UNSAFE_CONTROL,
    DISPLAY_ERROR_VISIBLE_URL_FORBIDDEN,
    DISPLAY_ERROR_VISIBLE_EMAIL_FORBIDDEN,
    DISPLAY_ERROR_OUTPUT_TOO_LARGE,
    DISPLAY_ERROR_EMPTY,
)

DISPLAY_HASH_DOMAIN_CONTRACT: Final = "f10.2:display-contract-v2"
DISPLAY_HASH_DOMAIN_RENDERED_EVIDENCE: Final = "f10.2:rendered-evidence-v1"


class DisplayError(ValueError):
    """Stable, sanitized failure from the display contract."""

    code: str

    def __init__(self, code: str) -> None:
        if code not in DISPLAY_ERROR_CODES:
            raise ValueError("unknown display error code")
        self.code = code
        super().__init__(code)


def validate_entity_replacement(value: str) -> None:
    """Validate a decoded entity before the next transformation stage."""

    for char in value:
        codepoint = ord(char)
        if (
            codepoint > 0x10FFFF
            or 0xD800 <= codepoint <= 0xDFFF
            or 0xFDD0 <= codepoint <= 0xFDEF
            or codepoint & 0xFFFF in {0xFFFE, 0xFFFF}
        ):
            raise DisplayError(DISPLAY_ERROR_UNICODE_INVALID)
        if (
            codepoint < 0x20
            or 0x7F <= codepoint <= 0x9F
            or codepoint in {0x2028, 0x2029, 0x061C}
            or 0x200E <= codepoint <= 0x200F
            or 0x202A <= codepoint <= 0x202E
            or 0x2066 <= codepoint <= 0x2069
        ):
            raise DisplayError(DISPLAY_ERROR_UNSAFE_CONTROL)


def canonical_json_bytes(value: object) -> bytes:
    """Serialize a display-owned value using the contract's canonical JSON rules."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


_DISPLAY_POLICY_PAYLOAD = {
    "algorithm_revision": DISPLAY_ALGORITHM_REVISION,
    "contract_version": DISPLAY_CONTRACT_VERSION,
    "derived_normalization": "NFC-after-layout-only-v1",
    "entity": {
        "canonicalization": DISPLAY_HTML5_ENTITY_TABLE_CANONICALIZATION,
        "decode_passes": DISPLAY_ENTITY_DECODE_PASSES,
        "key_policy": DISPLAY_HTML5_ENTITY_KEY_POLICY,
        "source": DISPLAY_HTML5_ENTITY_TABLE_SOURCE,
        "table_sha256": DISPLAY_HTML5_ENTITY_TABLE_SHA256,
    },
    "errors": list(DISPLAY_ERROR_CODES),
    "external_reference": {
        "email_pattern": DISPLAY_VISIBLE_EMAIL_PATTERN_SOURCE,
        "flags": int(DISPLAY_EXTERNAL_REFERENCE_PATTERN_FLAGS),
        "order": ["url", "email"],
        "url_pattern": DISPLAY_VISIBLE_URL_PATTERN_SOURCE,
        "bare_dotted_tokens": "not_url_without_path_query_fragment",
        "url_error": DISPLAY_ERROR_VISIBLE_URL_FORBIDDEN,
        "email_error": DISPLAY_ERROR_VISIBLE_EMAIL_FORBIDDEN,
    },
    "hash_domains": {
        "contract": DISPLAY_HASH_DOMAIN_CONTRACT,
        "rendered_evidence": DISPLAY_HASH_DOMAIN_RENDERED_EVIDENCE,
    },
    "html": {
        "block_tags": sorted(DISPLAY_BLOCK_TAGS),
        "break_tag": DISPLAY_BREAK_TAG,
        "list_containers": sorted(DISPLAY_LIST_CONTAINER_TAGS),
        "list_item": DISPLAY_LIST_ITEM_TAG,
        "suppressed_tags": sorted(DISPLAY_SUPPRESSED_TAGS),
        "void_tags": sorted(DISPLAY_HTML_VOID_TAGS),
        "comments_and_declarations": "discard",
        "unknown_tags": "discard_tags_preserve_text",
        "layout": "blocks-blank-line-br-line-li-bullet-two-space-indent-v1",
        "literal_ampersands": "control-sentinel-before-html-parser-v1",
    },
    "limits": {
        "field_input_bytes": DISPLAY_MAX_FIELD_INPUT_BYTES,
        "field_output_bytes": DISPLAY_MAX_FIELD_OUTPUT_BYTES,
        "aggregate_visible_evidence_bytes": DISPLAY_MAX_RENDERED_VISIBLE_EVIDENCE_BYTES,
        "html_depth": DISPLAY_MAX_HTML_DEPTH,
        "parse_events": DISPLAY_MAX_PARSE_EVENTS,
        "accounting": {
            "encoding": "utf-8",
            "field_input": "each-non-none-source-field-before-decoding",
            "working_output": "after-each-completed-entity-pass",
            "field_output": "each-non-none-final-field-after-nfc-and-tab-rendering",
            "aggregate": "title-company-description-and-non-none-location-only",
            "aggregate_excludes": [
                "opaque_id",
                "schema-version-hashes",
                "json-syntax",
                "composer-labels-counters-separators",
                "none-location",
            ],
            "enforcement": "before-serialization-hashing-and-constructor",
        },
    },
    "schema": DISPLAY_SCHEMA,
    "source_validation": {
        "input": "str-strict-utf8-unicode-scalars-noncharacters",
        "raw_allowed_controls": ["LF", "TAB"],
        "entity_allowed_controls": [],
        "rejected_controls": "C0-C1-DEL-ESC-CR-NUL-BIDI-U2028-U2029",
        "tabs": "visible-two-character-backslash-t",
        "attributes": "discard-never-emit",
        "empty_required": "fail",
        "empty_optional_location": "none",
    },
}
DISPLAY_POLICY_CANONICAL_BYTES: Final = canonical_json_bytes(_DISPLAY_POLICY_PAYLOAD)
DISPLAY_CONTRACT_SHA256: Final = hashlib.sha256(
    DISPLAY_HASH_DOMAIN_CONTRACT.encode("ascii") + b"\x00" + DISPLAY_POLICY_CANONICAL_BYTES
).hexdigest()


def _freeze_policy(value: object) -> object:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_policy(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_policy(item) for item in value)
    return value


# The mapping and every nested collection are intentionally immutable for callers.
DISPLAY_POLICY_PAYLOAD: Final = cast(Mapping[str, object], _freeze_policy(_DISPLAY_POLICY_PAYLOAD))


__all__ = [
    "DISPLAY_ALGORITHM_REVISION",
    "DISPLAY_BLOCK_TAGS",
    "DISPLAY_CONTRACT_SHA256",
    "DISPLAY_CONTRACT_VERSION",
    "DISPLAY_ENTITY_DECODE_PASSES",
    "DISPLAY_ERROR_CODES",
    "DISPLAY_ERROR_DECODE_DEPTH_EXCEEDED",
    "DISPLAY_ERROR_EMPTY",
    "DISPLAY_ERROR_ENTITY_INVALID",
    "DISPLAY_ERROR_ENTITY_TABLE_MISMATCH",
    "DISPLAY_ERROR_HTML_DEPTH_EXCEEDED",
    "DISPLAY_ERROR_HTML_MALFORMED",
    "DISPLAY_ERROR_INPUT_INVALID",
    "DISPLAY_ERROR_INPUT_TOO_LARGE",
    "DISPLAY_ERROR_OUTPUT_TOO_LARGE",
    "DISPLAY_ERROR_PARSE_LIMIT_EXCEEDED",
    "DISPLAY_ERROR_UNICODE_INVALID",
    "DISPLAY_ERROR_UNSAFE_CONTROL",
    "DISPLAY_ERROR_VISIBLE_EMAIL_FORBIDDEN",
    "DISPLAY_ERROR_VISIBLE_URL_FORBIDDEN",
    "DISPLAY_HASH_DOMAIN_CONTRACT",
    "DISPLAY_HASH_DOMAIN_RENDERED_EVIDENCE",
    "DISPLAY_HTML5_ENTITY_KEY_POLICY",
    "DISPLAY_HTML5_ENTITY_TABLE_CANONICALIZATION",
    "DISPLAY_HTML5_ENTITY_TABLE_SHA256",
    "DISPLAY_HTML5_ENTITY_TABLE_SOURCE",
    "DISPLAY_HTML_VOID_TAGS",
    "DISPLAY_LIST_CONTAINER_TAGS",
    "DISPLAY_LIST_ITEM_TAG",
    "DISPLAY_MAX_FIELD_INPUT_BYTES",
    "DISPLAY_MAX_FIELD_OUTPUT_BYTES",
    "DISPLAY_MAX_HTML_DEPTH",
    "DISPLAY_MAX_PARSE_EVENTS",
    "DISPLAY_MAX_RENDERED_VISIBLE_EVIDENCE_BYTES",
    "DISPLAY_POLICY_CANONICAL_BYTES",
    "DISPLAY_POLICY_PAYLOAD",
    "DISPLAY_SCHEMA",
    "DISPLAY_SUPPRESSED_TAGS",
    "DISPLAY_VISIBLE_EMAIL_PATTERN",
    "DISPLAY_VISIBLE_EMAIL_PATTERN_SOURCE",
    "DISPLAY_VISIBLE_URL_PATTERN",
    "DISPLAY_VISIBLE_URL_PATTERN_SOURCE",
    "DisplayError",
    "canonical_json_bytes",
    "validate_entity_replacement",
]
