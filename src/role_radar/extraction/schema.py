"""Schema Draft 2020-12 versionado y compatible con el contrato del broker."""

import json
from typing import Any

from role_radar.extraction.schemas import JobExtractionPayload

SCHEMA_VERSION = "job-extraction-1"
MAX_SCHEMA_BYTES = 64 * 1024
MAX_SCHEMA_DEPTH = 16
MAX_SCHEMA_PROPERTIES = 256


def get_extraction_schema() -> dict[str, Any]:
    schema = JobExtractionPayload.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    assert_broker_compatible(schema)
    return schema


def extraction_schema() -> dict[str, Any]:
    """Alias explícito para callers del adapter y tests."""
    return get_extraction_schema()


def schema_depth(value: Any, depth: int = 0) -> int:
    if isinstance(value, dict):
        return max([depth, *(schema_depth(item, depth + 1) for item in value.values())])
    if isinstance(value, list):
        return max([depth, *(schema_depth(item, depth + 1) for item in value)])
    return depth


def assert_broker_compatible(schema: dict[str, Any]) -> None:
    encoded = json.dumps(schema, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_SCHEMA_BYTES:
        raise ValueError("extraction schema exceeds broker size limit")
    if schema_depth(schema) > MAX_SCHEMA_DEPTH:
        raise ValueError("extraction schema exceeds broker depth limit")
    refs = []
    has_id = False
    too_many_properties = False

    def visit(value: Any) -> None:
        nonlocal has_id, too_many_properties
        if isinstance(value, dict):
            has_id = has_id or "$id" in value
            properties = value.get("properties")
            if isinstance(properties, dict) and len(properties) > MAX_SCHEMA_PROPERTIES:
                too_many_properties = True
            ref = value.get("$ref")
            if isinstance(ref, str):
                refs.append(ref)
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(schema)
    if has_id:
        raise ValueError("remote or declared schema ids are not supported")
    if too_many_properties:
        raise ValueError("schema object has too many declared properties")
    if any(not ref.startswith("#/") for ref in refs):
        raise ValueError("only local schema references are supported")
