"""Contrato versionado del payload y del schema que recibe el broker."""

import json
from pathlib import Path

from role_radar.extraction.schema import (
    MAX_SCHEMA_BYTES,
    SCHEMA_VERSION,
    assert_broker_compatible,
    get_extraction_schema,
    schema_depth,
)
from role_radar.extraction.schemas import JobExtractionPayload


def test_valid_fixture_and_schema_limits() -> None:
    fixture = Path(__file__).parents[2] / "fixtures" / "extraction_valid.json"
    payload = JobExtractionPayload.model_validate_json(fixture.read_text())
    assert payload.required_skills[0].evidence == "core API platform"
    schema = get_extraction_schema()
    assert SCHEMA_VERSION
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert len(json.dumps(schema, ensure_ascii=False).encode()) <= MAX_SCHEMA_BYTES
    assert schema_depth(schema) <= 16
    assert_broker_compatible(schema)


def test_payload_rejects_unknown_fields() -> None:
    try:
        JobExtractionPayload.model_validate({"unexpected": True})
    except ValueError as exc:
        assert "unexpected" in str(exc)
    else:
        raise AssertionError("unknown extraction field was accepted")
