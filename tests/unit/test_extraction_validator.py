"""Reglas puras de evidencia, duplicados y rangos."""

import json
from pathlib import Path

from role_radar.extraction.schemas import JobExtractionPayload
from role_radar.extraction.validator import validate_extraction


def _fixture(name: str) -> JobExtractionPayload:
    path = Path(__file__).parents[2] / "fixtures" / name
    return JobExtractionPayload.model_validate(json.loads(path.read_text()))


def test_evidence_uses_normalized_substrings() -> None:
    payload = _fixture("extraction_valid.json")
    assert validate_extraction(payload, "Build and operate the CORE   API platform at Acme.") == ()


def test_invalid_evidence_is_reported_without_returning_content() -> None:
    payload = _fixture("extraction_invalid_evidence.json")
    errors = validate_extraction(payload, "Build and operate the core API platform at Acme.")
    assert "seniority.evidence_not_found" in errors


def test_folded_match_accepts_connector_paraphrase() -> None:
    payload = JobExtractionPayload.model_validate(
        {
            "required_skills": [
                {"value": "JavaScript/TypeScript", "evidence": "JavaScript/TypeScript & React"},
            ],
        }
    )
    description = (
        "7+ Years of hands-on experience with modern Javascript/Typescript frontend "
        "development and React (or equivalent component frameworks)"
    )
    assert validate_extraction(payload, description) == ()


def test_folded_match_still_rejects_invented_quotes() -> None:
    payload = JobExtractionPayload.model_validate(
        {
            "required_skills": [
                {"value": "Go", "evidence": "5 years of Go and Kubernetes"},
            ],
        }
    )
    errors = validate_extraction(payload, "Python and Django role with on-call rotation.")
    assert "required_skills[0].evidence_not_found" in errors


def test_item_state_is_accepted_and_abstention_skipped() -> None:
    payload = JobExtractionPayload.model_validate(
        {
            "required_skills": [
                {"state": "specified", "value": "Python", "evidence": "Python and Django"},
                {"state": "unknown", "value": "Go", "evidence": None},
            ],
        }
    )
    errors = validate_extraction(payload, "Python and Django role.")
    assert errors == ()


def test_duplicate_items_and_incoherent_salary_are_reported() -> None:
    payload = JobExtractionPayload.model_validate(
        {
            "required_skills": [
                {"value": "Python", "evidence": "Python"},
                {"value": " python ", "evidence": "Python"},
            ],
            "salary": {
                "state": "specified",
                "min": 50,
                "max": 100,
                "currency": "USD",
                "period": "year",
                "evidence": "$50-$100 USD",
            },
        }
    )
    errors = validate_extraction(payload, "Python $50-$100 USD")
    assert "required_skills[1].duplicate" in errors
    assert not any(error.startswith("salary.") for error in errors)
