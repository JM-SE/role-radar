import pytest

from role_radar.deep_evaluation.input_builder import DeepEvaluationInputV1, build_deep_input
from role_radar.deep_evaluation.schema import validate_deep_payload
from tests.unit.test_deep_selector import candidate


def valid_input() -> DeepEvaluationInputV1:
    item = candidate(80)
    return build_deep_input(
        item,
        profile={
            "title": "engineer",
            "years_of_experience": 4,
            "target_roles": (),
            "target_titles": (),
            "core_skills": (),
            "secondary_skills": (),
            "regions": (),
            "remote_only": False,
            "employment_preferences": (),
            "languages": {},
            "excluded_roles": (),
            "excluded_technologies": (),
            "hard_constraints": {},
            "soft_preferences": {"preferred_industries": ()},
        },
        extraction={"remote_policy": {"state": "unknown", "value": None, "evidence": None}},
    )


def test_payload_is_strict_and_no_cot() -> None:
    input_value = valid_input()
    payload = {
        "fit_score": 75,
        "decision": "strong_match",
        "strengths": [],
        "gaps": [],
        "model_concerns": [],
        "uncertainties": [],
        "recommended_action": "apply",
        "confidence": 1,
    }
    assert validate_deep_payload(payload, input_value).fit_score == 75
    with pytest.raises(ValueError):
        validate_deep_payload({**payload, "reasoning": "secret"}, input_value)
