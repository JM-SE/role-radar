import pytest

from role_radar.deep_evaluation.input_builder import build_deep_input
from tests.unit.test_deep_selector import candidate


def test_input_excludes_description_and_soft_preferences() -> None:
    item = candidate(80)
    value = build_deep_input(
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
            "soft_preferences": {"preferred_industries": ("secret",)},
        },
        extraction={"required_skills": [{"value": "Python", "evidence": "Python"}]},
    )
    dumped = value.model_dump_json()
    assert "description" not in dumped
    assert "secret" not in dumped


def test_long_evidence_is_rejected_not_truncated() -> None:
    item = candidate(80)
    with pytest.raises(ValueError, match="240"):
        build_deep_input(
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
                "soft_preferences": {},
            },
            extraction={"required_skills": [{"value": "Python", "evidence": "x" * 241}]},
        )
