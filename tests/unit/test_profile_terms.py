"""Gate A selected-profile and deterministic phrase compiler checks."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from role_radar.continuous_acquisition.runtime_discovery_v2 import freeze_selected_profile
from role_radar.discovery.policy import DiscoveryPhraseGrammarV1, DiscoveryPolicyV1
from role_radar.discovery.profile_terms import (
    FrozenCandidateProfileV1,
    compile_profile_terms,
)
from role_radar.domain.profile import CandidateProfileV1, canonical_profile_sha256

PROFILE_ID = "00000000-0000-0000-0000-000000000001"


def profile() -> CandidateProfileV1:
    return CandidateProfileV1.model_validate(
        {
            "title": "backend engineer",
            "years_of_experience": 8,
            "target_roles": ["backend", "platform"],
            "target_titles": ["backend engineer", "platform engineer"],
            "core_skills": ["python"],
            "secondary_skills": [],
            "regions": ["europe"],
            "remote_only": True,
            "employment_preferences": ["full_time"],
            "languages": {"english": "professional"},
            "excluded_roles": [],
            "excluded_technologies": [],
            "hard_constraints": {
                "available_work_authorizations": [],
                "unavailable_work_authorizations": [],
                "allowed_employment_types": [],
            },
            "soft_preferences": {"preferred_industries": []},
        }
    )


def policy(*, group_values: tuple[str, ...] = ("Backend Engineer",)) -> DiscoveryPolicyV1:
    candidate = profile()
    return DiscoveryPolicyV1.model_validate(
        {
            "schema_version": 1,
            "policy_version": "gate-a-v1",
            "profile_binding": {
                "profile_id": PROFILE_ID,
                "row_version": 1,
                "schema_version": 1,
                "canonical_profile_sha256": canonical_profile_sha256(
                    candidate.model_dump(mode="json")
                ),
            },
            "phrase_grammar": DiscoveryPhraseGrammarV1().model_dump(mode="json"),
            "groups": {"backend": group_values},
            "target_roles": {
                "backend": {"primary_groups": ["backend"]},
                "platform": {"primary_groups": ["backend"]},
            },
            "target_titles": {
                "backend engineer": {"primary_groups": ["backend"]},
                "platform engineer": {"primary_groups": ["backend"]},
            },
        }
    )


def test_compilation_is_profile_bound_and_keeps_provenance() -> None:
    selected = policy()
    compiled = compile_profile_terms(
        FrozenCandidateProfileV1(selected.profile_binding, profile()), selected
    )
    assert compiled.approved_phrases == ("Backend Engineer",)
    assert len(compiled.phrases[0].provenance) == 4
    assert all(
        item.profile_binding == selected.profile_binding
        for item in [FrozenCandidateProfileV1(selected.profile_binding, profile())]
    )


def test_nine_compiled_phrases_fail_without_truncation() -> None:
    selected = policy(group_values=tuple(f"Role {index}" for index in range(9)))
    with pytest.raises(ValueError) as error:
        compile_profile_terms(
            FrozenCandidateProfileV1(selected.profile_binding, profile()), selected
        )
    assert getattr(error.value, "code", "") == "discovery_terms_limit_exceeded"


def test_freeze_selected_profile_fetches_only_bound_row() -> None:
    candidate = profile()
    row = SimpleNamespace(
        id=PROFILE_ID,
        version=1,
        schema_version=1,
        is_active=True,
        profile_json=candidate.model_dump(mode="json"),
    )
    binding = policy().profile_binding

    class Session:
        def get(self, _model: object, profile_id: str) -> object:
            assert profile_id == PROFILE_ID
            return row

        def list_active(self) -> list[object]:
            raise AssertionError("list_active must never be called")

    frozen = freeze_selected_profile(Session(), binding)
    assert frozen.binding == binding
    assert frozen.profile == candidate


def test_bound_row_drift_is_rejected() -> None:
    candidate = profile()
    binding = policy().profile_binding

    class Session:
        def get(self, _model: object, _profile_id: str) -> object:
            return SimpleNamespace(
                id=PROFILE_ID,
                version=2,
                schema_version=1,
                is_active=True,
                profile_json=candidate.model_dump(mode="json"),
            )

    with pytest.raises(ValueError) as error:
        freeze_selected_profile(Session(), binding)
    assert getattr(error.value, "code", "") == "discovery_profile_binding_mismatch"
