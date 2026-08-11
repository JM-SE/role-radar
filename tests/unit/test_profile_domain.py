"""Tests for canonical profile payloads and evidence fingerprints."""

from role_radar.domain.profile import (
    canonical_profile_bytes,
    canonical_profile_payload,
    canonical_profile_sha256,
)

PROFILE = {
    "title": "Backend Engineer",
    "years_of_experience": 8,
    "target_roles": ["Backend"],
    "target_titles": ["Backend Engineer"],
    "core_skills": ["Python"],
    "secondary_skills": [],
    "regions": ["Spain"],
    "remote_only": True,
    "employment_preferences": ["full_time"],
    "languages": {"English": "professional"},
    "excluded_roles": [],
    "excluded_technologies": [],
    "hard_constraints": {},
    "soft_preferences": {},
}


def test_canonical_profile_payload_and_hash_are_stable() -> None:
    canonical = canonical_profile_payload(PROFILE)
    assert canonical["title"] == "backend engineer"
    assert canonical["target_roles"] == ["backend"]
    assert canonical["hard_constraints"] == {
        "available_work_authorizations": [],
        "unavailable_work_authorizations": [],
        "allowed_employment_types": [],
    }
    assert canonical_profile_bytes(PROFILE) == canonical_profile_bytes(
        {**PROFILE, "title": " backend   engineer "}
    )
    assert len(canonical_profile_sha256(PROFILE)) == 64
