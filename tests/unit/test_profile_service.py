"""Transactional profile-version transition tests."""

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from role_radar.repositories.profiles import ProfileRepository
from role_radar.services.profile_service import ProfileService

PROFILE = {
    "title": "backend engineer",
    "years_of_experience": 8,
    "target_roles": ["backend"],
    "target_titles": ["backend engineer"],
    "core_skills": ["python"],
    "secondary_skills": [],
    "regions": ["spain"],
    "remote_only": True,
    "employment_preferences": ["full_time"],
    "languages": {"english": "professional"},
    "excluded_roles": [],
    "excluded_technologies": [],
    "hard_constraints": {},
    "soft_preferences": {},
}


def test_successor_insert_failure_restores_predecessor(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    predecessor = ProfileRepository(db_session).create_v1(name="A", profile_json=PROFILE)
    db_session.commit()

    def fail_create(*_args: object, **_kwargs: object) -> None:
        raise IntegrityError("insert", {}, RuntimeError("collision"))

    monkeypatch.setattr(ProfileRepository, "create", fail_create)

    with pytest.raises(ValueError, match="already exists"):
        ProfileService(db_session).create_version(predecessor.id, PROFILE)

    db_session.commit()
    history = ProfileRepository(db_session).list_all()
    assert len(history) == 1
    assert history[0].version == 1
    assert history[0].is_active is True
