"""Tests unitarios de ProfileRepository."""

from sqlalchemy.orm import Session

from role_radar.repositories.profiles import ProfileRepository


def test_create_and_get(db_session: Session) -> None:
    repo = ProfileRepository(db_session)
    profile = repo.create(name="Perfil A", profile_json={"roles": ["backend"]})
    db_session.commit()

    assert profile.id
    fetched = repo.get(profile.id)
    assert fetched is not None
    assert fetched.name == "Perfil A"
    assert fetched.version == 1
    assert fetched.is_active is True
    assert fetched.profile_json == {"roles": ["backend"]}


def test_get_unknown_returns_none(db_session: Session) -> None:
    repo = ProfileRepository(db_session)
    assert repo.get("no-existe") is None


def test_create_with_custom_version(db_session: Session) -> None:
    repo = ProfileRepository(db_session)
    profile = repo.create(
        name="Perfil B",
        profile_json={"roles": []},
        version=3,
        is_active=False,
    )
    db_session.commit()
    assert profile.version == 3
    assert profile.is_active is False


def test_list_active_filters_inactive(db_session: Session) -> None:
    repo = ProfileRepository(db_session)
    repo.create(name="Activo", profile_json={})
    repo.create(name="Inactivo", profile_json={}, is_active=False)
    db_session.commit()

    names = {p.name for p in repo.list_active()}
    assert names == {"Activo"}
    assert len(repo.list_all()) == 2
