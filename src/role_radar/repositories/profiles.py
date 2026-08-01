"""Persistencia de perfiles candidato."""

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from role_radar.db.models import CandidateProfile


class ProfileRepository:
    """I/O de CandidateProfile. Sin reglas de negocio ni commit propio."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create(
        self,
        name: str,
        profile_json: dict[str, Any],
        version: int = 1,
        is_active: bool = True,
    ) -> CandidateProfile:
        profile = CandidateProfile(
            name=name,
            profile_json=profile_json,
            version=version,
            is_active=is_active,
        )
        self._session.add(profile)
        self._session.flush()
        return profile

    def get(self, profile_id: str) -> CandidateProfile | None:
        return self._session.get(CandidateProfile, profile_id)

    def list_active(self) -> list[CandidateProfile]:
        stmt = (
            select(CandidateProfile)
            .where(CandidateProfile.is_active.is_(True))
            .order_by(CandidateProfile.created_at)
        )
        return list(self._session.scalars(stmt))

    def list_all(self) -> list[CandidateProfile]:
        stmt = select(CandidateProfile).order_by(CandidateProfile.created_at)
        return list(self._session.scalars(stmt))
