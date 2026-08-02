"""Persistencia de perfiles candidato."""

from typing import Any

from sqlalchemy import func, select
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
        schema_version: int = 0,
    ) -> CandidateProfile:
        profile = CandidateProfile(
            name=name,
            profile_json=profile_json,
            version=version,
            is_active=is_active,
            schema_version=schema_version,
        )
        self._session.add(profile)
        self._session.flush()
        return profile

    def create_v1(self, *, name: str, profile_json: dict[str, Any]) -> CandidateProfile:
        """Create the first canonical version; callers own the transaction."""
        profile = self.create(name=name, profile_json=profile_json, version=1, schema_version=1)
        return profile

    def active_for_name(self, name: str) -> list[CandidateProfile]:
        stmt = (
            select(CandidateProfile)
            .where(CandidateProfile.name == name, CandidateProfile.is_active.is_(True))
            .order_by(CandidateProfile.version, CandidateProfile.id)
        )
        return list(self._session.scalars(stmt))

    def active_candidates(self) -> list[CandidateProfile]:
        return self.list_active()

    def create_version(self, predecessor_id: str, profile_json: dict[str, Any]) -> CandidateProfile:
        predecessor = self.get(predecessor_id)
        if predecessor is None:
            raise LookupError("profile not found")
        if not predecessor.is_active:
            raise ValueError("profile version is inactive")
        max_version = (
            self._session.scalar(
                select(func.max(CandidateProfile.version)).where(
                    CandidateProfile.name == predecessor.name
                )
            )
            or predecessor.version
        )
        predecessor.is_active = False
        profile = CandidateProfile(
            name=predecessor.name,
            version=int(max_version) + 1,
            profile_json=profile_json,
            schema_version=1,
            is_active=True,
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
