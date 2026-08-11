"""Persistencia de perfiles candidato."""

from typing import Any, cast

from sqlalchemy import func, select, update
from sqlalchemy.engine import CursorResult
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

    def deactivate_if_active(self, profile_id: str) -> int:
        """Deactivate one predecessor only when it is still active.

        The row count is the optimistic-concurrency token used by the profile
        service. This method deliberately does not commit.
        """
        result = cast(
            CursorResult[Any],
            self._session.execute(
                update(CandidateProfile)
                .where(CandidateProfile.id == profile_id, CandidateProfile.is_active.is_(True))
                .values(is_active=False)
            ),
        )
        return int(result.rowcount)

    def max_version_for_name(self, name: str) -> int:
        """Return the highest version in one profile lineage."""
        return int(
            self._session.scalar(
                select(func.max(CandidateProfile.version)).where(CandidateProfile.name == name)
            )
            or 0
        )

    def active_candidates(self) -> list[CandidateProfile]:
        return self.list_active()

    def create_version(self, predecessor_id: str, profile_json: dict[str, Any]) -> CandidateProfile:
        """Compatibility entry point for the transactional profile service."""
        from role_radar.services.profile_service import ProfileService

        return ProfileService(self._session).create_version(predecessor_id, profile_json)

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
