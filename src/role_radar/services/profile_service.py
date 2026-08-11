"""Application rules for immutable candidate-profile version transitions."""

from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from role_radar.db.models import CandidateProfile
from role_radar.repositories.profiles import ProfileRepository


class ProfileService:
    """Coordinate profile transitions without owning the outer request commit."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._repository = ProfileRepository(session)

    def create_version(
        self, predecessor_id: str, profile_json: dict[str, Any]
    ) -> CandidateProfile:
        """Create exactly one active successor using predecessor CAS.

        The nested transaction ensures that a failed successor insert restores
        the predecessor's active flag before the request dependency decides
        whether to commit the outer transaction.
        """
        with self._session.begin_nested():
            predecessor = self._repository.get(predecessor_id)
            if predecessor is None:
                raise LookupError("profile not found")
            if not predecessor.is_active:
                raise ValueError("profile version is inactive")

            active_profiles = self._repository.active_for_name(predecessor.name)
            if len(active_profiles) != 1 or active_profiles[0].id != predecessor_id:
                raise ValueError("profile active state conflict")

            if self._repository.deactivate_if_active(predecessor_id) != 1:
                raise ValueError("profile version update conflict")

            try:
                successor = self._repository.create(
                    name=predecessor.name,
                    profile_json=profile_json,
                    version=self._repository.max_version_for_name(predecessor.name) + 1,
                    schema_version=1,
                    is_active=True,
                )
            except IntegrityError as exc:
                raise ValueError("profile version already exists") from exc

        return successor
