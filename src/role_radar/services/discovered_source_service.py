"""Worker-only registration policy for independently verified ATS sources."""

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from role_radar.discovery.contracts import (
    GreenhouseOfficialCandidate,
    KnownOfficialCandidate,
    LeverOfficialCandidate,
    SourceRegistration,
)
from role_radar.discovery.policy import (
    DISCOVERY_POLICY_VERSION,
    MAX_ACTIVE_DISCOVERY_SOURCES,
    MAX_NEW_SOURCES_PER_RUN,
)
from role_radar.domain.enums import SourceType
from role_radar.repositories.sources import SourceRepository
from role_radar.sources.configuration import GreenhouseSourceConfig, LeverSourceConfigV1
from role_radar.sources.identity import canonical_source_key


class DiscoveredSourceService:
    """No HTTP/API entry point; called only after official collector success."""

    def __init__(
        self,
        session: Session,
        *,
        max_new_per_run: int = MAX_NEW_SOURCES_PER_RUN,
        max_active: int = MAX_ACTIVE_DISCOVERY_SOURCES,
    ) -> None:
        self._sources = SourceRepository(session)
        self._session = session
        self._max_new_per_run = max_new_per_run
        self._max_active = max_active

    def register_verified(
        self, candidate: KnownOfficialCandidate, *, new_sources_used: int = 0
    ) -> SourceRegistration:
        source_type, configuration, name = _candidate_data(candidate)
        key = canonical_source_key(source_type, configuration)
        existing = self._sources.get_by_key(key)
        if existing is not None:
            blocked = not existing.enabled or existing.archived_at is not None
            return SourceRegistration(existing.id, key, False, True, blocked)
        if new_sources_used >= self._max_new_per_run:
            return SourceRegistration(None, key, False, False, True)
        if self._sources.count_active_management_origin("discovery") >= self._max_active:
            return SourceRegistration(None, key, False, False, True)
        try:
            # The savepoint makes a unique-key race recoverable without
            # invalidating the caller's finalization transaction.
            with self._session.begin_nested():
                row = self._sources.create_row(
                    source_id=str(uuid4()),
                    source_type=source_type,
                    name=name,
                    source_key=key,
                    configuration=configuration,
                    configuration_version=1,
                    enabled=True,
                    management_origin="discovery",
                    discovery_policy_version=DISCOVERY_POLICY_VERSION,
                    discovery_verified_at=datetime.now(UTC),
                )
            return SourceRegistration(row.id, key, True, True, False)
        except IntegrityError:
            existing = self._sources.get_by_key(key)
            if existing is None:
                raise
            return SourceRegistration(
                existing.id,
                key,
                False,
                True,
                not existing.enabled or existing.archived_at is not None,
            )


def _candidate_data(
    candidate: KnownOfficialCandidate,
) -> tuple[SourceType, dict[str, str], str]:
    if isinstance(candidate, GreenhouseOfficialCandidate):
        config = GreenhouseSourceConfig.model_validate(candidate.configuration).model_dump(
            mode="json", exclude_none=True
        )
        return SourceType.GREENHOUSE, config, f"Greenhouse {config['board_token']}"
    if isinstance(candidate, LeverOfficialCandidate):
        config = LeverSourceConfigV1.model_validate(candidate.configuration).model_dump(
            mode="json", exclude_none=True
        )
        return SourceType.LEVER, config, f"Lever {config['site']} ({config['region']})"
    raise TypeError("candidate is not an official ATS candidate")
