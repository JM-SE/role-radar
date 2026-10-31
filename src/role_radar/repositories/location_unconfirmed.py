"""Persistence for review-only offers with unknown geography."""

from __future__ import annotations

from typing import Any

from sqlalchemy import case, delete, select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from role_radar.db.models import LocationUnconfirmed
from role_radar.domain.dto import NormalizedJob
from role_radar.matching.contracts import ProfileBinding


class LocationUnconfirmedRepository:
    """Stores review observations separately from eligible jobs and scores."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def observe(
        self,
        *,
        binding: ProfileBinding,
        source_id: str,
        normalized: NormalizedJob,
        source_url: str | None,
        application_url: str,
    ) -> None:
        values = {
            "profile_id": binding.profile_id,
            "profile_version": binding.row_version,
            "profile_schema_version": binding.schema_version,
            "profile_hash": binding.canonical_profile_sha256,
            "source_id": source_id,
            "external_id": normalized.external_id,
            "title": normalized.title,
            "company": normalized.company,
            "location": normalized.location,
            "source_url": source_url,
            "application_url": application_url,
            "reason_code": "region_unknown",
            "first_seen_at": normalized.collected_at,
            "last_seen_at": normalized.collected_at,
        }
        dialect = self._session.get_bind().dialect.name
        if dialect == "sqlite":
            statement: Any = sqlite_insert(LocationUnconfirmed).values(**values)
        elif dialect == "postgresql":
            statement = postgresql_insert(LocationUnconfirmed).values(**values)
        else:
            raise RuntimeError("location_unconfirmed_database_dialect_unsupported")

        excluded = statement.excluded
        self._session.execute(
            statement.on_conflict_do_update(
                index_elements=(
                    LocationUnconfirmed.profile_id,
                    LocationUnconfirmed.source_id,
                    LocationUnconfirmed.external_id,
                ),
                set_={
                    "profile_version": excluded.profile_version,
                    "profile_schema_version": excluded.profile_schema_version,
                    "profile_hash": excluded.profile_hash,
                    "title": excluded.title,
                    "company": excluded.company,
                    "location": excluded.location,
                    "source_url": excluded.source_url,
                    "application_url": excluded.application_url,
                    "reason_code": excluded.reason_code,
                    "last_seen_at": case(
                        (
                            excluded.last_seen_at > LocationUnconfirmed.last_seen_at,
                            excluded.last_seen_at,
                        ),
                        else_=LocationUnconfirmed.last_seen_at,
                    ),
                },
            )
        )

    def remove(self, *, profile_id: str, source_id: str, external_id: str) -> None:
        if not external_id:
            return
        self._session.execute(
            delete(LocationUnconfirmed).where(
                LocationUnconfirmed.profile_id == profile_id,
                LocationUnconfirmed.source_id == source_id,
                LocationUnconfirmed.external_id == external_id,
            )
        )

    def list_current(
        self,
        *,
        binding: ProfileBinding,
        limit: int = 50,
        offset: int = 0,
    ) -> list[LocationUnconfirmed]:
        statement = (
            select(LocationUnconfirmed)
            .where(
                LocationUnconfirmed.profile_id == binding.profile_id,
                LocationUnconfirmed.profile_version == binding.row_version,
                LocationUnconfirmed.profile_schema_version == binding.schema_version,
                LocationUnconfirmed.profile_hash == binding.canonical_profile_sha256,
            )
            .order_by(LocationUnconfirmed.last_seen_at.desc(), LocationUnconfirmed.id.asc())
            .limit(limit)
            .offset(offset)
        )
        return list(self._session.scalars(statement))
