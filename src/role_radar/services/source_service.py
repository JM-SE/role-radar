"""Source control-plane policy and optimistic concurrency."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from role_radar.db.models import Source
from role_radar.domain.enums import SourceType
from role_radar.free_sources.terms import JobicyTermsAcceptance, validate_jobicy_terms
from role_radar.repositories.sources import SourceRepository
from role_radar.sources.catalog import get_catalog_entry
from role_radar.sources.configuration import validate_configuration
from role_radar.sources.identity import canonical_source_key

LAST_ERROR_CODES = frozenset(
    {
        "collection_failed",
        "configuration_unavailable",
        "source_type_unavailable",
        "invalid_source_config",
        "unsupported_configuration_version",
    }
)


class SourceServiceError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class SourceNotFound(SourceServiceError):
    def __init__(self) -> None:
        super().__init__("source_not_found")


class RevisionConflict(SourceServiceError):
    def __init__(self) -> None:
        super().__init__("revision_conflict")


class SourceService:
    """Business policy over a DB-only repository."""

    def __init__(
        self,
        session: Session,
        repository: SourceRepository | None = None,
        *,
        jobicy_terms: JobicyTermsAcceptance | None = None,
    ) -> None:
        self._repo = repository or SourceRepository(session)
        self._jobicy_terms = jobicy_terms

    def create(
        self,
        *,
        source_type: SourceType | str,
        name: str,
        configuration: Mapping[str, Any],
    ) -> Source:
        value = self._source_type(source_type)
        entry = get_catalog_entry(value)
        if not entry.adapter_available or entry.configuration_version is None:
            raise SourceServiceError("source_type_unavailable")
        clean_name = self._name(name)
        try:
            validated = validate_configuration(
                value, entry.configuration_version, dict(configuration)
            )
            config = validated.model_dump(mode="json", exclude_none=True)
            key = canonical_source_key(value, config)
        except (TypeError, ValueError) as exc:
            raise SourceServiceError("invalid_source_config") from exc
        if self._repo.get_by_key(key) is not None:
            raise SourceServiceError("source_key_conflict")
        try:
            return self._repo.create_row(
                source_id=str(uuid4()),
                source_type=value,
                name=clean_name,
                source_key=key,
                configuration=config,
                configuration_version=entry.configuration_version,
                enabled=False,
                revision=1,
            )
        except IntegrityError as exc:
            raise SourceServiceError("source_key_conflict") from exc

    def update(
        self,
        source_id: str,
        *,
        expected_revision: int,
        name: str | None = None,
        configuration: Mapping[str, Any] | None = None,
        source_type: SourceType | str | None = None,
    ) -> Source:
        source = self._required(source_id)
        if source.archived_at is not None:
            raise SourceServiceError("source_archived")
        if source_type is not None and self._source_type(source_type) is not source.type:
            raise SourceServiceError("identity_immutable")
        changes: dict[str, Any] = {}
        if name is not None:
            changes["name"] = self._name(name)
        if configuration is not None:
            entry = get_catalog_entry(source.type)
            if not entry.adapter_available or entry.configuration_version is None:
                raise SourceServiceError("source_type_unavailable")
            try:
                validated = validate_configuration(
                    source.type, entry.configuration_version, dict(configuration)
                )
                config = validated.model_dump(mode="json", exclude_none=True)
                key = canonical_source_key(source.type, config)
            except (TypeError, ValueError) as exc:
                raise SourceServiceError("invalid_source_config") from exc
            if key != source.source_key:
                if self._repo.has_references(source_id) or self._repo.has_run_history(source_id):
                    raise SourceServiceError("identity_immutable")
                other = self._repo.get_by_key(key)
                if other is not None and other.id != source_id:
                    raise SourceServiceError("source_key_conflict")
            changes["configuration"] = config
            changes["source_key"] = key
            changes["configuration_version"] = entry.configuration_version
        if not changes:
            if source.revision != expected_revision:
                raise RevisionConflict()
            return source
        return self._cas(source_id, expected_revision, changes)

    def enable(self, source_id: str, *, expected_revision: int) -> Source:
        source = self._required(source_id)
        if source.archived_at is not None:
            raise SourceServiceError("source_archived")
        self._assert_enableable(source, jobicy_terms=self._jobicy_terms)
        if source.enabled:
            if source.revision != expected_revision:
                raise RevisionConflict()
            return source
        return self._cas(source_id, expected_revision, {"enabled": True})

    def disable(self, source_id: str, *, expected_revision: int) -> Source:
        source = self._required(source_id)
        if source.archived_at is not None:
            raise SourceServiceError("source_archived")
        if source.revision != expected_revision:
            raise RevisionConflict()
        if not source.enabled:
            return source
        return self._cas(source_id, expected_revision, {"enabled": False})

    def archive(self, source_id: str, *, expected_revision: int) -> Source:
        source = self._required(source_id)
        if source.archived_at is not None:
            raise SourceServiceError("source_already_archived")
        return self._cas(
            source_id,
            expected_revision,
            {"archived_at": datetime.now(UTC), "enabled": False},
        )

    def get(self, source_id: str) -> Source:
        return self._required(source_id)

    def list_sources(
        self,
        *,
        source_type: SourceType | None = None,
        enabled: bool | None = None,
        archived: bool | None = None,
        adapter_available: bool | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Source], int]:
        # The catalog is tiny and static. Filtering availability in policy keeps
        # the repository unaware of catalog metadata while preserving pagination.
        all_rows = self._repo.list(
            source_type=source_type,
            enabled=enabled,
            archived=archived,
            limit=100000,
            offset=0,
        )
        if adapter_available is not None:
            all_rows = [
                row
                for row in all_rows
                if get_catalog_entry(row.type).adapter_available is adapter_available
            ]
        total = len(all_rows)
        return all_rows[offset : offset + limit], total

    def _required(self, source_id: str) -> Source:
        source = self._repo.get(source_id)
        if source is None:
            raise SourceNotFound()
        return source

    def _cas(self, source_id: str, expected_revision: int, changes: Mapping[str, Any]) -> Source:
        updated = self._repo.update_cas(source_id, expected_revision, changes)
        if updated is not None:
            return updated
        if self._repo.get(source_id) is None:
            raise SourceNotFound()
        raise RevisionConflict()

    @staticmethod
    def _name(name: str) -> str:
        if not isinstance(name, str):
            raise SourceServiceError("invalid_source_config")
        clean = name.strip()
        if not 1 <= len(clean) <= 255:
            raise SourceServiceError("invalid_source_config")
        return clean

    @staticmethod
    def _source_type(source_type: SourceType | str) -> SourceType:
        try:
            return SourceType(source_type)
        except ValueError as exc:
            raise SourceServiceError("source_type_unavailable") from exc

    @staticmethod
    def _assert_enableable(
        source: Source, *, jobicy_terms: JobicyTermsAcceptance | None = None
    ) -> None:
        if source.type is SourceType.JOBICY:
            terms_error = validate_jobicy_terms(
                jobicy_terms, now=datetime.now(UTC)
            )
            if terms_error is not None:
                raise SourceServiceError(terms_error)
        entry = get_catalog_entry(source.type)
        if (
            not entry.adapter_available
            or source.configuration_version != entry.configuration_version
        ):
            raise SourceServiceError("source_type_unavailable")
        try:
            validated = validate_configuration(
                source.type, source.configuration_version, dict(source.configuration or {})
            )
            if canonical_source_key(source.type, validated.model_dump()) != source.source_key:
                raise ValueError("source key does not match configuration")
        except ValueError as exc:
            raise SourceServiceError("invalid_source_config") from exc
