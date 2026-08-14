"""Source-only discovery orchestration.

Search hits and verification results are transient.  Only verified board
registration metadata is handed to a repository; no Job or collector path is
called here.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from role_radar.continuous_acquisition.contracts import (
    DISCOVERY_POLICY_VERSION,
    DiscoveryCandidate,
    RegistrationResult,
    VerifiedSource,
)
from role_radar.db.models import Source
from role_radar.domain.enums import SourceType
from role_radar.repositories.sources import SourceRepository
from role_radar.sources.identity import greenhouse_source_key, lever_source_key


class CandidateProvider(Protocol):
    def candidates(self) -> tuple[DiscoveryCandidate, ...]: ...


class AsyncCandidateProvider(Protocol):
    async def candidates_async(self) -> tuple[DiscoveryCandidate, ...]: ...


class RegistrationStore(Protocol):
    def register(self, verified: VerifiedSource) -> RegistrationResult: ...

    def reserve(self, candidate: DiscoveryCandidate) -> bool: ...


@dataclass(frozen=True, slots=True)
class DiscoveryService:
    """Deliberately limited to transient candidate flow and registration."""

    candidates: CandidateProvider
    verifier: object
    store: RegistrationStore
    max_candidates: int = 8

    def run(self) -> tuple[RegistrationResult, ...]:
        output: list[RegistrationResult] = []
        new_sources = 0
        for candidate in self.candidates.candidates():
            if new_sources >= self.max_candidates:
                break
            reserve = getattr(self.store, "reserve", None)
            if reserve is not None and not reserve(candidate):
                continue
            verified = self.verifier(candidate)  # type: ignore[operator]
            if verified is not None:
                result = self.store.register(verified)
                output.append(result)
                mark = getattr(self.store, "mark_verified", None)
                if mark is not None:
                    mark(result)
                if result.disposition == "created":
                    new_sources += 1
                else:
                    release = getattr(self.store, "release", None)
                    if release is not None:
                        release(candidate)
            else:
                release = getattr(self.store, "release", None)
                if release is not None:
                    release(candidate)
        return tuple(output)

    async def run_async(self) -> tuple[RegistrationResult, ...]:
        """Async runtime seam preserving reservation-before-verification."""
        provider = self.candidates
        candidates_async = getattr(provider, "candidates_async", None)
        candidates = await candidates_async() if candidates_async else provider.candidates()
        output: list[RegistrationResult] = []
        new_sources = 0
        for candidate in candidates:
            if new_sources >= self.max_candidates:
                break
            reserve = getattr(self.store, "reserve", None)
            if reserve is not None and not reserve(candidate):
                continue
            try:
                verified = self.verifier(candidate)  # type: ignore[operator]
                if inspect.isawaitable(verified):
                    verified = await verified
            except BaseException:
                release = getattr(self.store, "release", None)
                if release is not None:
                    release(candidate)
                raise
            if verified is None:
                release = getattr(self.store, "release", None)
                if release is not None:
                    release(candidate)
                continue
            result = self.store.register(verified)
            output.append(result)
            mark = getattr(self.store, "mark_verified", None)
            if mark is not None:
                mark(result)
            if result.disposition == "created":
                new_sources += 1
            else:
                release = getattr(self.store, "release", None)
                if release is not None:
                    release(candidate)
        return tuple(output)


class SqlAlchemyRegistrationStore:
    """Registration policy protects manually disabled and archived Sources."""

    def __init__(self, session: Session, run_id: str, operation_id: str) -> None:
        self.session = session
        self.run_id = run_id
        self.operation_id = operation_id

    def reserve(self, candidate: DiscoveryCandidate) -> bool:
        """Reserve verification capacity before any provider/collector I/O."""
        from role_radar.continuous_acquisition.orm import SourceDiscoveryRun

        run = self.session.get(SourceDiscoveryRun, self.run_id)
        if run is None or run.reserved_count >= 8:
            return False
        active = self.session.scalar(
            select(func.count()).select_from(Source).where(
                Source.enabled.is_(True),
                Source.archived_at.is_(None),
                Source.management_origin == "discovery",
            )
        )
        if int(active or 0) >= 50:
            return False
        run.reserved_count += 1
        self.session.flush()
        return True

    def release(self, _candidate: DiscoveryCandidate) -> None:
        from role_radar.continuous_acquisition.orm import SourceDiscoveryRun

        run = self.session.get(SourceDiscoveryRun, self.run_id)
        if run is not None and run.reserved_count > 0:
            run.reserved_count -= 1

    def mark_verified(self, result: RegistrationResult) -> None:
        from role_radar.continuous_acquisition.orm import SourceDiscoveryRun

        run = self.session.get(SourceDiscoveryRun, self.run_id)
        if run is not None:
            run.verified_count += 1
            if result.disposition == "created":
                run.registered_count += 1

    def register(self, verified: VerifiedSource) -> RegistrationResult:
        from role_radar.continuous_acquisition.orm import SourceDiscoveryRegistration

        source_repo = SourceRepository(self.session)
        existing = source_repo.get_by_key(verified.source_key)
        if existing is not None:
            state = "archived" if existing.archived_at is not None else ("enabled" if existing.enabled else "disabled")
            disposition = f"existing_{state}"
            self.session.add(SourceDiscoveryRegistration(run_id=self.run_id, operation_id=self.operation_id, source_id=existing.id, source_key=verified.source_key, disposition=disposition, previous_state=state, current_state=state))
            return RegistrationResult(existing.id, disposition, verified.source_key, state)
        source = source_repo.create_row(source_id=str(uuid4()), source_type=SourceType(verified.source_type), name=verified.name, source_key=verified.source_key, configuration=dict(verified.configuration), configuration_version=1, enabled=True, management_origin="discovery", discovery_policy_version=DISCOVERY_POLICY_VERSION, discovery_verified_at=datetime.now(UTC))
        self.session.add(SourceDiscoveryRegistration(run_id=self.run_id, operation_id=self.operation_id, source_id=source.id, source_key=verified.source_key, disposition="created", current_state="enabled"))
        return RegistrationResult(source.id, "created", verified.source_key, "enabled")


def verified_source(source_type: str, configuration: dict[str, str], name: str, postings: int) -> VerifiedSource:
    if source_type not in {"greenhouse", "lever"}:
        raise ValueError("unsupported source type")
    key = greenhouse_source_key(configuration["board_token"]) if source_type == "greenhouse" else lever_source_key(configuration)
    return VerifiedSource(key, source_type, name, configuration, postings)  # type: ignore[arg-type]
