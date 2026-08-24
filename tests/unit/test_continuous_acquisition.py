"""Offline contracts for the F10.1B continuous-acquisition boundary."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from role_radar.continuous_acquisition.contracts import (
    AcquisitionRunState,
    AcquisitionSourceOutcome,
    JobCounters,
    OperationState,
    SourceSnapshot,
    VerifiedSource,
)
from role_radar.continuous_acquisition.discovery import (
    DiscoveryService,
    SqlAlchemyRegistrationStore,
)
from role_radar.continuous_acquisition.identity import derive_strong_identities
from role_radar.continuous_acquisition.orm import (
    ContinuousAcquisitionRun,
)
from role_radar.continuous_acquisition.persistence import OfferPersistence
from role_radar.continuous_acquisition.policy import (
    aggregate_outcomes,
    assert_conservation,
    freshness_decision,
)
from role_radar.continuous_acquisition.providers import FakeSearchProvider
from role_radar.continuous_acquisition.repositories import (
    DiscoveryRepository,
    RunRepository,
)
from role_radar.continuous_acquisition.scheduling import (
    acquisition_slot,
    discovery_slot,
    rotate_sources,
)
from role_radar.db.base import Base
from role_radar.db.models import Job, Source
from role_radar.domain.dto import RawJob
from role_radar.domain.enums import SourceType
from role_radar.repositories.sources import SourceRepository

AS_OF = datetime(2026, 8, 13, 12, tzinfo=UTC)


def raw_job(*, recency: datetime | None, collected_at: datetime = AS_OF) -> RawJob:
    return RawJob(
        source="greenhouse",
        external_id="eng-1",
        source_url="https://boards.greenhouse.io/acme/jobs/eng-1",
        application_url=None,
        title="Backend Engineer",
        company="Acme",
        collected_at=collected_at,
        published_at=recency,
        structured_data={"updated_at": recency.isoformat()} if recency is not None else {},
    )


def source_snapshot() -> SourceSnapshot:
    return SourceSnapshot(
        source_id="source-1",
        source_key="greenhouse:acme",
        source_type="greenhouse",
        name="Acme",
        configuration={"board_token": "acme"},
    )


def file_session(tmp_path: Path) -> Session:
    # Importing the bounded-context ORM registers its tables alongside the
    # historical models, while the file-backed database keeps mutation checks real.
    engine = create_engine(f"sqlite:///{tmp_path / 'continuous.db'}")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_freshness_is_exactly_fourteen_days_and_never_uses_collected_at() -> None:
    exact = freshness_decision(raw_job(recency=AS_OF - timedelta(days=14)), as_of_utc=AS_OF)
    stale = freshness_decision(
        raw_job(recency=AS_OF - timedelta(days=14, microseconds=1)), as_of_utc=AS_OF
    )
    fallback = freshness_decision(raw_job(recency=None), as_of_utc=AS_OF)

    assert exact.accepted is True
    assert stale.code == "freshness_before_cutoff"
    assert fallback.code == "freshness_timestamp_missing"


@pytest.mark.parametrize(
    ("outcomes", "expected"),
    [
        ((), AcquisitionRunState.FAILED),
        (
            (AcquisitionSourceOutcome("s", OperationState.EMPTY, usable=True),),
            AcquisitionRunState.COMPLETED_EMPTY,
        ),
        (
            (
                AcquisitionSourceOutcome(
                    "s", OperationState.SUCCEEDED, JobCounters(1, 1), usable=True
                ),
            ),
            AcquisitionRunState.COMPLETED,
        ),
        (
            (AcquisitionSourceOutcome("s", OperationState.FAILED, usable=True),),
            AcquisitionRunState.COMPLETED_PARTIAL,
        ),
        (
            (AcquisitionSourceOutcome("s", OperationState.INDETERMINATE, usable=False),),
            AcquisitionRunState.INDETERMINATE,
        ),
    ],
)
def test_outcome_matrix_and_indeterminate_dominance(
    outcomes: tuple[AcquisitionSourceOutcome, ...], expected: AcquisitionRunState
) -> None:
    assert aggregate_outcomes(outcomes).state is expected
    assert aggregate_outcomes(
        (*outcomes, AcquisitionSourceOutcome("unknown", OperationState.INDETERMINATE))
    ).state is AcquisitionRunState.INDETERMINATE


def test_conservation_is_explicit() -> None:
    assert_conservation(
        JobCounters(observed=5, created=1, duplicate=1, stale=1, invalid=1, conflict=1)
    )
    with pytest.raises(ValueError, match="conservation"):
        assert_conservation(JobCounters(observed=2, created=1))


def test_strong_identity_keeps_official_urls_and_excludes_weak_urls() -> None:
    identities = derive_strong_identities(
        source_key="greenhouse:acme",
        external_id="eng-1",
        posting_url="https://boards.greenhouse.io/acme/jobs/eng-1/?utm_source=newsletter&job=1",
        application_url="https://evil.example/apply/eng-1",
    )

    assert {identity.kind for identity in identities} == {
        "source_external_id",
        "official_posting_url",
    }
    assert identities[1].value == "https://boards.greenhouse.io/acme/jobs/eng-1?job=1"
    assert all("utm_" not in identity.value for identity in identities)


def test_slots_and_rotation_are_stable() -> None:
    assert acquisition_slot(AS_OF) == acquisition_slot(AS_OF + timedelta(hours=1))
    assert acquisition_slot(AS_OF, canary_id="fix-01") == acquisition_slot(
        AS_OF + timedelta(hours=1), canary_id="fix-01"
    )
    assert acquisition_slot(AS_OF, canary_id="fix-01") != acquisition_slot(AS_OF)
    assert discovery_slot(AS_OF, canary_id="fix-01").endswith(":fix-01")
    with pytest.raises(ValueError, match="canary_id_invalid"):
        acquisition_slot(AS_OF, canary_id="invalid/id")
    assert rotate_sources(("a", "b", "c"), day=AS_OF) == rotate_sources(
        ("c", "a", "b"), day=AS_OF
    )
    assert rotate_sources(("a", "b"), day=AS_OF) != rotate_sources(
        ("a", "b"), day=AS_OF + timedelta(days=1)
    )


def test_persistence_rejects_stale_without_db_mutation(tmp_path: Path) -> None:
    session = file_session(tmp_path)
    try:
        run = RunRepository(session).claim_acquisition(
            slot_key="continuous-acquisition:daily-slot-v1:2026-08-13",
            policy_version="continuous-acquisition-v1",
            snapshots=(source_snapshot(),),
            owner="test-worker",
        )
        operation = RunRepository(session).create_operation(run.id, source_snapshot())
        disposition = OfferPersistence(session, as_of_utc=AS_OF).persist(
            raw_job(recency=AS_OF - timedelta(days=14, microseconds=1)),
            source=source_snapshot(),
            run_id=run.id,
            operation_id=operation.id,
        )
        assert disposition == "freshness_before_cutoff"
        assert session.scalar(select(func.count()).select_from(Job)) == 0
        assert session.scalar(select(func.count()).select_from(ContinuousAcquisitionRun)) == 1
    finally:
        session.close()


def test_source_only_registration_preserves_disabled_archived_and_empty_board(
    tmp_path: Path,
) -> None:
    session = file_session(tmp_path)
    try:
        source_repo = SourceRepository(session)
        disabled = source_repo.create_row(
            source_id="disabled", source_type=SourceType.GREENHOUSE, name="Disabled",
            source_key="greenhouse:disabled", configuration={"board_token": "disabled"},
            configuration_version=1, enabled=False,
        )
        archived = source_repo.create_row(
            source_id="archived", source_type=SourceType.GREENHOUSE, name="Archived",
            source_key="greenhouse:archived", configuration={"board_token": "archived"},
            configuration_version=1, enabled=False, archived_at=AS_OF,
        )
        discovery = DiscoveryRepository(session)
        run = discovery.claim(
            "discovery-slot", owner="test", policy_version="test", config_version="test"
        )
        operation = discovery.intent(
            run.id,
            operation_key="source-only",
            provider="fake",
            operation_type="verify",
            reserved_capacity=0,
        )
        store = SqlAlchemyRegistrationStore(session, run.id, operation.id)
        disabled_result = store.register(
        VerifiedSource(
                disabled.source_key, "greenhouse", "Changed", {"board_token": "disabled"}, 1
            )
        )
        archived_result = store.register(
        VerifiedSource(
                archived.source_key, "greenhouse", "Changed", {"board_token": "archived"}, 1
            )
        )
        empty = DiscoveryService(FakeSearchProvider(), lambda _candidate: None, store).run()
        session.commit()

        assert disabled_result.disposition == "existing_disabled"
        assert archived_result.disposition == "existing_archived"
        disabled_source = session.get(Source, "disabled")
        archived_source = session.get(Source, "archived")
        assert disabled_source is not None
        assert archived_source is not None
        assert disabled_source.enabled is False
        assert archived_source.archived_at is not None
        assert archived_source.archived_at.replace(tzinfo=UTC) == AS_OF
        assert empty == ()
        assert session.scalar(select(func.count()).select_from(Source)) == 2
    finally:
        session.close()
